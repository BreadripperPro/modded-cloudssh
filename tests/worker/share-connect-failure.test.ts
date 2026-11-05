import { describe, expect, it, vi } from 'vitest';
import { SSHShareDO } from '../../src/worker/share-do';

const ticket = 'one-time-ticket';
async function fixture(configFetch: () => Promise<Response>, auditFails = false) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ticket)));
  const hash = btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const share: any = {
    share_id: 'share-1', token_hash: 'capability-hash', owner_user_id: 1, owner_github_id: '123',
    server_id: 1, server_name: 'server', expires_at: Date.now() + 60_000,
    session_expires_at: Date.now() + 600_000, max_session_seconds: 600,
    status: 'claimed', ticket_hash: hash, ticket_expires_at: Date.now() + 60_000,
    session_name: null, audit_bytes: 0, device_pub_key: null, audit_retention_days: 90,
  };
  const events: Array<{ type: string; details: string }> = [{ type: 'share.claimed', details: '{}' }];
  const sql = { exec: vi.fn((statement: string, ...args: any[]) => {
    const empty = { toArray: () => [], one: () => ({}) };
    if (statement.includes('SELECT * FROM share_state')) return { ...empty, toArray: () => [{ ...share }] };
    if (statement.includes('SELECT COUNT(*)')) return { ...empty, one: () => ({ count: events.length }) };
    if (statement.includes("SET status = 'active'")) {
      if (share.status === 'claimed') Object.assign(share, { status: 'active', active_at: args[0],
        session_name: args[1], ticket_hash: null, ticket_expires_at: null });
    } else if (statement.includes('SET status = ?')) {
      Object.assign(share, { status: args[0], closed_at: args[1], ticket_hash: null, ticket_expires_at: null });
    } else if (statement.includes('INSERT INTO audit_events')) {
      if (auditFails) throw new Error('audit unavailable');
      events.push({ type: args[1], details: args[2] });
    } else if (statement.includes('SET audit_purge_due = ?')) share.audit_purge_due = args[0];
    return empty;
  }) };
  const updates: any[] = [];
  const ownerFetch = vi.fn(async (request: Request) => {
    if (request.url.endsWith('/share-config')) return configFetch();
    updates.push(await request.json());
    return Response.json({ success: true });
  });
  const setAlarm = vi.fn(async () => {});
  const state = { storage: { sql, setAlarm } };
  const env = {
    USER_DB: { get: () => ({ fetch: ownerFetch }), idFromName: (name: string) => name },
    SSH_SESSION: { get: () => ({ fetch: async () => Response.json({}) }), idFromName: (name: string) => name },
  };
  const instance = new SSHShareDO(state as unknown as DurableObjectState, env as never);
  const consume = () => instance.fetch(new Request('http://internal/internal/connect/consume', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ticket, sessionName: 'session-1' }),
  }));
  const config = () => ({ host: 'ssh.example.com', port: 22, username: 'alice', password: 'DO_NOT_LEAK',
    sessionPolicy: { source: 'share', shareId: share.share_id, shareRef: share.token_hash,
      sessionExpiresAt: share.session_expires_at, allowAgent: false, allowMetadataMutation: false,
      allowHostKeyMutation: false, allowReconnect: false, allowSftp: true } });
  return { share, events, updates, setAlarm, instance, consume, config };
}

describe('consumed one-time shares converge on connection failure', () => {
  it.each([
    ['network rejection', async () => { throw new Error('DO_NOT_LEAK provider failure'); }, 502],
    ['invalid JSON', async () => new Response('{DO_NOT_LEAK', { status: 200 }), 502],
    ['invalid policy', async () => Response.json({ password: 'DO_NOT_LEAK' }), 502],
    ['HTTP rejection', async () => new Response('DO_NOT_LEAK', { status: 403 }), 403],
  ] as const)('%s closes, audits and syncs owner without restoring the ticket', async (_name, fetch, code) => {
    const { share, events, updates, consume, setAlarm } = await fixture(fetch);
    const response = await consume();
    expect(response.status).toBe(code);
    expect(await response.text()).not.toContain('DO_NOT_LEAK');
    expect(share.status).toBe('closed');
    expect(share.ticket_hash).toBeNull();
    expect(share.ticket_expires_at).toBeNull();
    expect(events.at(-1)?.type).toBe('session.connection_failed');
    expect(events.at(-1)?.details).not.toContain('DO_NOT_LEAK');
    expect(updates.at(-1).status).toBe('closed');
    expect(setAlarm).toHaveBeenCalled();
    expect((await consume()).status).toBe(409);
  });

  it('finalization/alarm failure also closes instead of leaving an orphan active share', async () => {
    let config: () => unknown;
    const f = await fixture(async () => Response.json(config()));
    config = f.config;
    f.setAlarm.mockRejectedValueOnce(new Error('alarm unavailable'));
    expect((await f.consume()).status).toBe(502);
    expect(f.share.status).toBe('closed');
    expect(f.updates.at(-1).status).toBe('closed');
    expect(f.events.at(-1)?.type).toBe('session.connection_failed');
  });

  it('audit failure cannot prevent the terminal state write', async () => {
    const f = await fixture(async () => { throw new Error('upstream unavailable'); }, true);
    expect((await f.consume()).status).toBe(502);
    expect(f.share.status).toBe('closed');
    expect(f.updates.at(-1).status).toBe('closed');
    expect((await f.consume()).status).toBe(409);
  });

  it('revocation while awaiting config is not overwritten or followed by credential delivery', async () => {
    let finish!: (response: Response) => void;
    const configPending = new Promise<Response>(resolve => { finish = resolve; });
    const f = await fixture(() => configPending);
    const consume = f.consume();
    await vi.waitFor(() => expect(f.share.status).toBe('active'));
    f.share.status = 'revoked';
    finish(Response.json(f.config()));
    const response = await consume;
    expect(response.status).toBe(410);
    expect(await response.text()).not.toContain('DO_NOT_LEAK');
    expect(f.share.status).toBe('revoked');
    expect(f.updates.some(update => update.status === 'active')).toBe(false);
  });

  it('valid setup delivers config once and remains active', async () => {
    let config: () => unknown;
    const f = await fixture(async () => Response.json(config()));
    config = f.config;
    const response = await f.consume();
    expect(response.status).toBe(200);
    expect((await response.json() as any).config.host).toBe('ssh.example.com');
    expect(f.share.status).toBe('active');
    expect(f.updates.at(-1).status).toBe('active');
    expect((await f.consume()).status).toBe(409);
  });
});
