import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { concat, encodeString } from '../../src/ssh/utils';
import { SSHAuth } from '../../src/ssh/auth';
import { SSHSession } from '../../src/worker/ssh-session';

const sessions: SSHSession[] = [];
function createSession() {
  const ws = { readyState: 1, send: vi.fn(), close: vi.fn() };
  const session = new SSHSession(ws as unknown as WebSocket, { close: vi.fn() }, {
    host: 'ssh.example.com', port: 22, username: 'test-user', authMethod: 'publickey',
    privateKey: 'test-key-already-accepted', password: 'must-not-use-this-value',
  });
  sessions.push(session);
  const internal = session as any;
  internal.state = 'auth';
  internal.activeAuthMethod = 'publickey';
  internal.attemptedAuthMethods.add('publickey');
  internal.sendEncrypted = vi.fn(async (_bytes: Uint8Array) => {});
  internal.openShell = vi.fn(async () => {});
  const messages = () => ws.send.mock.calls.map(([value]) => JSON.parse(value));
  return { session, internal, ws, messages };
}
const failure = (methods: string, partial = true) => concat(
  new Uint8Array([51]), encodeString(methods), new Uint8Array([partial ? 1 : 0])
);

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  for (const session of sessions.splice(0)) session.close(true);
  vi.clearAllTimers();
  vi.useRealTimers();
});

describe('explicit password factor after public-key authentication', () => {
  it.each(['second-factor-secret', ''])('prompts once and submits only the explicitly entered password %#', async (password) => {
    const { session, internal, ws, messages } = createSession();
    await internal.handleAuthPacket(51, failure('password'));
    const challenge = messages().find((message) => message.type === 'auth_challenge');
    expect(challenge).toMatchObject({ method: 'password', canUseStoredPassword: false,
      prompts: [{ text: '', echo: false }] });
    expect(internal.sendEncrypted).not.toHaveBeenCalled();
    expect(internal.activeAuthMethod).toBe('password');
    await session.handleWebSocketMessage(JSON.stringify({ type: 'auth_response', id: 'stale', responses: [password] }));
    expect(internal.sendEncrypted).not.toHaveBeenCalled();
    await session.handleWebSocketMessage(JSON.stringify({ type: 'auth_challenge_ack', id: challenge.id }));
    await session.handleWebSocketMessage(JSON.stringify({ type: 'auth_response', id: challenge.id, responses: [password] }));
    expect(internal.sendEncrypted).toHaveBeenCalledExactlyOnceWith(
      SSHAuth.buildPasswordAuthRequest('test-user', password)
    );
    expect(internal.config.password).toBe('must-not-use-this-value');
    expect(JSON.stringify(messages())).not.toContain('second-factor-secret');
    expect(JSON.stringify(messages())).not.toContain('must-not-use-this-value');
    await session.handleWebSocketMessage(JSON.stringify({ type: 'auth_response', id: challenge.id, responses: [password] }));
    expect(internal.sendEncrypted).toHaveBeenCalledTimes(1);
    await internal.handleAuthPacket(52, new Uint8Array([52]));
    expect(internal.openShell).toHaveBeenCalledOnce();
    expect(ws.close).not.toHaveBeenCalled();
  });

  it.each(['password', 'publickey,password'])('never prompts on ordinary key rejection (methods=%s)', async (methods) => {
    const { internal, ws, messages } = createSession();
    await internal.handleAuthPacket(51, failure(methods, false));
    expect(messages().some((message) => message.type === 'auth_challenge')).toBe(false);
    expect(internal.sendEncrypted).not.toHaveBeenCalled();
    expect(ws.close).toHaveBeenCalledWith(1000);
  });

  it('stops after a rejected password factor rather than retrying the primary key', async () => {
    const { session, internal, ws, messages } = createSession();
    await internal.handleAuthPacket(51, failure('password'));
    const challenge = messages().find((message) => message.type === 'auth_challenge');
    await session.handleWebSocketMessage(JSON.stringify({ type: 'auth_response', id: challenge.id, responses: ['wrong'] }));
    expect(internal.sendEncrypted).toHaveBeenCalledTimes(1);
    await internal.handleAuthPacket(51, failure('publickey,password,keyboard-interactive', false));
    expect(internal.sendEncrypted).toHaveBeenCalledTimes(1);
    expect(messages().filter((message) => message.type === 'auth_challenge')).toHaveLength(1);
    expect(ws.close).toHaveBeenCalledWith(1000);
  });

  it.each(['share', 'intermediate-hop'])('never opens a password prompt for %s', async (mode) => {
    const { internal, ws, messages } = createSession();
    if (mode === 'share') internal.config.sessionPolicy = { source: 'share' };
    else internal.allowKeyboardInteractive = false;
    await internal.handleAuthPacket(51, failure('password'));
    expect(messages().some((message) => message.type === 'auth_challenge')).toBe(false);
    expect(internal.sendEncrypted).not.toHaveBeenCalled();
    expect(ws.close).toHaveBeenCalledWith(1000);
  });

  it('cannot substitute a retained primary password and releases challenge state on rejection', async () => {
    const { session, internal, ws, messages } = createSession();
    await internal.handleAuthPacket(51, failure('password'));
    const challenge = messages().find((message) => message.type === 'auth_challenge');
    await session.handleWebSocketMessage(JSON.stringify({ type: 'auth_response', id: challenge.id, useStoredPassword: true }));
    expect(internal.sendEncrypted).not.toHaveBeenCalled();
    expect(internal.pendingAuthChallenge).toBeNull();
    expect(ws.close).toHaveBeenCalledOnce();
  });

  it('binds acknowledgements and responses to the originating session', async () => {
    const first = createSession();
    const second = createSession();
    await first.internal.handleAuthPacket(51, failure('password'));
    await second.internal.handleAuthPacket(51, failure('password'));
    const challenge = first.messages().find((message) => message.type === 'auth_challenge');
    await second.session.handleWebSocketMessage(JSON.stringify({ type: 'auth_response', id: challenge.id, responses: ['secret'] }));
    expect(second.internal.sendEncrypted).not.toHaveBeenCalled();
    expect(first.internal.sendEncrypted).not.toHaveBeenCalled();
  });

  it.each(['cancel', 'timeout', 'close'])('cleans up a pending factor on %s', async (action) => {
    const { session, internal, ws, messages } = createSession();
    await internal.handleAuthPacket(51, failure('password'));
    const challenge = messages().find((message) => message.type === 'auth_challenge');
    if (action === 'cancel') {
      await session.handleWebSocketMessage(JSON.stringify({ type: 'auth_cancel', id: challenge.id }));
    } else if (action === 'timeout') {
      await session.handleWebSocketMessage(JSON.stringify({ type: 'auth_challenge_ack', id: challenge.id }));
      await vi.advanceTimersByTimeAsync(120_001);
    } else session.close(true);
    expect(ws.close).toHaveBeenCalledWith(1000);
    expect(internal.pendingAuthChallenge).toBeNull();
    await session.handleWebSocketMessage(JSON.stringify({ type: 'auth_response', id: challenge.id, responses: ['late'] }));
    expect(internal.sendEncrypted).not.toHaveBeenCalled();
  });
});
