import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { once } from 'node:events';
import { beforeAll, afterAll, describe, expect, it, vi } from 'vitest';
import { SSHSession } from '../../src/worker/ssh-session';

const enabled = process.env.CLOUDSSH_GATEWAY_INTEROP === '1';
const fixtures = resolve(__dirname, '../ssh/fixtures');
let buildDirectory: string;
let binary: string;

async function launch(mode: string): Promise<{ child: ChildProcess; port: number }> {
  const child = spawn(binary, ['-mode', mode, '-key', join(fixtures, 'id_ed25519'),
    '-authorized-key', join(fixtures, 'id_ed25519.pub')], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stderr?.on('data', () => {});
  let text = '';
  child.stdout!.on('data', (chunk: Buffer) => { if (text.length < 1024) text += chunk.toString(); });
  try {
    await vi.waitFor(() => {
      if (child.exitCode !== null) throw new Error('Test gateway exited');
      expect(text).toContain('\n');
    }, { timeout: 5000, interval: 20 });
    const port = JSON.parse(text.trim()).port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid test gateway port');
    return { child, port };
  } catch (error) { child.kill('SIGTERM'); throw error; }
}

async function run(mode: string, wrongResponse = false): Promise<void> {
  const { child, port } = await launch(mode);
  const socket = connect(port, '127.0.0.1');
  let session: SSHSession | undefined;
  try {
    await once(socket, 'connect');
    const messages: Array<{ type?: string; event?: string; id?: string; method?: string }> = [];
    const responses: Promise<void>[] = [];
    const ws = {
      readyState: 1,
      send(value: string | ArrayBuffer) {
        if (typeof value !== 'string') return;
        const message = JSON.parse(value);
        messages.push(message);
        if (message.type === 'auth_challenge') {
          const answer = wrongResponse ? 'wrong-public-test-response'
            : mode === 'otp' ? '123456' : 'cloudssh-public-test-password';
          // Simulate explicit browser acknowledgement and submission, not application auto-fill.
          responses.push(Promise.resolve().then(async () => {
            await session!.handleWebSocketMessage(JSON.stringify({ type: 'auth_challenge_ack', id: message.id }));
            await session!.handleWebSocketMessage(JSON.stringify({ type: 'auth_response', id: message.id, responses: [answer] }));
          }));
        }
      },
      close() { this.readyState = 3; },
    };
    session = new SSHSession(ws as unknown as WebSocket, {
      readable: Readable.toWeb(socket), writable: Writable.toWeb(socket), close: () => socket.destroy(),
    }, {
      host: '127.0.0.1', port, username: 'cloudssh-test',
      authMethod: mode === 'none' ? 'none' : mode === 'publickey-password' ? 'publickey' : 'password',
      password: mode === 'password' ? 'cloudssh-public-test-password' : '',
      privateKey: mode === 'publickey-password' ? readFileSync(join(fixtures, 'id_ed25519'), 'utf8') : undefined,
    });
    await session.startHandshake();
    if (wrongResponse) {
      await vi.waitFor(() => expect(ws.readyState).toBe(3), { timeout: 7000 });
      expect(messages.some((message) => message.event === 'auth_success')).toBe(false);
      expect(messages.some((message) => message.event === 'shell_ready')).toBe(false);
    } else {
      await vi.waitFor(() => expect(messages.some((message) => message.event === 'shell_ready')).toBe(true),
        { timeout: 7000, interval: 20 });
      expect(messages.filter((message) => message.type === 'error')).toEqual([]);
      const result = await (session as any).executeAgentCommand('public-test-exec', 3000);
      expect(result).toMatchObject({ stdout: 'CLOUDSSH_GATEWAY_EXEC_OK', exitCode: 0 });
      if (mode === 'publickey-password') {
        expect(messages.filter((message) => message.type === 'auth_challenge')).toHaveLength(1);
        expect(messages.find((message) => message.type === 'auth_challenge')?.method).toBe('password');
      }
    }
    await Promise.all(responses);
  } finally {
    session?.close(true);
    socket.destroy();
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      await exited;
    }
  }
}

describe.skipIf(!enabled)('independent Go SSH gateway interoperability', () => {
  beforeAll(() => {
    buildDirectory = mkdtempSync(join(tmpdir(), 'cloudssh-gateway-'));
    binary = join(buildDirectory, 'gateway');
    try {
      execFileSync('go', ['build', '-mod=readonly', '-o', binary, '.'], {
        cwd: resolve(__dirname, 'gateway'), env: { ...process.env, GOTOOLCHAIN: 'local' },
        stdio: 'pipe', timeout: 120_000,
      });
    } catch (error) { rmSync(buildDirectory, { recursive: true, force: true }); throw error; }
  }, 130_000);
  afterAll(() => { if (buildDirectory) rmSync(buildDirectory, { recursive: true, force: true }); });
  it.each(['none', 'password', 'otp', 'publickey-password'])('completes %s authentication and session channels', async (mode) => {
    await run(mode);
  }, 15_000);
  it.each(['otp', 'publickey-password'])('rejects an invalid %s response', async (mode) => {
    await run(mode, true);
  }, 15_000);
});
