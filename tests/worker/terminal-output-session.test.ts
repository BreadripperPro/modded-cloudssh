/// <reference lib="es2022" />
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SSHChannel } from '../../src/ssh/channel';
import { writeUint32 } from '../../src/ssh/utils';
import { SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA } from '../../src/types';
import { MAX_TERMINAL_OUTPUT_PENDING_BYTES as LIMIT, TERMINAL_OUTPUT_ACK_TIMEOUT_MS as TIMEOUT } from '../../src/terminal-output-policy';
import { SSHSession } from '../../src/worker/ssh-session';

function createSession() {
  const ws = { send: vi.fn(), close: vi.fn(), readyState: 1 };
  const socket = { close: vi.fn() };
  const session = new SSHSession(ws as unknown as WebSocket, socket as never, {
    host: 'ssh.example.com', port: 22, username: 'alice', authMethod: 'password', password: 'secret',
  });
  const internal = session as any;
  internal.state = 'ready';
  const channel = new SSHChannel();
  internal.shellChannel = channel;
  internal.channels.set(0, channel);
  const adjust = vi.spyOn(internal, 'queueLocalWindowAdjust').mockImplementation(() => {});
  return { session, internal, ws, socket, adjust };
}

function payload(type: number, bytes: number) {
  const extended = type === SSH_MSG_CHANNEL_EXTENDED_DATA;
  const offset = extended ? 13 : 9;
  const data = new Uint8Array(offset + bytes);
  data[0] = type;
  writeUint32(data, 1, 0);
  if (extended) writeUint32(data, 5, 1);
  writeUint32(data, offset - 4, bytes);
  return data;
}

function flowId(ws: { send: ReturnType<typeof vi.fn> }): string {
  const frame = ws.send.mock.calls.map(([data]) => typeof data === 'string' ? JSON.parse(data) : null)
    .find((frame) => frame?.type === 'terminal_output_flow');
  return frame.id;
}

describe('SSH terminal output cost/availability gate', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('stdout + stderr share the 4 MiB cap; overflow stops forwarding/window renewals and closes normally', async () => {
    const { internal, ws, socket, adjust } = createSession();
    const chunkSize = 32 * 1024;
    for (let i = 0; i < LIMIT / chunkSize; i++) {
      const type = i % 2 === 0 ? SSH_MSG_CHANNEL_DATA : SSH_MSG_CHANNEL_EXTENDED_DATA;
      await internal.handleSessionPacket(type, payload(type, chunkSize));
    }
    expect(internal.terminalOutputGuard.pendingBytes).toBe(LIMIT);
    expect(adjust).toHaveBeenCalledTimes(LIMIT / chunkSize);
    await internal.handleSessionPacket(SSH_MSG_CHANNEL_DATA, payload(SSH_MSG_CHANNEL_DATA, 1));
    expect(ws.send.mock.calls.filter(([data]) => data instanceof Uint8Array))
      .toHaveLength(LIMIT / chunkSize);
    expect(adjust).toHaveBeenCalledTimes(LIMIT / chunkSize);
    expect(socket.close).toHaveBeenCalledOnce();
    expect(ws.close).toHaveBeenCalledWith(1000);
    expect(ws.send).toHaveBeenCalledWith(expect.stringContaining('output_backlog_closed'));
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ACKs free budget without becoming SSH input or resetting user activity', async () => {
    const { session, internal, ws } = createSession();
    await internal.handleSessionPacket(SSH_MSG_CHANNEL_DATA, payload(SSH_MSG_CHANNEL_DATA, 100));
    const input = vi.spyOn(internal, 'enqueueChannelData');
    const activity = session.getLastUserActivityAt();
    vi.advanceTimersByTime(1000);
    await session.handleWebSocketMessage(JSON.stringify({ type: 'terminal_output_ack', id: flowId(ws), bytes: 100 }));
    expect(internal.terminalOutputGuard.pendingBytes).toBe(0);
    expect(input).not.toHaveBeenCalled();
    expect(session.getLastUserActivityAt()).toBe(activity);
    session.close(true);
  });

  it('ping/remote output cannot keep an unacknowledged client alive indefinitely', async () => {
    const { session, internal, ws, socket } = createSession();
    await internal.handleSessionPacket(SSH_MSG_CHANNEL_DATA, payload(SSH_MSG_CHANNEL_DATA, 1));
    vi.advanceTimersByTime(TIMEOUT - 1);
    await session.handleWebSocketMessage('{"type":"ping"}');
    await internal.handleSessionPacket(SSH_MSG_CHANNEL_EXTENDED_DATA, payload(SSH_MSG_CHANNEL_EXTENDED_DATA, 1));
    vi.advanceTimersByTime(1);
    expect(socket.close).toHaveBeenCalledOnce();
    expect(ws.close).toHaveBeenCalledWith(1000);
  });

  it('detach cancels the deadline; replay is charged to a new epoch and rejects old ACKs', async () => {
    const { session, internal, ws } = createSession();
    await internal.handleSessionPacket(SSH_MSG_CHANNEL_DATA, payload(SSH_MSG_CHANNEL_DATA, 10));
    const oldId = flowId(ws);
    session.setDetached(true);
    vi.advanceTimersByTime(TIMEOUT * 2);
    expect(ws.close).not.toHaveBeenCalled();
    await internal.handleSessionPacket(SSH_MSG_CHANNEL_DATA, payload(SSH_MSG_CHANNEL_DATA, 20));
    const nextWs = { send: vi.fn(), close: vi.fn(), readyState: 1 };
    await session.reattachWebSocket(nextWs as unknown as WebSocket);
    expect(flowId(nextWs)).not.toBe(oldId);
    expect(internal.terminalOutputGuard.pendingBytes).toBe(20);
    await session.handleWebSocketMessage(JSON.stringify({ type: 'terminal_output_ack', id: oldId, bytes: 20 }));
    expect(internal.terminalOutputGuard.pendingBytes).toBe(20);
    await session.handleWebSocketMessage(JSON.stringify({ type: 'terminal_output_ack', id: flowId(nextWs), bytes: 20 }));
    expect(internal.terminalOutputGuard.pendingBytes).toBe(0);
    session.close(true);
  });

  it('failed output sends terminate instead of continuing to renew the SSH window', async () => {
    const { internal, ws, socket, adjust } = createSession();
    ws.send.mockImplementation(() => { throw new Error('closed'); });
    await internal.handleSessionPacket(SSH_MSG_CHANNEL_DATA, payload(SSH_MSG_CHANNEL_DATA, 10));
    expect(adjust).not.toHaveBeenCalled();
    expect(socket.close).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });
});
