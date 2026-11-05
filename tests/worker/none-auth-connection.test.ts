import { describe, expect, it, vi } from 'vitest';
import { SSHSessionDO } from '../../src/worker/durable-object';

function createConnection() {
  const instance = new SSHSessionDO({} as DurableObjectState, {} as never);
  const init = vi.fn(async () => {});
  (instance as any).initSSHSession = init;
  const ws = { send: vi.fn(), close: vi.fn() };
  return { instance, init, ws, socket: ws as unknown as WebSocket };
}

const target = { host: 'ssh.example.com', port: 22, username: 'access-token-user' };

describe('Anonymous SSH authentication configuration', () => {
  it('仅显式 none 允许无密码/私钥，并剥离残留凭据及客户端注入策略', async () => {
    const { instance, init, ws, socket } = createConnection();
    await instance.webSocketMessage(socket, JSON.stringify({
      ...target,
      authMethod: 'none',
      password: 'stale-password',
      privateKey: 'stale-key',
      userId: '7',
      jumpHosts: [{ host: 'private.example.com' }],
      sessionPolicy: { source: 'share' },
    }));
    expect(init).toHaveBeenCalledWith(socket, { ...target, authMethod: 'none', password: '' }, undefined, undefined);
    expect(ws.close).not.toHaveBeenCalled();
    expect(JSON.stringify(ws.send.mock.calls)).not.toContain(target.username);
  });

  it('none 不需要提供任何密码或私钥字段', async () => {
    const { instance, init, socket } = createConnection();
    await instance.webSocketMessage(socket, JSON.stringify({ ...target, authMethod: 'none' }));
    expect(init).toHaveBeenCalledOnce();
  });

  it.each([undefined, 'password'])('password 允许明确的空字符串（authMethod=%s）', async (authMethod) => {
    const { instance, init, ws, socket } = createConnection();
    await instance.webSocketMessage(socket, JSON.stringify({ ...target, authMethod, password: '' }));
    expect(init).toHaveBeenCalledOnce();
    expect(ws.close).not.toHaveBeenCalled();
  });

  it.each([
    { authMethod: 'password', password: null },
    { authMethod: 'password', password: false },
    { authMethod: 'password', password: 123 },
    { authMethod: 'publickey', password: '', privateKey: '' },
    { authMethod: 'publickey', password: 'not-a-key' },
    { authMethod: 'invalid', password: '' },
  ])('拒绝错误类型密码或缺失私钥：%j', async (config) => {
    const { instance, init, ws, socket } = createConnection();
    await instance.webSocketMessage(socket, JSON.stringify({ ...target, ...config }));
    expect(init).not.toHaveBeenCalled();
    expect(ws.close).toHaveBeenCalledWith(1011, 'Invalid credentials');
  });

  it.each([undefined, 'password', 'publickey', 'invalid'])('其他模式仍拒绝缺失凭据（%s）', async (authMethod) => {
    const { instance, init, ws, socket } = createConnection();
    await instance.webSocketMessage(socket, JSON.stringify({ ...target, authMethod }));
    expect(init).not.toHaveBeenCalled();
    expect(ws.close).toHaveBeenCalledWith(1011, 'Invalid credentials');
  });

  it.each(['host', 'username'])('none 仍要求 %s', async (field) => {
    const { instance, init, ws, socket } = createConnection();
    await instance.webSocketMessage(socket, JSON.stringify({ ...target, authMethod: 'none', [field]: '' }));
    expect(init).not.toHaveBeenCalled();
    expect(ws.close).toHaveBeenCalledWith(1011, 'Invalid credentials');
  });
});
