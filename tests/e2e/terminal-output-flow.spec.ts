import { expect, test } from './fixtures';
import { mockAnonymousSession } from './helpers';

// Exercise the real SSHTerminal onmessage + trzsz path, not just the ACK helper.
test('binary terminal output is acknowledged by bytes and old sockets cannot send ACKs', async ({ page }) => {
  await mockAnonymousSession(page);
  await page.goto('/');
  await expect(page.locator('#connection-form')).toBeVisible();
  await page.evaluate(async () => {
    const { SSHTerminal } = await (window as any).eval("import('/src/terminal.ts')");
    const root = document.createElement('div');
    root.id = 'output-flow-terminal';
    root.style.cssText = 'position:fixed;inset:0;width:600px;height:300px';
    document.body.appendChild(root);
    const terminal = new SSHTerminal(root.id);
    terminal.mount();
    const frames: any[] = [];
    const socket: any = {
      readyState: WebSocket.OPEN,
      send(frame: string) { if (typeof frame === 'string' && frame.startsWith('{')) frames.push(JSON.parse(frame)); },
      close() { this.readyState = WebSocket.CLOSED; },
    };
    terminal.connectWithWebSocket(socket, undefined, { resetDisplay: false });
    socket.onmessage({ data: JSON.stringify({ type: 'terminal_output_flow', id: 'old' }) });
    socket.onmessage({ data: new TextEncoder().encode('中文\r\n').buffer });
    (window as any).__outputFlow = { terminal, socket, frames };
  });
  await expect.poll(() => page.evaluate(() => (window as any).__outputFlow.frames
    .filter((frame: any) => frame.type === 'terminal_output_ack')))
    .toEqual([{ type: 'terminal_output_ack', id: 'old', bytes: 8 }]);
  await expect.poll(() => page.evaluate(() => {
    const buffer = (window as any).__outputFlow.terminal.terminal.buffer.active;
    return Array.from({ length: buffer.length }, (_, i) => buffer.getLine(i).translateToString()).join('\n');
  })).toContain('中文');

  await page.evaluate(() => {
    const { terminal, socket, frames } = (window as any).__outputFlow;
    socket.onmessage({ data: new Uint8Array([65]).buffer }); // pending batched ACK
    const nextSocket: any = {
      readyState: WebSocket.OPEN,
      send(frame: string) { if (typeof frame === 'string' && frame.startsWith('{')) frames.push(JSON.parse(frame)); },
      close() { this.readyState = WebSocket.CLOSED; },
    };
    terminal.connectWithWebSocket(nextSocket, undefined, { resetDisplay: false });
    socket.onmessage({ data: new Uint8Array([66]).buffer }); // stale socket ignored
    nextSocket.onmessage({ data: JSON.stringify({ type: 'terminal_output_flow', id: 'new' }) });
    nextSocket.onmessage({ data: new Uint8Array([67]).buffer });
  });
  await expect.poll(() => page.evaluate(() => (window as any).__outputFlow.frames
    .filter((frame: any) => frame.type === 'terminal_output_ack')))
    .toEqual([
      { type: 'terminal_output_ack', id: 'old', bytes: 8 },
      { type: 'terminal_output_ack', id: 'new', bytes: 1 },
    ]);
  const fatal = await page.evaluate(() => {
    const { terminal } = (window as any).__outputFlow;
    let willReconnect: boolean | null = null;
    terminal.reconnectWebSocketFactory = async () => { throw new Error('must not retry'); };
    terminal.setSessionClosedHandler((_event: unknown, retry: boolean) => { willReconnect = retry; });
    const socket = terminal.ws;
    socket.onmessage({ data: JSON.stringify({ type: 'error', event: 'packet_error',
      params: { message: 'authentication failed' } }) });
    socket.readyState = WebSocket.CLOSED;
    socket.onclose({ code: 1011 });
    const result = { canReconnect: terminal.canReconnect, willReconnect };
    terminal.dispose();
    return result;
  });
  expect(fatal).toEqual({ canReconnect: false, willReconnect: false });
});
