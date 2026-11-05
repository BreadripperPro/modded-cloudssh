import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TerminalOutputAck } from '../frontend/src/terminal-output-ack';
import { TERMINAL_OUTPUT_ACK_INTERVAL_MS as INTERVAL } from '../src/terminal-output-policy';

describe('terminal output receipt ACK', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('batches raw bytes, not decoded characters, into cumulative ACKs', () => {
    const send = vi.fn();
    const ack = new TerminalOutputAck(send);
    ack.start('current');
    ack.receive(new TextEncoder().encode('中文').length);
    ack.receive(100);
    expect(send).not.toHaveBeenCalled();
    vi.advanceTimersByTime(INTERVAL);
    expect(JSON.parse(send.mock.calls[0][0])).toEqual({ type: 'terminal_output_ack', id: 'current', bytes: 106 });
    ack.receive(1);
    vi.advanceTimersByTime(INTERVAL);
    expect(JSON.parse(send.mock.calls[1][0]).bytes).toBe(107);
  });

  it('resets epochs and cancels ACKs on socket replacement or close', () => {
    const send = vi.fn();
    const ack = new TerminalOutputAck(send);
    ack.start('old');
    ack.receive(100);
    ack.start('new');
    vi.advanceTimersByTime(INTERVAL);
    expect(send).not.toHaveBeenCalled();
    ack.receive(10);
    vi.advanceTimersByTime(INTERVAL);
    expect(JSON.parse(send.mock.calls[0][0])).toEqual({ type: 'terminal_output_ack', id: 'new', bytes: 10 });
    ack.receive(10);
    ack.dispose();
    vi.advanceTimersByTime(INTERVAL);
    expect(send).toHaveBeenCalledOnce();
  });

  it('does not send ACKs to legacy servers without flow announcement', () => {
    const send = vi.fn();
    const ack = new TerminalOutputAck(send);
    ack.receive(100);
    ack.start(null);
    ack.receive(100);
    vi.advanceTimersByTime(INTERVAL);
    expect(send).not.toHaveBeenCalled();
  });
});
