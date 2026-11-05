import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  MAX_TERMINAL_OUTPUT_PENDING_BYTES as LIMIT,
  TERMINAL_OUTPUT_ACK_TIMEOUT_MS as TIMEOUT,
} from '../../src/terminal-output-policy';
import { TerminalOutputGuard } from '../../src/worker/terminal-output-guard';

describe('terminal output in-flight guard', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('allows exactly 4 MiB, rejects the next byte without increasing its counter', () => {
    const guard = new TerminalOutputGuard(vi.fn());
    expect(guard.reserve(LIMIT)).toBe(true);
    expect(guard.reserve(1)).toBe(false);
    expect(guard.pendingBytes).toBe(LIMIT);
    guard.dispose();
  });

  it('valid cumulative ACKs allow total output beyond 4 MiB', () => {
    const guard = new TerminalOutputGuard(vi.fn());
    for (let n = 1; n <= 10; n++) {
      expect(guard.reserve(LIMIT)).toBe(true);
      guard.acknowledge(guard.id, n * LIMIT);
      expect(guard.pendingBytes).toBe(0);
    }
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([-1, 0, 1.5, NaN, Infinity, 101, '100', null])('ignores invalid/future ACK %s', (bytes) => {
    const guard = new TerminalOutputGuard(vi.fn());
    guard.reserve(100);
    guard.acknowledge(guard.id, bytes);
    expect(guard.pendingBytes).toBe(100);
    guard.dispose();
  });

  it('does not grant budget for duplicate, decreasing or previous-connection ACKs', () => {
    const guard = new TerminalOutputGuard(vi.fn());
    guard.reserve(100);
    const oldId = guard.id;
    guard.acknowledge(oldId, 60);
    guard.acknowledge(oldId, 60);
    guard.acknowledge(oldId, 50);
    expect(guard.pendingBytes).toBe(40);
    guard.reset();
    guard.reserve(100);
    guard.acknowledge(oldId, 100);
    expect(guard.pendingBytes).toBe(100);
    guard.dispose();
  });

  it('closes a client with no progress after 60s, unaffected by bogus ACKs', () => {
    const stalled = vi.fn();
    const guard = new TerminalOutputGuard(stalled);
    guard.reserve(1);
    vi.advanceTimersByTime(TIMEOUT - 1);
    guard.acknowledge(guard.id, 2);
    guard.reserve(1);
    vi.advanceTimersByTime(1);
    expect(stalled).toHaveBeenCalledOnce();
  });

  it('only real ACK progress restarts the deadline; reset/dispose cancel it', () => {
    const stalled = vi.fn();
    const guard = new TerminalOutputGuard(stalled);
    guard.reserve(100);
    vi.advanceTimersByTime(TIMEOUT - 1);
    guard.acknowledge(guard.id, 50);
    vi.advanceTimersByTime(TIMEOUT - 1);
    expect(stalled).not.toHaveBeenCalled();
    guard.reset();
    guard.reserve(1);
    guard.dispose();
    vi.advanceTimersByTime(TIMEOUT * 2);
    expect(stalled).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
