import {
  MAX_TERMINAL_OUTPUT_PENDING_BYTES,
  TERMINAL_OUTPUT_ACK_TIMEOUT_MS,
} from '../terminal-output-policy';

/** Bound stdout + stderr in flight to one WebSocket, without retaining payloads. */
export class TerminalOutputGuard {
  private sent = 0;
  private acknowledged = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private epoch = crypto.randomUUID();

  constructor(private readonly onStalled: () => void) {}

  get id(): string { return this.epoch; }
  get pendingBytes(): number { return this.sent - this.acknowledged; }

  reserve(bytes: number): boolean {
    if (!Number.isSafeInteger(bytes) || bytes < 0 ||
      bytes > MAX_TERMINAL_OUTPUT_PENDING_BYTES - this.pendingBytes ||
      !Number.isSafeInteger(this.sent + bytes)) return false;
    this.sent += bytes;
    if (this.pendingBytes > 0 && this.timer === null) this.armDeadline();
    return true;
  }

  acknowledge(id: unknown, bytes: unknown): void {
    // Cumulative count: duplicates, stale connections, future/negative ACKs cannot
    // free budget. A client ACK is flow control only, never user activity/auth.
    if (id !== this.epoch || typeof bytes !== 'number' || !Number.isSafeInteger(bytes) ||
      bytes <= this.acknowledged || bytes > this.sent) return;
    this.acknowledged = bytes;
    this.clearDeadline();
    if (this.pendingBytes > 0) this.armDeadline();
  }

  reset(): void {
    this.clearDeadline();
    this.sent = 0;
    this.acknowledged = 0;
    this.epoch = crypto.randomUUID();
  }

  dispose(): void { this.clearDeadline(); }

  private armDeadline(): void {
    this.timer = setTimeout(() => {
      this.timer = null;
      this.onStalled();
    }, TERMINAL_OUTPUT_ACK_TIMEOUT_MS);
  }

  private clearDeadline(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }
}
