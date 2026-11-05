import { TERMINAL_OUTPUT_ACK_INTERVAL_MS } from '../../src/terminal-output-policy';

/** Batch cumulative WebSocket receipt ACKs; no output data is retained here. */
export class TerminalOutputAck {
  private id: string | null = null;
  private received = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly send: (frame: string) => void) {}

  start(id: unknown): void {
    this.dispose();
    this.id = typeof id === 'string' && id.length <= 64 ? id : null;
    this.received = 0;
  }

  receive(bytes: number): void {
    if (!this.id || !Number.isSafeInteger(bytes) || bytes <= 0) return;
    this.received += bytes;
    if (this.timer !== null) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      this.send(JSON.stringify({ type: 'terminal_output_ack', id: this.id, bytes: this.received }));
    }, TERMINAL_OUTPUT_ACK_INTERVAL_MS);
  }

  dispose(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.id = null;
  }
}
