// WebSocket receipt accounting, not a lifetime output limit or a shell sandbox.
// Workers WebSockets expose no usable bufferedAmount/drain API; bound bytes sent
// but not yet acknowledged by the current browser connection instead.
export const MAX_TERMINAL_OUTPUT_PENDING_BYTES = 4 * 1024 * 1024;
export const TERMINAL_OUTPUT_ACK_TIMEOUT_MS = 60_000;
export const TERMINAL_OUTPUT_ACK_INTERVAL_MS = 16;
