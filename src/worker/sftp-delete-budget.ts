import { MAX_SFTP_LIST_ENTRIES } from '../ssh/sftp';

export const SFTP_DELETE_POLICY = {
  maxEntries: 50_000,
  maxEntryBytes: 16 * 1024 * 1024,
  maxRequests: 100_000,
  maxDepth: 64,
  maxDirectoryEntries: MAX_SFTP_LIST_ENTRIES,
  timeoutMs: 5 * 60_000,
} as const;

/** One budget shared by the entire deletion tree, not restarted per directory. */
export class SFTPDeleteBudget {
  readonly deadline: number;
  readonly policy: { [K in keyof typeof SFTP_DELETE_POLICY]: number };
  private entries = 0;
  private entryBytes = 0;
  private requests = 0;

  constructor(policy: Partial<SFTPDeleteBudget['policy']> = {}) {
    this.policy = { ...SFTP_DELETE_POLICY, ...policy };
    this.deadline = Date.now() + this.policy.timeoutMs;
  }

  checkDepth(depth: number): void {
    this.checkTime();
    if (depth > this.policy.maxDepth) throw new Error('SFTP recursive delete depth limit exceeded');
  }

  takeEntries(count: number, bytes = 0): void {
    this.checkTime();
    if (count > this.policy.maxEntries - this.entries) {
      throw new Error('SFTP recursive delete entry limit exceeded');
    }
    if (bytes > this.policy.maxEntryBytes - this.entryBytes) {
      throw new Error('SFTP recursive delete listing memory limit exceeded');
    }
    this.entries += count;
    this.entryBytes += bytes;
  }

  takeRequests(count = 1): void {
    this.checkTime();
    if (count > this.policy.maxRequests - this.requests) {
      throw new Error('SFTP recursive delete request limit exceeded');
    }
    this.requests += count;
  }

  checkTime(): void {
    if (Date.now() >= this.deadline) throw new Error('SFTP recursive delete deadline exceeded');
  }
}
