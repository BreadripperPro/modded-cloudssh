import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SSHChannel } from '../../src/ssh/channel';
import type { SFTPFileEntry } from '../../src/ssh/sftp-types';
import { SSH_FXP_HANDLE, SSH_FXP_STATUS, SSH_S_IFDIR, SSH_S_IFLNK } from '../../src/ssh/sftp-types';
import { SFTPDeleteBudget } from '../../src/worker/sftp-delete-budget';
import { SFTPHandler } from '../../src/worker/sftp-handler';

function entry(filename: string, permissions = 0o100644): SFTPFileEntry {
  return { filename, longname: '', attrs: { permissions } };
}
function fixture(entries: SFTPFileEntry[], isTruncated = false) {
  const sendJSON = vi.fn();
  const handler = new SFTPHandler(1, new SSHChannel(), vi.fn(), sendJSON, vi.fn(), vi.fn());
  const sftp = {
    openDir: vi.fn(async () => new Uint8Array([SSH_FXP_HANDLE])),
    parseHandleResponse: vi.fn(() => new Uint8Array([1])),
    listAllEntries: vi.fn(async () => ({ entries, isTruncated })),
    closeHandle: vi.fn(async () => {}),
    removeFile: vi.fn(async () => new Uint8Array([SSH_FXP_STATUS])),
    rmdir: vi.fn(async () => new Uint8Array([SSH_FXP_STATUS])),
    parseStatusResponse: vi.fn(() => ({ code: 0, message: 'OK' })),
  };
  Object.assign(handler, { sftp, ready: true });
  return { handler, sftp, sendJSON };
}

describe('bounded recursive SFTP deletion', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('truncated listing closes its handle and performs no partial deletion', async () => {
    const { handler, sftp } = fixture([entry('a')], true);
    await expect((handler as any).rmdirRecursive('/root')).rejects.toThrow('directory entry limit');
    expect(sftp.closeHandle).toHaveBeenCalledOnce();
    expect(sftp.removeFile).not.toHaveBeenCalled();
    expect(sftp.rmdir).not.toHaveBeenCalled();
  });

  it('shared entry budget fails before deleting a newly enumerated directory', async () => {
    const { handler, sftp } = fixture([entry('a'), entry('b')]);
    const budget = new SFTPDeleteBudget({ maxEntries: 1 });
    await expect((handler as any).rmdirRecursive('/root', budget)).rejects.toThrow('entry limit');
    expect(sftp.closeHandle).toHaveBeenCalledOnce();
    expect(sftp.removeFile).not.toHaveBeenCalled();
  });

  it('shared listing memory budget also stops before deleting entries', async () => {
    const { handler, sftp } = fixture([entry('a')]);
    const budget = new SFTPDeleteBudget({ maxEntryBytes: 1 });
    await expect((handler as any).rmdirRecursive('/root', budget)).rejects.toThrow('memory limit');
    expect(sftp.closeHandle).toHaveBeenCalledOnce();
    expect(sftp.removeFile).not.toHaveBeenCalled();
  });

  it('depth limit is shared across the tree; symlinks never recurse', async () => {
    const { handler, sftp } = fixture([entry('link', SSH_S_IFLNK), entry('child', SSH_S_IFDIR)]);
    const budget = new SFTPDeleteBudget({ maxDepth: 0 });
    await expect((handler as any).rmdirRecursive('/root', budget)).rejects.toThrow('depth limit');
    expect(sftp.openDir).toHaveBeenCalledOnce();
    expect(sftp.removeFile).toHaveBeenCalledWith('/root/link', { deadline: budget.deadline });
    expect(sftp.rmdir).not.toHaveBeenCalled();
  });

  it('deadline expiry still attempts bounded handle cleanup, then stops mutations', async () => {
    const { handler, sftp } = fixture([entry('a')]);
    const budget = new SFTPDeleteBudget({ timeoutMs: 10 });
    sftp.listAllEntries.mockImplementation(async () => {
      vi.setSystemTime(budget.deadline + 1);
      return { entries: [entry('a')], isTruncated: false };
    });
    await expect((handler as any).rmdirRecursive('/root', budget)).rejects.toThrow('deadline');
    expect(sftp.closeHandle).toHaveBeenCalledWith(new Uint8Array([1]), {
      deadline: Math.min(budget.deadline + 5000, Date.now() + 5000),
    });
    expect(sftp.removeFile).not.toHaveBeenCalled();
  });

  it('reserves cleanup and stops when the shared request budget is exhausted', async () => {
    const { handler, sftp } = fixture([entry('a')]);
    const budget = new SFTPDeleteBudget({ maxRequests: 2 });
    await expect((handler as any).rmdirRecursive('/root', budget)).rejects.toThrow('request limit');
    expect(sftp.closeHandle).toHaveBeenCalledOnce();
    expect(sftp.removeFile).not.toHaveBeenCalled();
  });

  it.each(['../escape', 'sub/file', 'sub\\file', 'bad\0name', ''])(
    'rejects invalid child name %s before mutating any listed entry', async name => {
      const { handler, sftp } = fixture([entry('safe'), entry(name)]);
      await expect((handler as any).rmdirRecursive('/root')).rejects.toThrow('entry name');
      expect(sftp.removeFile).not.toHaveBeenCalled();
      expect(sftp.closeHandle).toHaveBeenCalledOnce();
    }
  );

  it('skips dot entries and supports directories larger than the UI 2000-entry page', async () => {
    const { handler, sftp } = fixture([entry('.'), entry('..'),
      ...Array.from({ length: 2001 }, (_, i) => entry(`f${i}`))]);
    await (handler as any).rmdirRecursive('/root');
    expect(sftp.listAllEntries).toHaveBeenCalledWith(new Uint8Array([1]), 10_000,
      expect.objectContaining({ beforeRequest: expect.any(Function) }));
    expect(sftp.removeFile).toHaveBeenCalledTimes(2001);
    expect(sftp.rmdir).toHaveBeenCalledOnce();
  });

  it('permission failure text does not trigger recursion or report success', async () => {
    const { handler, sftp, sendJSON } = fixture([]);
    sftp.parseStatusResponse.mockReturnValue({ code: 3, message: 'Failure' });
    await handler.removeDirectory('/root');
    expect(sftp.openDir).not.toHaveBeenCalled();
    expect(sendJSON).toHaveBeenCalledWith(expect.objectContaining({ type: 'sftp_error' }));
    expect(sendJSON).not.toHaveBeenCalledWith(expect.objectContaining({ success: true }));
  });
});
