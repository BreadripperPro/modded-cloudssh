import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { estimateSFTPEntryBytes, MAX_SFTP_LIST_MEMORY_BYTES, SFTPClient } from '../../src/ssh/sftp';
import { SSH_FXP_NAME, SSH_FXP_STATUS } from '../../src/ssh/sftp-types';
import { concat, encodeString, encodeUint32 } from '../../src/ssh/utils';

const handle = new Uint8Array([1]);
function names(...files: string[]) {
  return concat(new Uint8Array([SSH_FXP_NAME]), encodeUint32(1), encodeUint32(files.length),
    ...files.map(name => concat(encodeString(name), encodeString(''), encodeUint32(0))));
}
function status(code: number, message = '') {
  return concat(new Uint8Array([SSH_FXP_STATUS]), encodeUint32(1), encodeUint32(code),
    encodeString(message), encodeString(''));
}

describe('SFTP directory enumeration budget', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('exactly-at-limit plus EOF is complete, not falsely truncated', async () => {
    const client = new SFTPClient();
    const read = vi.spyOn(client, 'readDir').mockResolvedValueOnce(names('a', 'b'))
      .mockResolvedValueOnce(status(1));
    const result = await client.listAllEntries(handle, 2);
    expect(result.entries.map(entry => entry.filename)).toEqual(['a', 'b']);
    expect(result.isTruncated).toBe(false);
    expect(read).toHaveBeenCalledTimes(2);
  });

  it('collects no more than the limit and signals overflow explicitly', async () => {
    const client = new SFTPClient();
    vi.spyOn(client, 'readDir').mockResolvedValue(names('a', 'b', 'c'));
    const result = await client.listAllEntries(handle, 2);
    expect(result.entries).toHaveLength(2);
    expect(result.isTruncated).toBe(true);
  });

  it('empty NAME batches cannot loop forever even with a positive entry limit', async () => {
    const client = new SFTPClient();
    const read = vi.spyOn(client, 'readDir').mockResolvedValue(names());
    await expect(client.listAllEntries(handle, 2)).rejects.toThrow('no progress');
    expect(read).toHaveBeenCalledTimes(3);
  });

  it('long names hit a byte budget before the count limit can exhaust DO memory', async () => {
    const client = new SFTPClient();
    vi.spyOn(client, 'readDir').mockResolvedValue(names('x'.repeat(8192)));
    const result = await client.listAllEntries(handle);
    expect(result.isTruncated).toBe(true);
    expect(result.entries.length).toBeLessThan(10_000);
    expect(result.entries.reduce((bytes, entry) => bytes + estimateSFTPEntryBytes(entry), 0))
      .toBeLessThanOrEqual(MAX_SFTP_LIST_MEMORY_BYTES);
  });

  it('request count bounds repeated/non-ending batches and invokes a shared budget', async () => {
    const client = new SFTPClient();
    const read = vi.spyOn(client, 'readDir').mockResolvedValue(names('repeat'));
    const beforeRequest = vi.fn();
    await expect(client.listAllEntries(handle, 10, { maxRequests: 2, beforeRequest }))
      .rejects.toThrow('request limit');
    expect(read).toHaveBeenCalledTimes(2);
    expect(beforeRequest).toHaveBeenCalledTimes(2);
  });

  it('honors the total deadline even if the response finally arrives', async () => {
    const client = new SFTPClient();
    const deadline = Date.now() + 10;
    vi.spyOn(client, 'readDir').mockImplementation(async () => {
      vi.setSystemTime(deadline + 1);
      return names('a');
    });
    await expect(client.listAllEntries(handle, 10, { deadline })).rejects.toThrow('deadline');
  });

  it('deadline also shortens a real pending READDIR and removes its timer', async () => {
    const client = new SFTPClient();
    client.setSendCallback(vi.fn());
    const pending = client.listAllEntries(handle, 10, { deadline: Date.now() + 20 })
      .catch(error => error);
    await vi.advanceTimersByTimeAsync(20);
    expect(await pending).toBeInstanceOf(Error);
    expect((client as any).pendingRequests.size).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
    client.dispose();
  });

  it('an expired deadline dispatches nothing', async () => {
    const client = new SFTPClient();
    const send = vi.fn();
    client.setSendCallback(send);
    await expect(client.openDir('/', { deadline: Date.now() })).rejects.toThrow('deadline');
    expect(send).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('EOF-like error text is not proof of complete enumeration', async () => {
    const client = new SFTPClient();
    vi.spyOn(client, 'readDir').mockResolvedValue(status(4, 'unexpected EOF in server'));
    await expect(client.listAllEntries(handle)).rejects.toThrow('unexpected EOF');
  });
});
