import { readUint32 } from './utils';

/** Checked SFTP v3 cursor. Lengths are validated BEFORE slicing or advancing. */
export class SFTPReader {
  private offset: number;

  constructor(private readonly data: Uint8Array, offset = 0) {
    this.offset = offset;
    this.require(0);
  }

  get position(): number { return this.offset; }
  get remaining(): number { return this.data.length - this.offset; }

  uint32(): number {
    this.require(4);
    const value = readUint32(this.data, this.offset);
    this.offset += 4;
    return value;
  }

  stringBytes(maxLength = Number.MAX_SAFE_INTEGER): Uint8Array {
    const length = this.uint32();
    if (length > maxLength) throw new Error('SFTP string field limit exceeded');
    this.require(length);
    const bytes = this.data.subarray(this.offset, this.offset + length);
    this.offset += length;
    return bytes;
  }

  end(): void {
    if (this.remaining !== 0) throw new Error('Invalid SFTP response: trailing bytes');
  }

  private require(length: number): void {
    if (!Number.isSafeInteger(this.offset) || this.offset < 0 ||
      !Number.isSafeInteger(length) || length < 0 || length > this.remaining) {
      throw new Error('Invalid SFTP response: truncated field');
    }
  }
}
