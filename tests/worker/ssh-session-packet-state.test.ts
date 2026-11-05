/// <reference lib="es2022" />
import { describe, expect, it, vi } from 'vitest';
import { SSHAESCTRCipher, SSHAESGCMCipher, SSHHMAC } from '../../src/ssh/crypto';
import { KEXInitBuilder } from '../../src/ssh/kex';
import { SSHPacketBuilder } from '../../src/ssh/packet';
import { concat } from '../../src/ssh/utils';
import { SSHSession } from '../../src/worker/ssh-session';

function createSession() {
  const ws = {
    readyState: 1,
    send: vi.fn(),
    close: vi.fn(),
  };
  const socket = { close: vi.fn() };
  const session = new SSHSession(ws as unknown as WebSocket, socket as never, {
    host: 'ssh.example.com',
    port: 22,
    username: 'alice',
    password: 'secret',
    authMethod: 'password',
  });
  return { session, ws, socket };
}

describe('SSHSession packet encryption state', () => {
  it('close during an awaited parse prevents subsequent packet dispatch', async () => {
    const { session } = createSession();
    const internal = session as any;
    let finish!: (packet: any) => void;
    internal.packetParser = {
      nextPacket: vi.fn(() => new Promise(resolve => { finish = resolve; })),
      getBufferLength: vi.fn(() => 0), clear: vi.fn(),
    };
    internal.handlePacket = vi.fn();
    const processing = internal.processPackets();
    session.close(true);
    finish({ payload: new Uint8Array([2]), length: 1, paddingLength: 0 });
    await processing;
    expect(internal.handlePacket).not.toHaveBeenCalled();
    expect(internal.packetParser.clear).toHaveBeenCalledOnce();
  });

  it('close during socket read never feeds late bytes back into cleared buffers', async () => {
    const { session, socket } = createSession();
    const internal = session as any;
    let finish!: (result: any) => void;
    Object.assign(socket, { readable: { getReader: () => ({
      read: () => new Promise(resolve => { finish = resolve; }),
    }) } });
    const feed = vi.spyOn(internal.packetParser, 'feed');
    const reading = internal.startReading();
    session.close(true);
    finish({ done: false, value: new Uint8Array(100) });
    await reading;
    expect(feed).not.toHaveBeenCalled();
    expect(internal.packetParser.getBufferLength()).toBe(0);
  });

  it('invalid GCM tag closes TCP/WS immediately and discards queued packets', async () => {
    const { session, ws, socket } = createSession();
    const internal = session as any;
    const key = new Uint8Array(16);
    const iv = new Uint8Array(12);
    const encrypt = new SSHAESGCMCipher(key, iv);
    const decrypt = new SSHAESGCMCipher(key, iv);
    await encrypt.init();
    await decrypt.init();
    internal.state = 'ready';
    internal.negotiatedCipherS2C = 'aes128-gcm@openssh.com';
    internal.decryptCipher = decrypt;
    const decryptSpy = vi.spyOn(decrypt, 'decrypt');
    const wire = await SSHPacketBuilder.build(
      new Uint8Array([2]), 16, (data, seq, aad) => encrypt.encrypt(data, seq, aad), 0, true
    );
    wire[wire.length - 1] ^= 1;
    internal.packetParser.feed(concat(wire, wire));
    await internal.processPackets();
    expect(socket.close).toHaveBeenCalledOnce();
    expect(ws.close).toHaveBeenCalledWith(1011);
    expect(ws.send).toHaveBeenCalledWith(expect.stringContaining('packet_error'));
    expect(internal.packetParser.getBufferLength()).toBe(0);
    expect(decryptSpy).toHaveBeenCalledOnce();
    await internal.processPackets();
    expect(decryptSpy).toHaveBeenCalledOnce();
  });

  it.each([
    {
      cipher: 'aes128-gcm@openssh.com',
      mac: 'none',
      expectedAuthTag: true,
      expectedMacLength: 0,
    },
    {
      cipher: 'aes128-ctr',
      mac: 'hmac-sha2-256',
      expectedAuthTag: false,
      expectedMacLength: 32,
    },
  ])(
    'recomputes $cipher framing after a packet enables encryption',
    async ({ cipher, mac, expectedAuthTag, expectedMacLength }) => {
      const { session } = createSession();
      const internal = session as any;
      const decrypt = vi.fn(async (data: Uint8Array) => data);
      const verify = vi.fn(async () => true);
      const nextPacket = vi
        .fn()
        .mockResolvedValueOnce({
          length: 12,
          paddingLength: 10,
          payload: new Uint8Array([21]),
          mac: new Uint8Array(0),
        })
        .mockResolvedValueOnce(null);

      internal.negotiatedCipherS2C = cipher;
      internal.negotiatedMacS2C = mac;
      internal.packetParser = {
        nextPacket,
        getBufferLength: vi.fn(() => 0),
      };
      internal.handlePacket = vi.fn(async () => {
        internal.decryptCipher = { decrypt };
        internal.decryptMac = expectedMacLength > 0 ? { verify } : null;
      });

      await internal.processPackets();

      expect(nextPacket).toHaveBeenCalledTimes(2);
      expect(nextPacket.mock.calls[0][0]).toBe(8);
      expect(nextPacket.mock.calls[0][2]).toBe(false);
      expect(nextPacket.mock.calls[0][3]).toBe(0);

      const [blockSize, decryptPacket, hasAuthTag, macLength, verifyMac] = nextPacket.mock.calls[1];
      expect(blockSize).toBe(16);
      expect(hasAuthTag).toBe(expectedAuthTag);
      expect(macLength).toBe(expectedMacLength);
      expect(typeof decryptPacket).toBe('function');
      expect(typeof verifyMac === 'function').toBe(expectedMacLength > 0);
    }
  );

  it('parses NEWKEYS and the first CTR/HMAC packet from one TCP chunk', async () => {
    const { session, ws, socket } = createSession();
    const internal = session as any;
    const keys = {
      ivClientToServer: new Uint8Array(16).fill(0x11),
      ivServerToClient: new Uint8Array(16).fill(0x22),
      encKeyClientToServer: new Uint8Array(16).fill(0x33),
      encKeyServerToClient: new Uint8Array(16).fill(0x44),
      integrityKeyC2S: new Uint8Array(32).fill(0x55),
      integrityKeyS2C: new Uint8Array(32).fill(0x66),
      sessionID: new Uint8Array(32).fill(0x77),
    };

    internal.state = 'kex';
    internal.derivedKeys = keys;
    internal.negotiatedCipherC2S = 'aes128-ctr';
    internal.negotiatedCipherS2C = 'aes128-ctr';
    internal.negotiatedMacC2S = 'hmac-sha2-256';
    internal.negotiatedMacS2C = 'hmac-sha2-256';
    internal.writeSocket = vi.fn(async () => {});
    const handlePacket = vi.spyOn(internal, 'handlePacket');

    const serverCipher = new SSHAESCTRCipher(keys.encKeyServerToClient, keys.ivServerToClient);
    const serverMac = new SSHHMAC('hmac-sha2-256', keys.integrityKeyS2C);
    await serverCipher.init();
    await serverMac.init();

    const newKeysPacket = await SSHPacketBuilder.build(new Uint8Array([21]), 8, null, 0);
    const extInfoPacket = await SSHPacketBuilder.build(
      new Uint8Array([7, 0, 0, 0, 0]),
      16,
      (data, seq, aad) => serverCipher.encrypt(data, seq, aad),
      1,
      false,
      (packet, seq) => serverMac.sign(packet, seq)
    );

    internal.packetParser.feed(concat(newKeysPacket, extInfoPacket));
    await internal.processPackets();

    expect(handlePacket).toHaveBeenCalledTimes(2);
    expect(handlePacket.mock.calls.map(([packet]: any[]) => packet.payload[0])).toEqual([21, 7]);
    expect(internal.packetParser.getBufferLength()).toBe(0);
    expect(internal.state).toBe('auth');
    expect(ws.close).not.toHaveBeenCalled();
    expect(socket.close).not.toHaveBeenCalled();
  });

  it('sendMutex resets to a fresh resolved Promise when queue drains to prevent unbounded chain leak', async () => {
    const { session } = createSession();
    const internal = session as any;
    internal.socketWriter = { write: vi.fn(async () => {}) };

    const initialMutex = internal.sendMutex;
    await internal.sendEncryptedPacket(async () => new Uint8Array([1, 2, 3]));

    // After all writes finish, sendMutex is reset to a fresh resolved Promise
    expect(internal.sendMutexPendingCount).toBe(0);
    expect(internal.sendMutex).not.toBe(initialMutex);

    // Verify it resolves immediately without pending chain
    let resolved = false;
    void internal.sendMutex.then(() => {
      resolved = true;
    });
    await Promise.resolve();
    expect(resolved).toBe(true);
  });

  it('handles server-initiated SSH_MSG_KEXINIT in ready state (Rekeying) and restores ready state seamlessly', async () => {
    const { session, ws, socket } = createSession();
    const internal = session as any;

    internal.state = 'ready';
    internal.encryptCipher = { encrypt: vi.fn(async (d: Uint8Array) => d) };
    internal.decryptCipher = { decrypt: vi.fn(async (d: Uint8Array) => d) };
    internal.writeSocket = vi.fn(async () => {});
    internal.enableEncryption = vi.fn(async () => {});
    internal.handleECDHReply = vi.fn(async () => {});

    // Valid KEXINIT payload from server
    const serverKexPayload = KEXInitBuilder.build();

    // Step 1: Server sends KEXINIT during ready state
    await internal.handlePacket({
      length: serverKexPayload.length,
      paddingLength: 0,
      payload: serverKexPayload,
    });

    expect(internal.isRekeying).toBe(true);
    expect(internal.state).toBe('rekey');
    expect(internal.isReady()).toBe(true); // isReady() reports true during rekeying to avoid false disconnects

    // Step 2: Server sends ECDH reply
    await internal.handlePacket({
      length: 1,
      paddingLength: 0,
      payload: new Uint8Array([31]), // SSH_MSG_KEX_ECDH_REPLY
    });
    expect(internal.handleECDHReply).toHaveBeenCalled();

    // Step 3: Server sends NEWKEYS
    await internal.handlePacket({
      length: 1,
      paddingLength: 0,
      payload: new Uint8Array([21]), // SSH_MSG_NEWKEYS
    });

    // Successfully completes rekeying and restores to ready state
    expect(internal.isRekeying).toBe(false);
    expect(internal.state).toBe('ready');
    expect(internal.enableEncryption).toHaveBeenCalled();
    expect(ws.close).not.toHaveBeenCalled();
    expect(socket.close).not.toHaveBeenCalled();
  });
});
