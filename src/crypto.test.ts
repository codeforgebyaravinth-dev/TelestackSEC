import {
  hkdf,
  hmacSha256,
  encryptAES256GCM,
  decryptAES256GCM,
  generateKeyPair,
  diffieHellman,
  ratchetSend,
  ratchetReceive,
  encryptPrivateKey,
  decryptPrivateKey,
  deriveSessionKeys,
  x3dhSenderKeyAgreement,
  x3dhReceiverKeyAgreement,
} from './crypto';
import { TelestackError, TelestackErrorCode } from './types';

describe('HKDF', () => {
  it('derives a key of the correct length', async () => {
    const ikm = Buffer.from('input-key-material');
    const salt = Buffer.alloc(32, 0);
    const info = Buffer.from('test');
    const derived = await hkdf(ikm, salt, info, 32);
    expect(derived).toHaveLength(32);
  });

  it('is deterministic', async () => {
    const ikm = Buffer.from('same-input');
    const salt = Buffer.alloc(32, 0);
    const info = Buffer.from('test');
    const a = await hkdf(ikm, salt, info, 32);
    const b = await hkdf(ikm, salt, info, 32);
    expect(a.equals(b)).toBe(true);
  });
});

describe('HMAC-SHA256', () => {
  it('produces 32-byte output', () => {
    const result = hmacSha256(Buffer.from('key'), Buffer.from('data'));
    expect(result).toHaveLength(32);
  });
});

describe('AES-256-GCM', () => {
  it('encrypts and decrypts correctly', () => {
    const key = Buffer.alloc(32, 0x42);
    const plaintext = Buffer.from('Hello, World!');
    const { ciphertext, iv, tag } = encryptAES256GCM(key, plaintext);
    const decrypted = decryptAES256GCM(key, ciphertext, iv, tag);
    expect(decrypted.toString()).toBe('Hello, World!');
  });

  it('uses AAD for context binding', () => {
    const key = Buffer.alloc(32, 0x42);
    const plaintext = Buffer.from('secret');
    const aad = Buffer.from('context');
    const { ciphertext, iv, tag } = encryptAES256GCM(key, plaintext, aad);
    // Decryption without AAD should fail
    expect(() => decryptAES256GCM(key, ciphertext, iv, tag)).toThrow();
    // Decryption with correct AAD should succeed
    const decrypted = decryptAES256GCM(key, ciphertext, iv, tag, aad);
    expect(decrypted.toString()).toBe('secret');
  });
});

describe('Key pair generation and DH', () => {
  it('generates valid key pairs', () => {
    const { publicKey, privateKey } = generateKeyPair();
    expect(publicKey.length).toBeGreaterThan(0);
    expect(privateKey.length).toBeGreaterThan(0);
  });

  it('produces the same shared secret for both sides', () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const aliceShared = diffieHellman(alice.privateKey, bob.publicKey);
    const bobShared = diffieHellman(bob.privateKey, alice.publicKey);
    expect(aliceShared.equals(bobShared)).toBe(true);
  });
});

describe('Symmetric ratchet', () => {
  const initialState = () => ({
    rootKey: Buffer.alloc(32, 0x01),
    chainKey: Buffer.alloc(32, 0x02),
    sendCount: 0,
    receiveCount: 0,
    skippedKeys: new Map<number, Buffer>(),
  });

  it('advances chain key on send', async () => {
    const state = initialState();
    const { newState } = await ratchetSend(state);
    expect(newState.sendCount).toBe(1);
    expect(newState.chainKey.equals(state.chainKey)).toBe(false);
  });

  it('send and receive produce the same message key', async () => {
    const state = initialState();
    const { messageKey: sendKey } = await ratchetSend(state);
    const { messageKey: recvKey } = await ratchetReceive(state, 0);
    expect(sendKey.equals(recvKey)).toBe(true);
  });

  it('detects replay attacks', async () => {
    const state = initialState();
    await ratchetReceive(state, 0); // first receive
    const updatedState = { ...state, receiveCount: 1 };
    await expect(ratchetReceive(updatedState, 0)).rejects.toThrow(TelestackError);
  });

  it('handles out-of-order messages', async () => {
    const state = initialState();
    // Receive message 2 before message 1
    const { messageKey: key2 } = await ratchetReceive(state, 2);
    // Message 1 should be stored in skipped keys and recoverable via original state
    const { messageKey: key1 } = await ratchetReceive(state, 0);
    expect(key1.equals(key2)).toBe(false);
  });

  it('throws on excessive message gap', async () => {
    const state = initialState();
    await expect(ratchetReceive(state, 2001)).rejects.toThrow(TelestackError);
  });
});

describe('Private key encryption', () => {
  it('encrypts and decrypts correctly', () => {
    const privateKey = Buffer.from('super-secret-private-key-bytes-here!!');
    const masterKey = 'my-master-key-for-testing-12345678';
    const encrypted = encryptPrivateKey(privateKey, masterKey);
    const decrypted = decryptPrivateKey(encrypted, masterKey);
    expect(decrypted.equals(privateKey)).toBe(true);
  });
});

describe('X3DH key agreement', () => {
  it('sender and receiver derive the same shared secret', async () => {
    const aliceIdentity = generateKeyPair();
    const aliceEphemeral = generateKeyPair();
    const bobIdentity = generateKeyPair();
    const bobSignedPreKey = generateKeyPair();

    const senderSecret = await x3dhSenderKeyAgreement(
      aliceIdentity,
      aliceEphemeral,
      bobIdentity.publicKey,
      bobSignedPreKey.publicKey
    );

    const receiverSecret = await x3dhReceiverKeyAgreement(
      bobIdentity,
      bobSignedPreKey,
      aliceIdentity.publicKey,
      aliceEphemeral.publicKey
    );

    expect(senderSecret.equals(receiverSecret)).toBe(true);
  });

  it('works with one-time prekeys', async () => {
    const aliceIdentity = generateKeyPair();
    const aliceEphemeral = generateKeyPair();
    const bobIdentity = generateKeyPair();
    const bobSignedPreKey = generateKeyPair();
    const bobOneTimePreKey = generateKeyPair();

    const senderSecret = await x3dhSenderKeyAgreement(
      aliceIdentity,
      aliceEphemeral,
      bobIdentity.publicKey,
      bobSignedPreKey.publicKey,
      bobOneTimePreKey.publicKey
    );

    const receiverSecret = await x3dhReceiverKeyAgreement(
      bobIdentity,
      bobSignedPreKey,
      aliceIdentity.publicKey,
      aliceEphemeral.publicKey,
      bobOneTimePreKey
    );

    expect(senderSecret.equals(receiverSecret)).toBe(true);
  });
});

describe('Session key derivation', () => {
  it('derives root and chain keys', async () => {
    const sharedSecret = Buffer.alloc(32, 0x55);
    const { rootKey, chainKey } = await deriveSessionKeys(sharedSecret);
    expect(rootKey).toHaveLength(32);
    expect(chainKey).toHaveLength(32);
    expect(rootKey.equals(chainKey)).toBe(false);
  });
});

describe('Error codes', () => {
  it('TelestackError has correct name and code', () => {
    const err = new TelestackError('test error', TelestackErrorCode.DECRYPTION_FAILED);
    expect(err.name).toBe('TelestackError');
    expect(err.code).toBe(TelestackErrorCode.DECRYPTION_FAILED);
    expect(err.message).toBe('test error');
  });
});
