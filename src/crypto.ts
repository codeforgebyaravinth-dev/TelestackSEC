import * as crypto from 'crypto';
import { TelestackError, TelestackErrorCode } from './types';

const MAX_SKIP = 2000;

export function hkdf(
  inputKeyMaterial: Buffer,
  salt: Buffer,
  info: Buffer,
  outputLength: number
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.hkdf('sha256', inputKeyMaterial, salt, info, outputLength, (err, derivedKey) => {
      if (err) reject(new TelestackError('HKDF derivation failed', TelestackErrorCode.KEY_DERIVATION_FAILED, err));
      else resolve(Buffer.from(derivedKey));
    });
  });
}

export function hmacSha256(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac('sha256', key).update(data).digest();
}

export function encryptAES256GCM(
  key: Buffer,
  plaintext: Buffer,
  aad?: Buffer
): { ciphertext: Buffer; iv: Buffer; tag: Buffer } {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, iv, tag };
}

export function decryptAES256GCM(
  key: Buffer,
  ciphertext: Buffer,
  iv: Buffer,
  tag: Buffer,
  aad?: Buffer
): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function generateKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { publicKey: Buffer.from(publicKey), privateKey: Buffer.from(privateKey) };
}

export function diffieHellman(privateKeyDer: Buffer, publicKeyDer: Buffer): Buffer {
  const privKey = crypto.createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
  const pubKey = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
  return crypto.diffieHellman({ privateKey: privKey, publicKey: pubKey });
}

export async function x3dhSenderKeyAgreement(
  senderIdentityKeyPair: { publicKey: Buffer; privateKey: Buffer },
  senderEphemeralKeyPair: { publicKey: Buffer; privateKey: Buffer },
  recipientIdentityPublicKey: Buffer,
  recipientSignedPreKeyPublicKey: Buffer,
  recipientOneTimePreKeyPublicKey?: Buffer
): Promise<Buffer> {
  // DH1 = DH(IKa, SPKb)
  const dh1 = diffieHellman(senderIdentityKeyPair.privateKey, recipientSignedPreKeyPublicKey);
  // DH2 = DH(EKa, IKb)
  const dh2 = diffieHellman(senderEphemeralKeyPair.privateKey, recipientIdentityPublicKey);
  // DH3 = DH(EKa, SPKb)
  const dh3 = diffieHellman(senderEphemeralKeyPair.privateKey, recipientSignedPreKeyPublicKey);

  let dhInput = Buffer.concat([dh1, dh2, dh3]);

  if (recipientOneTimePreKeyPublicKey) {
    // DH4 = DH(EKa, OPKb)
    const dh4 = diffieHellman(senderEphemeralKeyPair.privateKey, recipientOneTimePreKeyPublicKey);
    dhInput = Buffer.concat([dhInput, dh4]);
  }

  const salt = Buffer.alloc(32, 0);
  const info = Buffer.from('TelestackSEC X3DH', 'utf8');
  return hkdf(dhInput, salt, info, 32);
}

export async function x3dhReceiverKeyAgreement(
  recipientIdentityKeyPair: { publicKey: Buffer; privateKey: Buffer },
  recipientSignedPreKeyPair: { publicKey: Buffer; privateKey: Buffer },
  senderIdentityPublicKey: Buffer,
  senderEphemeralPublicKey: Buffer,
  recipientOneTimePreKeyPair?: { publicKey: Buffer; privateKey: Buffer }
): Promise<Buffer> {
  // DH1 = DH(SPKb, IKa)
  const dh1 = diffieHellman(recipientSignedPreKeyPair.privateKey, senderIdentityPublicKey);
  // DH2 = DH(IKb, EKa)
  const dh2 = diffieHellman(recipientIdentityKeyPair.privateKey, senderEphemeralPublicKey);
  // DH3 = DH(SPKb, EKa)
  const dh3 = diffieHellman(recipientSignedPreKeyPair.privateKey, senderEphemeralPublicKey);

  let dhInput = Buffer.concat([dh1, dh2, dh3]);

  if (recipientOneTimePreKeyPair) {
    // DH4 = DH(OPKb, EKa)
    const dh4 = diffieHellman(recipientOneTimePreKeyPair.privateKey, senderEphemeralPublicKey);
    dhInput = Buffer.concat([dhInput, dh4]);
  }

  const salt = Buffer.alloc(32, 0);
  const info = Buffer.from('TelestackSEC X3DH', 'utf8');
  return hkdf(dhInput, salt, info, 32);
}

export interface RatchetState {
  rootKey: Buffer;
  chainKey: Buffer;
  sendCount: number;
  receiveCount: number;
  skippedKeys: Map<number, Buffer>;
}

export async function ratchetSend(state: RatchetState): Promise<{ messageKey: Buffer; newState: RatchetState }> {
  const messageKey = hmacSha256(state.chainKey, Buffer.from([0x01]));
  const nextChainKey = hmacSha256(state.chainKey, Buffer.from([0x02]));

  return {
    messageKey,
    newState: {
      ...state,
      chainKey: nextChainKey,
      sendCount: state.sendCount + 1,
    },
  };
}

export async function ratchetReceive(
  state: RatchetState,
  messageCounter: number
): Promise<{ messageKey: Buffer; newState: RatchetState }> {
  // Check for skipped key
  if (state.skippedKeys.has(messageCounter)) {
    const messageKey = state.skippedKeys.get(messageCounter)!;
    const newSkipped = new Map(state.skippedKeys);
    newSkipped.delete(messageCounter);
    return {
      messageKey,
      newState: { ...state, skippedKeys: newSkipped },
    };
  }

  // Check for gaps (out-of-order messages)
  if (messageCounter > state.receiveCount) {
    const gap = messageCounter - state.receiveCount;
    if (gap > MAX_SKIP) {
      throw new TelestackError(
        `Message gap ${gap} exceeds MAX_SKIP limit ${MAX_SKIP}`,
        TelestackErrorCode.MAX_SKIP_EXCEEDED
      );
    }

    // Store skipped keys
    let currentState = { ...state, skippedKeys: new Map(state.skippedKeys) };
    while (currentState.receiveCount < messageCounter) {
      const skippedKey = hmacSha256(currentState.chainKey, Buffer.from([0x01]));
      currentState.skippedKeys.set(currentState.receiveCount, skippedKey);
      currentState.chainKey = hmacSha256(currentState.chainKey, Buffer.from([0x02]));
      currentState.receiveCount++;
    }

    const messageKey = hmacSha256(currentState.chainKey, Buffer.from([0x01]));
    currentState.chainKey = hmacSha256(currentState.chainKey, Buffer.from([0x02]));
    currentState.receiveCount++;

    return { messageKey, newState: currentState };
  }

  if (messageCounter < state.receiveCount) {
    throw new TelestackError('Replay attack detected: message counter too low', TelestackErrorCode.REPLAY_DETECTED);
  }

  const messageKey = hmacSha256(state.chainKey, Buffer.from([0x01]));
  const nextChainKey = hmacSha256(state.chainKey, Buffer.from([0x02]));

  return {
    messageKey,
    newState: {
      ...state,
      chainKey: nextChainKey,
      receiveCount: state.receiveCount + 1,
    },
  };
}

export function encryptPrivateKey(privateKey: Buffer, masterKey: string): string {
  const keyBuffer = Buffer.from(masterKey.padEnd(32, '0').slice(0, 32), 'utf8');
  const { ciphertext, iv, tag } = encryptAES256GCM(keyBuffer, privateKey);
  return JSON.stringify({
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
  });
}

export function decryptPrivateKey(encrypted: string, masterKey: string): Buffer {
  const { ciphertext, iv, tag } = JSON.parse(encrypted);
  const keyBuffer = Buffer.from(masterKey.padEnd(32, '0').slice(0, 32), 'utf8');
  return decryptAES256GCM(
    keyBuffer,
    Buffer.from(ciphertext, 'base64'),
    Buffer.from(iv, 'base64'),
    Buffer.from(tag, 'base64')
  );
}

export async function deriveSessionKeys(sharedSecret: Buffer): Promise<{ rootKey: Buffer; chainKey: Buffer }> {
  const salt = Buffer.alloc(32, 0);
  const rootKeyInfo = Buffer.from('TelestackSEC RootKey', 'utf8');
  const chainKeyInfo = Buffer.from('TelestackSEC ChainKey', 'utf8');

  const rootKey = await hkdf(sharedSecret, salt, rootKeyInfo, 32);
  const chainKey = await hkdf(sharedSecret, salt, chainKeyInfo, 32);

  return { rootKey, chainKey };
}
