import { PrismaClient } from '@prisma/client';
import { Logger } from './logger';
import { UserService } from './services/user.service';
import { SessionService } from './services/session.service';
import { DeviceService } from './services/device.service';
import { AdminService } from './services/admin.service';
import {
  TelestackSECConfig,
  TelestackError,
  TelestackErrorCode,
  EncryptOptions,
  EncryptResult,
  DecryptOptions,
  DecryptResult,
} from './types';
import {
  generateKeyPair,
  x3dhSenderKeyAgreement,
  x3dhReceiverKeyAgreement,
  deriveSessionKeys,
  ratchetSend,
  ratchetReceive,
  encryptAES256GCM,
  decryptAES256GCM,
  decryptPrivateKey,
  RatchetState,
} from './crypto';

export * from './types';
export { UserService, SessionService, DeviceService, AdminService };

export class TelestackSEC {
  private prisma!: PrismaClient;
  private logger: Logger;
  private initialized = false;

  private masterKey: string;
  private masterKeyVersion: string;
  private maxPrekeys: number;
  private prekeysThreshold: number;
  private messageHistoryEnabled: boolean;
  private sessionExpiryDays: number | null;

  public user!: UserService;
  public session!: SessionService;
  public device!: DeviceService;
  public admin!: AdminService;

  constructor(private config: TelestackSECConfig) {
    this.logger = new Logger(config.logLevel ?? 'info');

    const masterKey = config.masterKey ?? process.env['MASTER_KEY'];
    if (!masterKey) {
      throw new TelestackError('masterKey is required (config or MASTER_KEY env)', TelestackErrorCode.INVALID_CONFIG);
    }

    this.masterKey = masterKey;
    this.masterKeyVersion = config.masterKeyVersion ?? '1';
    this.maxPrekeys = config.maxPrekeys ?? 50;
    this.prekeysThreshold = config.prekeysThreshold ?? 20;
    this.messageHistoryEnabled = config.messageHistoryEnabled ?? true;
    this.sessionExpiryDays = config.sessionExpiryDays ?? null;
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    this.prisma = new PrismaClient({
      datasources: { db: { url: this.config.databaseUrl } },
      log: this.config.logLevel === 'debug' ? ['query'] : [],
    });

    await this.prisma.$connect();

    this.user = new UserService(this.prisma, this.logger, this.masterKey, this.masterKeyVersion, this.maxPrekeys);
    this.session = new SessionService(this.prisma, this.logger);
    this.device = new DeviceService(this.prisma, this.logger);
    this.admin = new AdminService(this.prisma, this.logger, this.masterKey, this.maxPrekeys);

    this.initialized = true;
    this.logger.info('TelestackSEC initialized');
  }

  async disconnect(): Promise<void> {
    if (this.prisma) {
      await this.prisma.$disconnect();
    }
    this.initialized = false;
    this.logger.info('TelestackSEC disconnected');
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new TelestackError('SDK not initialized. Call initialize() first.', TelestackErrorCode.NOT_INITIALIZED);
    }
  }

  async encrypt(options: EncryptOptions): Promise<EncryptResult> {
    this.ensureInitialized();

    const { from: senderId, to: recipientId, message } = options;

    // Get or create session
    let session = await this.prisma.session.findFirst({
      where: { userId: senderId, peerId: recipientId },
    });

    if (!session) {
      session = await this.establishSession(senderId, recipientId);
    }

    // Deserialize ratchet state
    const skippedKeys = new Map<number, Buffer>(
      Object.entries(JSON.parse(session.skippedKeys) as Record<string, string>).map(
        ([k, v]) => [parseInt(k), Buffer.from(v, 'base64')]
      )
    );

    const state: RatchetState = {
      rootKey: Buffer.from(session.rootKey, 'base64'),
      chainKey: Buffer.from(session.chainKey, 'base64'),
      sendCount: session.sendCount,
      receiveCount: session.receiveCount,
      skippedKeys,
    };

    const { messageKey, newState } = await ratchetSend(state);

    // Encrypt message with AAD context binding
    const aad = Buffer.from(JSON.stringify({ sessionId: session.id, counter: state.sendCount }));
    const plaintext = Buffer.from(message, 'utf8');
    const { ciphertext, iv, tag } = encryptAES256GCM(messageKey, plaintext, aad);

    const ciphertextPayload = JSON.stringify({
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      counter: state.sendCount,
    });

    // Update session state
    const updatedSkipped: Record<string, string> = {};
    newState.skippedKeys.forEach((v, k) => { updatedSkipped[k.toString()] = v.toString('base64'); });

    await this.prisma.session.update({
      where: { id: session.id },
      data: {
        chainKey: newState.chainKey.toString('base64'),
        sendCount: newState.sendCount,
        skippedKeys: JSON.stringify(updatedSkipped),
      },
    });

    let messageRecord: { id: string } | null = null;
    if (this.messageHistoryEnabled) {
      messageRecord = await this.prisma.message.create({
        data: {
          sessionId: session.id,
          senderId,
          ciphertext: ciphertextPayload,
          counter: state.sendCount,
        },
      });
    }

    return {
      ciphertext: ciphertextPayload,
      sessionId: session.id,
      messageId: messageRecord?.id ?? `${session.id}-${state.sendCount}`,
    };
  }

  async decrypt(options: DecryptOptions): Promise<DecryptResult> {
    this.ensureInitialized();

    const { to: recipientId, ciphertext: ciphertextPayload, sessionId } = options;

    // The sessionId is the sender's session ID — look it up to identify who sent the message.
    const senderSession = await this.prisma.session.findUnique({ where: { id: sessionId } });
    if (!senderSession) {
      throw new TelestackError(`Session ${sessionId} not found`, TelestackErrorCode.SESSION_NOT_FOUND);
    }

    const senderId = senderSession.userId;

    // The receiver maintains their own independent session record (userId=recipient, peerId=sender).
    const receiverSession = await this.prisma.session.findFirst({
      where: { userId: recipientId, peerId: senderId },
    });

    if (!receiverSession) {
      throw new TelestackError(
        `Receiver session not found for ${recipientId} ← ${senderId}`,
        TelestackErrorCode.SESSION_NOT_FOUND
      );
    }

    const { ciphertext, iv, tag, counter } = JSON.parse(ciphertextPayload) as {
      ciphertext: string;
      iv: string;
      tag: string;
      counter: number;
    };

    const skippedKeys = new Map<number, Buffer>(
      Object.entries(JSON.parse(receiverSession.skippedKeys) as Record<string, string>).map(
        ([k, v]) => [parseInt(k), Buffer.from(v, 'base64')]
      )
    );

    const state: RatchetState = {
      rootKey: Buffer.from(receiverSession.rootKey, 'base64'),
      chainKey: Buffer.from(receiverSession.chainKey, 'base64'),
      sendCount: receiverSession.sendCount,
      receiveCount: receiverSession.receiveCount,
      skippedKeys,
    };

    const { messageKey, newState } = await ratchetReceive(state, counter);

    // AAD must match what was bound during encryption (uses sender's session ID).
    const aad = Buffer.from(JSON.stringify({ sessionId, counter }));

    let plaintext: Buffer;
    try {
      plaintext = decryptAES256GCM(
        messageKey,
        Buffer.from(ciphertext, 'base64'),
        Buffer.from(iv, 'base64'),
        Buffer.from(tag, 'base64'),
        aad
      );
    } catch (err) {
      throw new TelestackError('Decryption failed: invalid message', TelestackErrorCode.DECRYPTION_FAILED, err as Error);
    }

    // Update the receiver's own session state
    const updatedSkipped: Record<string, string> = {};
    newState.skippedKeys.forEach((v, k) => { updatedSkipped[k.toString()] = v.toString('base64'); });

    await this.prisma.session.update({
      where: { id: receiverSession.id },
      data: {
        chainKey: newState.chainKey.toString('base64'),
        receiveCount: newState.receiveCount,
        skippedKeys: JSON.stringify(updatedSkipped),
      },
    });

    let messageId = `${receiverSession.id}-${counter}`;
    if (this.messageHistoryEnabled) {
      const msg = await this.prisma.message.create({
        data: {
          sessionId: receiverSession.id,
          senderId,
          ciphertext: ciphertextPayload,
          counter,
        },
      });
      messageId = msg.id;
    }

    return {
      message: plaintext.toString('utf8'),
      from: senderId,
      messageId,
    };
  }

  private async establishSession(senderId: string, recipientId: string): Promise<{
    id: string; userId: string; peerId: string; rootKey: string; chainKey: string;
    sendCount: number; receiveCount: number; skippedKeys: string;
    createdAt: Date; updatedAt: Date; expiresAt: Date | null;
  }> {
    // Get sender's identity key
    const senderIdentityKeyRecord = await this.prisma.identityKey.findUnique({ where: { userId: senderId } });
    if (!senderIdentityKeyRecord) {
      throw new TelestackError(`Identity key not found for user ${senderId}`, TelestackErrorCode.USER_NOT_FOUND);
    }

    // Get recipient's identity key and signed prekey
    const recipientIdentityKeyRecord = await this.prisma.identityKey.findUnique({ where: { userId: recipientId } });
    if (!recipientIdentityKeyRecord) {
      throw new TelestackError(`Identity key not found for user ${recipientId}`, TelestackErrorCode.USER_NOT_FOUND);
    }

    const recipientSignedPreKey = await this.prisma.signedPreKey.findFirst({
      where: { userId: recipientId, active: true },
      orderBy: { keyId: 'desc' },
    });

    if (!recipientSignedPreKey) {
      throw new TelestackError(`No signed prekey for user ${recipientId}`, TelestackErrorCode.PREKEY_EXHAUSTED);
    }

    // Atomically consume a one-time prekey
    const oneTimePreKey = await this.prisma.$transaction(async (tx) => {
      const pk = await tx.preKey.findFirst({
        where: { userId: recipientId, used: false },
        orderBy: { keyId: 'asc' },
      });
      if (pk) {
        await tx.preKey.update({ where: { id: pk.id }, data: { used: true, usedAt: new Date() } });
      }
      return pk;
    });

    // Decode sender's identity key
    const senderIdentityPublic = Buffer.from(senderIdentityKeyRecord.publicKey, 'base64');
    const senderIdentityPrivate = this.decryptKey(senderIdentityKeyRecord.encryptedPrivateKey, senderIdentityKeyRecord.keyVersion);

    // Generate ephemeral key pair for sender
    const senderEphemeralKeyPair = generateKeyPair();

    // Decode recipient's keys
    const recipientIdentityPublic = Buffer.from(recipientIdentityKeyRecord.publicKey, 'base64');
    const recipientSignedPreKeyPublic = Buffer.from(recipientSignedPreKey.publicKey, 'base64');
    const recipientSignedPreKeyPrivate = this.decryptKey(recipientSignedPreKey.encryptedPrivateKey, '1');

    let oneTimePreKeyPublic: Buffer | undefined;
    let oneTimePreKeyPrivate: Buffer | undefined;
    if (oneTimePreKey) {
      oneTimePreKeyPublic = Buffer.from(oneTimePreKey.publicKey, 'base64');
      oneTimePreKeyPrivate = this.decryptKey(oneTimePreKey.encryptedPrivateKey, '1');
    }

    // Compute shared secret (sender side)
    const sharedSecret = await x3dhSenderKeyAgreement(
      { publicKey: senderIdentityPublic, privateKey: senderIdentityPrivate },
      senderEphemeralKeyPair,
      recipientIdentityPublic,
      recipientSignedPreKeyPublic,
      oneTimePreKeyPublic
    );

    const { rootKey, chainKey } = await deriveSessionKeys(sharedSecret);

    // Verify receiver side produces same shared secret
    const recipientIdentityPrivate = this.decryptKey(recipientIdentityKeyRecord.encryptedPrivateKey, recipientIdentityKeyRecord.keyVersion);
    const verifiedSecret = await x3dhReceiverKeyAgreement(
      { publicKey: recipientIdentityPublic, privateKey: recipientIdentityPrivate },
      { publicKey: recipientSignedPreKeyPublic, privateKey: recipientSignedPreKeyPrivate },
      senderIdentityPublic,
      senderEphemeralKeyPair.publicKey,
      oneTimePreKeyPublic && oneTimePreKeyPrivate
        ? { publicKey: oneTimePreKeyPublic, privateKey: oneTimePreKeyPrivate }
        : undefined
    );

    if (!sharedSecret.equals(verifiedSecret)) {
      throw new TelestackError('Key agreement failed: shared secrets do not match', TelestackErrorCode.KEY_DERIVATION_FAILED);
    }

    const expiresAt = this.sessionExpiryDays
      ? new Date(Date.now() + this.sessionExpiryDays * 86400 * 1000)
      : null;

    // Create both the sender's outbound session and the receiver's inbound session.
    // Each side advances its own chain key independently, ensuring correct key derivation.
    return this.prisma.$transaction(async (tx) => {
      const senderSession = await tx.session.create({
        data: {
          userId: senderId,
          peerId: recipientId,
          rootKey: rootKey.toString('base64'),
          chainKey: chainKey.toString('base64'),
          sendCount: 0,
          receiveCount: 0,
          skippedKeys: '{}',
          expiresAt,
        },
      });

      // Mirror session for the receiver so they maintain their own independent receive chain.
      await tx.session.create({
        data: {
          userId: recipientId,
          peerId: senderId,
          rootKey: rootKey.toString('base64'),
          chainKey: chainKey.toString('base64'),
          sendCount: 0,
          receiveCount: 0,
          skippedKeys: '{}',
          expiresAt,
        },
      });

      return senderSession;
    });
  }

  private decryptKey(encryptedKey: string, version: string): Buffer {
    const keyToUse = version === this.masterKeyVersion
      ? this.masterKey
      : this.config.previousMasterKeys?.[version];

    if (!keyToUse) {
      throw new TelestackError(`Master key version ${version} not found`, TelestackErrorCode.KEY_DERIVATION_FAILED);
    }

    return decryptPrivateKey(encryptedKey, keyToUse);
  }
}
