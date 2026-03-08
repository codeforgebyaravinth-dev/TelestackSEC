import { PrismaClient } from '@prisma/client';
import { Logger } from '../logger';
import { TelestackError, TelestackErrorCode, UserInfo } from '../types';
import { generateKeyPair, encryptPrivateKey, hmacSha256 } from '../crypto';

export class UserService {
  constructor(
    private prisma: PrismaClient,
    private logger: Logger,
    private masterKey: string,
    private masterKeyVersion: string,
    private maxPrekeys: number
  ) {}

  async register(email: string): Promise<UserInfo> {
    this.logger.info('Registering user', { email });

    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new TelestackError(`User with email ${email} already exists`, TelestackErrorCode.USER_ALREADY_EXISTS);
    }

    // Generate identity key pair
    const identityKeyPair = generateKeyPair();
    const encryptedPrivateKey = encryptPrivateKey(identityKeyPair.privateKey, this.masterKey);

    // Generate prekeys
    const prekeys = Array.from({ length: this.maxPrekeys }, (_, i) => {
      const pair = generateKeyPair();
      return {
        keyId: i + 1,
        publicKey: pair.publicKey.toString('base64'),
        encryptedPrivateKey: encryptPrivateKey(pair.privateKey, this.masterKey),
      };
    });

    // Generate signed prekey
    const signedPreKeyPair = generateKeyPair();
    const signedPreKeyEncrypted = encryptPrivateKey(signedPreKeyPair.privateKey, this.masterKey);

    const user = await this.prisma.$transaction(async (tx) => {
      const newUser = await tx.user.create({
        data: { email },
      });

      await tx.identityKey.create({
        data: {
          userId: newUser.id,
          publicKey: identityKeyPair.publicKey.toString('base64'),
          encryptedPrivateKey,
          keyVersion: this.masterKeyVersion,
        },
      });

      await tx.preKey.createMany({
        data: prekeys.map((pk) => ({ userId: newUser.id, ...pk })),
      });

      await tx.signedPreKey.create({
        data: {
          userId: newUser.id,
          keyId: 1,
          publicKey: signedPreKeyPair.publicKey.toString('base64'),
          signature: this.signPreKey(signedPreKeyPair.publicKey, identityKeyPair.privateKey),
          encryptedPrivateKey: signedPreKeyEncrypted,
        },
      });

      return newUser;
    });

    this.logger.info('User registered', { userId: user.id });
    return { userId: user.id, email: user.email, createdAt: user.createdAt };
  }

  private signPreKey(preKeyPublic: Buffer, identityPrivate: Buffer): string {
    // Use HMAC as a simplified signature (in production, use Ed25519)
    return hmacSha256(identityPrivate, preKeyPublic).toString('base64');
  }

  async get(userId: string): Promise<UserInfo> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new TelestackError(`User ${userId} not found`, TelestackErrorCode.USER_NOT_FOUND);
    }
    return { userId: user.id, email: user.email, createdAt: user.createdAt };
  }

  async getPublicKey(userId: string): Promise<string> {
    const identityKey = await this.prisma.identityKey.findUnique({ where: { userId } });
    if (!identityKey) {
      throw new TelestackError(`Public key for user ${userId} not found`, TelestackErrorCode.USER_NOT_FOUND);
    }
    return identityKey.publicKey;
  }

  async delete(userId: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new TelestackError(`User ${userId} not found`, TelestackErrorCode.USER_NOT_FOUND);
    }
    await this.prisma.user.delete({ where: { id: userId } });
    this.logger.info('User deleted', { userId });
  }
}
