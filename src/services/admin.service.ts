import { PrismaClient } from '@prisma/client';
import { Logger } from '../logger';
import { TelestackError, TelestackErrorCode, HealthStatus, RotationResult, CleanupResult, DiagnosticsResult } from '../types';
import { generateKeyPair, encryptPrivateKey } from '../crypto';

export class AdminService {
  constructor(
    private prisma: PrismaClient,
    private logger: Logger,
    private masterKey: string,
    private maxPrekeys: number
  ) {}

  async health(): Promise<HealthStatus> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return { status: 'healthy', database: true, timestamp: new Date() };
    } catch {
      return { status: 'unhealthy', database: false, timestamp: new Date() };
    }
  }

  async rotatePrekeys(userId: string, retentionDays: number = 30): Promise<RotationResult> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new TelestackError(`User ${userId} not found`, TelestackErrorCode.USER_NOT_FOUND);
    }

    const unusedCount = await this.prisma.preKey.count({ where: { userId, used: false } });
    const needed = Math.max(0, this.maxPrekeys - unusedCount);

    if (needed > 0) {
      const existingKeys = await this.prisma.preKey.findMany({
        where: { userId },
        orderBy: { keyId: 'desc' },
        take: 1,
        select: { keyId: true },
      });

      const startKeyId = existingKeys.length > 0 ? existingKeys[0].keyId + 1 : 1;

      const newPrekeys = Array.from({ length: needed }, (_, i) => {
        const pair = generateKeyPair();
        return {
          userId,
          keyId: startKeyId + i,
          publicKey: pair.publicKey.toString('base64'),
          encryptedPrivateKey: encryptPrivateKey(pair.privateKey, this.masterKey),
        };
      });

      await this.prisma.preKey.createMany({ data: newPrekeys });
    }

    const retentionDate = new Date();
    retentionDate.setDate(retentionDate.getDate() - retentionDays);

    const oldUsedCount = await this.prisma.preKey.count({
      where: { userId, used: true, usedAt: { lt: retentionDate } },
    });

    this.logger.info('Prekeys rotated', { userId, generated: needed });

    return {
      userId,
      newPrekeysGenerated: needed,
      oldPrekeysRetained: oldUsedCount,
      timestamp: new Date(),
    };
  }

  async cleanupUsedPrekeys(userId: string, retentionDays: number = 30): Promise<CleanupResult> {
    const retentionDate = new Date();
    retentionDate.setDate(retentionDate.getDate() - retentionDays);

    const result = await this.prisma.preKey.deleteMany({
      where: {
        userId,
        used: true,
        usedAt: { lt: retentionDate },
      },
    });

    this.logger.info('Used prekeys cleaned up', { userId, deleted: result.count });

    return {
      userId,
      deletedCount: result.count,
      timestamp: new Date(),
    };
  }

  async getDiagnostics(): Promise<DiagnosticsResult> {
    const [users, sessions, messages, prekeys, devices] = await Promise.all([
      this.prisma.user.count(),
      this.prisma.session.count(),
      this.prisma.message.count(),
      this.prisma.preKey.count({ where: { used: false } }),
      this.prisma.device.count(),
    ]);

    return {
      totalUsers: users,
      totalSessions: sessions,
      totalMessages: messages,
      totalPrekeys: prekeys,
      totalDevices: devices,
      timestamp: new Date(),
    };
  }
}
