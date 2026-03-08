import { PrismaClient } from '@prisma/client';
import { Logger } from '../logger';
import { TelestackError, TelestackErrorCode, SessionStatus } from '../types';

export class SessionService {
  constructor(
    private prisma: PrismaClient,
    private logger: Logger
  ) {}

  async getStatus(userId1: string, userId2: string): Promise<SessionStatus> {
    const session = await this.prisma.session.findFirst({
      where: {
        OR: [
          { userId: userId1, peerId: userId2 },
          { userId: userId2, peerId: userId1 },
        ],
      },
    });

    if (!session) {
      throw new TelestackError(`Session not found between ${userId1} and ${userId2}`, TelestackErrorCode.SESSION_NOT_FOUND);
    }

    return {
      sessionId: session.id,
      userId: session.userId,
      peerId: session.peerId,
      sendCount: session.sendCount,
      receiveCount: session.receiveCount,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
      expiresAt: session.expiresAt,
    };
  }

  async list(userId: string): Promise<SessionStatus[]> {
    const sessions = await this.prisma.session.findMany({
      where: {
        OR: [{ userId }, { peerId: userId }],
      },
      orderBy: { updatedAt: 'desc' },
    });

    return sessions.map((s) => ({
      sessionId: s.id,
      userId: s.userId,
      peerId: s.peerId,
      sendCount: s.sendCount,
      receiveCount: s.receiveCount,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
      expiresAt: s.expiresAt,
    }));
  }

  async reset(userId1: string, userId2: string): Promise<void> {
    await this.prisma.session.deleteMany({
      where: {
        OR: [
          { userId: userId1, peerId: userId2 },
          { userId: userId2, peerId: userId1 },
        ],
      },
    });
    this.logger.info('Session reset', { userId1, userId2 });
  }
}
