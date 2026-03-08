import { PrismaClient } from '@prisma/client';
import { Logger } from '../logger';
import {
  TelestackError,
  TelestackErrorCode,
  DeviceInfo,
  DeviceRegistration,
  PreKeyBundle,
  PreKeyBundleUpload,
  EnvelopeSend,
  EnvelopeInfo,
} from '../types';

export class DeviceService {
  constructor(
    private prisma: PrismaClient,
    private logger: Logger
  ) {}

  async register(params: DeviceRegistration): Promise<DeviceInfo> {
    const user = await this.prisma.user.findUnique({ where: { id: params.userId } });
    if (!user) {
      throw new TelestackError(`User ${params.userId} not found`, TelestackErrorCode.USER_NOT_FOUND);
    }

    const device = await this.prisma.device.create({
      data: {
        userId: params.userId,
        name: params.name,
        identityPublicKey: params.identityPublicKey,
        registrationId: params.registrationId,
        isPrimary: params.isPrimary ?? false,
      },
    });

    return {
      deviceId: device.id,
      userId: device.userId,
      name: device.name,
      identityPublicKey: device.identityPublicKey,
      registrationId: device.registrationId,
      isPrimary: device.isPrimary,
      createdAt: device.createdAt,
    };
  }

  async uploadPreKeyBundle(params: PreKeyBundleUpload): Promise<void> {
    const device = await this.prisma.device.findUnique({ where: { id: params.deviceId } });
    if (!device) {
      throw new TelestackError(`Device ${params.deviceId} not found`, TelestackErrorCode.DEVICE_NOT_FOUND);
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.devicePreKey.create({
        data: {
          deviceId: params.deviceId,
          keyId: params.signedPreKey.keyId,
          publicKey: params.signedPreKey.publicKey,
          signature: params.signedPreKey.signature,
          isSigned: true,
        },
      });

      if (params.oneTimePreKeys.length > 0) {
        await tx.devicePreKey.createMany({
          data: params.oneTimePreKeys.map((k) => ({
            deviceId: params.deviceId,
            keyId: k.keyId,
            publicKey: k.publicKey,
            isSigned: false,
          })),
        });
      }
    });
  }

  async getPreKeyBundle(deviceId: string): Promise<PreKeyBundle> {
    const device = await this.prisma.device.findUnique({ where: { id: deviceId } });
    if (!device) {
      throw new TelestackError(`Device ${deviceId} not found`, TelestackErrorCode.DEVICE_NOT_FOUND);
    }

    const signedPreKey = await this.prisma.devicePreKey.findFirst({
      where: { deviceId, isSigned: true, used: false },
      orderBy: { keyId: 'desc' },
    });

    if (!signedPreKey) {
      throw new TelestackError(`No signed prekey for device ${deviceId}`, TelestackErrorCode.PREKEY_EXHAUSTED);
    }

    const oneTimePreKey = await this.prisma.devicePreKey.findFirst({
      where: { deviceId, isSigned: false, used: false },
      orderBy: { keyId: 'asc' },
    });

    if (oneTimePreKey) {
      await this.prisma.devicePreKey.update({
        where: { id: oneTimePreKey.id },
        data: { used: true },
      });
    }

    return {
      deviceId,
      identityPublicKey: device.identityPublicKey,
      signedPreKey: {
        keyId: signedPreKey.keyId,
        publicKey: signedPreKey.publicKey,
        signature: signedPreKey.signature ?? '',
      },
      oneTimePreKey: oneTimePreKey
        ? { keyId: oneTimePreKey.keyId, publicKey: oneTimePreKey.publicKey }
        : undefined,
    };
  }

  async sendEnvelope(params: EnvelopeSend): Promise<string> {
    const senderDevice = await this.prisma.device.findUnique({ where: { id: params.senderDeviceId } });
    if (!senderDevice) {
      throw new TelestackError(`Sender device ${params.senderDeviceId} not found`, TelestackErrorCode.DEVICE_NOT_FOUND);
    }

    const recipientDevice = await this.prisma.device.findUnique({ where: { id: params.recipientDeviceId } });
    if (!recipientDevice) {
      throw new TelestackError(`Recipient device ${params.recipientDeviceId} not found`, TelestackErrorCode.DEVICE_NOT_FOUND);
    }

    const expiresAt = params.ttlSeconds
      ? new Date(Date.now() + params.ttlSeconds * 1000)
      : null;

    const envelope = await this.prisma.deviceEnvelope.create({
      data: {
        senderUserId: params.senderUserId,
        senderDeviceId: params.senderDeviceId,
        recipientUserId: params.recipientUserId,
        recipientDeviceId: params.recipientDeviceId,
        ciphertext: params.ciphertext,
        envelopeType: params.envelopeType ?? 'message',
        expiresAt,
      },
    });

    return envelope.id;
  }

  async fetchPendingEnvelopes(deviceId: string, limit: number = 100): Promise<EnvelopeInfo[]> {
    const now = new Date();
    const envelopes = await this.prisma.deviceEnvelope.findMany({
      where: {
        recipientDeviceId: deviceId,
        delivered: false,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: now } },
        ],
      },
      take: limit,
      orderBy: { createdAt: 'asc' },
    });

    return envelopes.map((e) => ({
      envelopeId: e.id,
      senderUserId: e.senderUserId,
      senderDeviceId: e.senderDeviceId,
      ciphertext: e.ciphertext,
      envelopeType: e.envelopeType,
      createdAt: e.createdAt,
    }));
  }

  async ackEnvelope(deviceId: string, envelopeId: string): Promise<void> {
    const envelope = await this.prisma.deviceEnvelope.findUnique({ where: { id: envelopeId } });
    if (!envelope || envelope.recipientDeviceId !== deviceId) {
      throw new TelestackError(`Envelope ${envelopeId} not found for device ${deviceId}`, TelestackErrorCode.DEVICE_NOT_FOUND);
    }

    await this.prisma.deviceEnvelope.update({
      where: { id: envelopeId },
      data: { delivered: true },
    });
  }
}
