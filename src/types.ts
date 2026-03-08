export interface TelestackSECConfig {
  databaseUrl: string;
  masterKey?: string;
  masterKeyVersion?: string;
  previousMasterKeys?: Record<string, string>;
  maxPrekeys?: number;
  prekeysThreshold?: number;
  messageHistoryEnabled?: boolean;
  sessionExpiryDays?: number | null;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

export interface UserInfo {
  userId: string;
  email: string;
  createdAt: Date;
}

export interface EncryptOptions {
  from: string;
  to: string;
  message: string;
}

export interface EncryptResult {
  ciphertext: string;
  sessionId: string;
  messageId: string;
}

export interface DecryptOptions {
  to: string;
  ciphertext: string;
  sessionId: string;
}

export interface DecryptResult {
  message: string;
  from: string;
  messageId: string;
}

export interface SessionStatus {
  sessionId: string;
  userId: string;
  peerId: string;
  sendCount: number;
  receiveCount: number;
  createdAt: Date;
  updatedAt: Date;
  expiresAt: Date | null;
}

export interface DeviceRegistration {
  userId: string;
  name: string;
  identityPublicKey: string;
  registrationId: number;
  isPrimary?: boolean;
}

export interface DeviceInfo {
  deviceId: string;
  userId: string;
  name: string;
  identityPublicKey: string;
  registrationId: number;
  isPrimary: boolean;
  createdAt: Date;
}

export interface PreKeyBundleUpload {
  deviceId: string;
  signedPreKey: {
    keyId: number;
    publicKey: string;
    signature: string;
  };
  oneTimePreKeys: Array<{
    keyId: number;
    publicKey: string;
  }>;
}

export interface PreKeyBundle {
  deviceId: string;
  identityPublicKey: string;
  signedPreKey: {
    keyId: number;
    publicKey: string;
    signature: string;
  };
  oneTimePreKey?: {
    keyId: number;
    publicKey: string;
  };
}

export interface EnvelopeSend {
  senderUserId: string;
  senderDeviceId: string;
  recipientUserId: string;
  recipientDeviceId: string;
  ciphertext: string;
  envelopeType?: string;
  ttlSeconds?: number;
}

export interface EnvelopeInfo {
  envelopeId: string;
  senderUserId: string;
  senderDeviceId: string;
  ciphertext: string;
  envelopeType: string;
  createdAt: Date;
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  database: boolean;
  timestamp: Date;
}

export interface RotationResult {
  userId: string;
  newPrekeysGenerated: number;
  oldPrekeysRetained: number;
  timestamp: Date;
}

export interface CleanupResult {
  userId: string;
  deletedCount: number;
  timestamp: Date;
}

export interface DiagnosticsResult {
  totalUsers: number;
  totalSessions: number;
  totalMessages: number;
  totalPrekeys: number;
  totalDevices: number;
  timestamp: Date;
}

export enum TelestackErrorCode {
  USER_NOT_FOUND = 'USER_NOT_FOUND',
  USER_ALREADY_EXISTS = 'USER_ALREADY_EXISTS',
  SESSION_NOT_FOUND = 'SESSION_NOT_FOUND',
  DEVICE_NOT_FOUND = 'DEVICE_NOT_FOUND',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  INVALID_CONFIG = 'INVALID_CONFIG',
  NOT_INITIALIZED = 'NOT_INITIALIZED',
  PREKEY_EXHAUSTED = 'PREKEY_EXHAUSTED',
  REPLAY_DETECTED = 'REPLAY_DETECTED',
  MAX_SKIP_EXCEEDED = 'MAX_SKIP_EXCEEDED',
  KEY_DERIVATION_FAILED = 'KEY_DERIVATION_FAILED',
}

export class TelestackError extends Error {
  constructor(
    message: string,
    public readonly code: TelestackErrorCode,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'TelestackError';
  }
}
