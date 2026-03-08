# 📦 **TelestackSEC - End-to-End Encryption SDK**

[![npm version](https://img.shields.io/npm/v/@telestack/sec.svg)](https://www.npmjs.com/package/@telestack/sec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/@telestack/sec)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/%3C%2F%3E-TypeScript-blue)](https://www.typescriptlang.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## 🔐 **TelestackSEC: Signal-Protocol Compatible E2EE for Node.js**

**Production-ready, TypeScript-first SDK** for adding end-to-end encrypted messaging to your applications. Implements the **Signal Protocol** (X3DH + Symmetric Ratchet) used by WhatsApp, Signal, and other secure messaging platforms.

```typescript
// Simple, intuitive API
const encrypted = await sdk.encrypt({
  from: alice.userId,
  to: bob.userId,
  message: "Hello Bob!"
});
```

---

## ✨ **Features**

### 🔒 **Cryptography**
- **X3DH Key Agreement** - Secure session establishment without pre-shared secrets
- **Symmetric Ratchet (KDF Chain)** - Perfect Forward Secrecy
- **AES-256-GCM** - Authenticated encryption for all messages
- **HKDF (RFC 5869)** - Standard key derivation
- **HMAC Chain Ratcheting** - Unique keys per message

### 📱 **Multi-Device Support**
- Register multiple devices per user
- Device-specific identity keys
- Primary device designation
- Offline message queuing with TTL

### 🛡️ **Security Hardening**
- **AAD Context Binding** - Prevents key misuse across contexts
- **Master Key Versioning** - Zero-downtime key rotation
- **Replay Attack Protection** - Duplicate message detection
- **DoS Protection** - MAX_SKIP limit (2000) prevents memory exhaustion
- **Atomic PreKey Consumption** - Race-condition free

### 🏗️ **Production Ready**
- **TypeScript** - Full type definitions
- **Prisma ORM** - PostgreSQL, MySQL, SQLite support
- **Comprehensive error handling** - Typed errors with codes
- **Health checks & diagnostics** - Production monitoring
- **Structured logging** - Configurable log levels

---

## 📊 **Security Properties**

| Property | Status | Description |
|----------|--------|-------------|
| **Authentication** | ✅ | X3DH with signed prekeys |
| **Confidentiality** | ✅ | AES-256-GCM per message |
| **Integrity** | ✅ | GCM authentication tags |
| **Forward Secrecy** | ✅ | Past messages safe even if keys stolen |
| **Post-Compromise Security** | ❌ | *Not provided* (root key static) |
| **Replay Protection** | ✅ | Duplicate message detection |
| **MITM Protection** | ✅ | Signed prekey verification |
| **Out-of-Order Delivery** | ✅ | Skipped message key storage |

> **⚠️ Important**: This implementation uses a **Symmetric Ratchet** (KDF Chain), not the full Double Ratchet. It provides Forward Secrecy but **does not** provide Post-Compromise Security. See [Security Considerations](#security-considerations) for details.

---

## 🚀 **Quick Start**

### Installation

```bash
npm install @telestack/sec
# or
yarn add @telestack/sec
```

### Environment Setup

```env
# .env
DATABASE_URL="postgresql://user:pass@localhost:5432/telestack_sec"
MASTER_KEY="your-32-character-master-key-for-encryption"
LOG_LEVEL="info"
```

### Basic Usage

```typescript
import { TelestackSEC } from '@telestack/sec';

// Initialize SDK
const sdk = new TelestackSEC({
  databaseUrl: process.env.DATABASE_URL!,
  masterKey: process.env.MASTER_KEY!,
  maxPrekeys: 50,
  logLevel: 'info'
});

await sdk.initialize();

// Register users
const alice = await sdk.user.register('alice@example.com');
const bob = await sdk.user.register('bob@example.com');

// Alice sends encrypted message
const encrypted = await sdk.encrypt({
  from: alice.userId,
  to: bob.userId,
  message: "Hello Bob! This is a secret message."
});

// Bob decrypts the message
const decrypted = await sdk.decrypt({
  to: bob.userId,
  ciphertext: encrypted.ciphertext,
  sessionId: encrypted.sessionId
});

console.log(decrypted.message); // "Hello Bob! This is a secret message."

// Graceful shutdown
await sdk.disconnect();
```

---

## 📚 **API Documentation**

### **Core Methods**

| Method | Description |
|--------|-------------|
| `sdk.encrypt(options)` | Encrypt a message from one user to another |
| `sdk.decrypt(options)` | Decrypt a received message |

### **User Management**

```typescript
// Register a new user
const user = await sdk.user.register('email@example.com');

// Get user info
const info = await sdk.user.get(userId);

// Get user's public key
const publicKey = await sdk.user.getPublicKey(userId);

// Delete user and all data
await sdk.user.delete(userId);
```

### **Session Management**

```typescript
// Check session status
const status = await sdk.session.getStatus(userId1, userId2);

// List all user sessions
const sessions = await sdk.session.list(userId);

// Reset/delete a session
await sdk.session.reset(userId1, userId2);
```

### **Multi-Device Support**

```typescript
// Register a device
const device = await sdk.device.register({
  userId: 'user-id',
  name: "Alice's iPhone",
  identityPublicKey: 'base64-key',
  registrationId: 12345,
  isPrimary: true
});

// Upload prekey bundle
await sdk.device.uploadPreKeyBundle({
  deviceId: device.deviceId,
  signedPreKey: {
    keyId: 1,
    publicKey: 'base64-key',
    signature: 'base64-signature'
  },
  oneTimePreKeys: [
    { keyId: 2, publicKey: 'base64-key' },
    { keyId: 3, publicKey: 'base64-key' }
  ]
});

// Get device prekey bundle (for session establishment)
const bundle = await sdk.device.getPreKeyBundle(device.deviceId);

// Send encrypted envelope (offline delivery)
await sdk.device.sendEnvelope({
  senderUserId: 'alice-id',
  senderDeviceId: 'alice-phone-id',
  recipientUserId: 'bob-id',
  recipientDeviceId: 'bob-phone-id',
  ciphertext: encrypted.ciphertext,
  envelopeType: 'message',
  ttlSeconds: 604800 // 7 days
});

// Fetch pending envelopes
const envelopes = await sdk.device.fetchPendingEnvelopes('bob-phone-id', 100);

// Acknowledge delivery
await sdk.device.ackEnvelope('bob-phone-id', envelopeId);
```

### **Admin Operations**

```typescript
// Health check
const health = await sdk.admin.health();

// Rotate prekeys
const rotation = await sdk.admin.rotatePrekeys(userId, 30); // 30 days retention

// Clean up used prekeys
const cleanup = await sdk.admin.cleanupUsedPrekeys(userId, 30);

// Get diagnostics
const diag = await sdk.admin.getDiagnostics();
```

---

## 🔧 **Configuration Options**

```typescript
interface TelestackSECConfig {
  // Database connection URL (required)
  databaseUrl: string;
  
  // Master key for encrypting private keys (32+ characters)
  masterKey?: string; // Falls back to process.env.MASTER_KEY
  
  // Master key version (for rotation)
  masterKeyVersion?: string; // Default: '1'
  
  // Previous master keys (for decryption during rotation)
  previousMasterKeys?: Record<string, string>;
  
  // Maximum number of prekeys to maintain per user
  maxPrekeys?: number; // Default: 50
  
  // Threshold for auto-rotation (when unused prekeys fall below this)
  prekeysThreshold?: number; // Default: 20
  
  // Whether to store message history
  messageHistoryEnabled?: boolean; // Default: true
  
  // Session expiry in days (null = never expire)
  sessionExpiryDays?: number | null; // Default: null
  
  // Log level
  logLevel?: 'debug' | 'info' | 'warn' | 'error'; // Default: 'info'
}
```

---

## 🗄️ **Database Schema**

The SDK uses Prisma ORM and supports PostgreSQL, MySQL, SQLite, and other databases. Key tables:

- **User** - User accounts and metadata
- **IdentityKey** - Long-term identity keys (encrypted)
- **PreKey** - One-time prekeys for session establishment
- **SignedPreKey** - Authenticated prekeys for MITM protection
- **Session** - Encrypted session states
- **Message** - Encrypted message history (optional)
- **Device** - Multi-device registration
- **DevicePreKey** - Device-specific prekeys
- **DeviceEnvelope** - Offline message queue

[View full schema →](prisma/schema.prisma)

---

## 🛡️ **Security Considerations**

### **What TelestackSEC Provides**

- ✅ **Authentication** - Verified identities via signed prekeys
- ✅ **Confidentiality** - AES-256-GCM encryption
- ✅ **Integrity** - GCM authentication tags
- ✅ **Forward Secrecy** - Past messages safe even if keys stolen
- ✅ **Replay Protection** - Duplicate message detection
- ✅ **MITM Protection** - Signed prekey verification

### **What TelestackSEC Does NOT Provide**

- ❌ **Post-Compromise Security** - If session state is stolen, all future messages are compromised
- ❌ **Deniable Authentication** - Messages are cryptographically attributable
- ❌ **Quantum Resistance** - Not resistant to quantum computing attacks

### **Recommendations**

1. **Short-lived sessions**: Re-establish sessions periodically
2. **Secure database**: Protect session states at rest
3. **Key rotation**: Rotate master keys regularly
4. **Monitor for gaps**: Watch for large message gaps (DoS attempts)

---

## 📋 **Requirements**

- **Node.js** 15.12.0 or higher (for `crypto.hkdf`)
- **Database** PostgreSQL, MySQL, SQLite (via Prisma)

---

## 📈 **Performance**

| Operation | Approximate Time |
|-----------|------------------|
| User Registration | 50-100ms |
| Message Encryption | 5-10ms |
| Message Decryption | 5-10ms |
| Session Establishment | 20-40ms |
| PreKey Generation (50) | 30-50ms |

---

## 🤝 **Contributing**

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting PRs.

- Report bugs via [Issues](https://github.com/telestack/sec/issues)
- Discuss features in [Discussions](https://github.com/telestack/sec/discussions)
- Follow [Semantic Versioning](https://semver.org/)

---

## 📄 **License**

MIT © [Telestack](LICENSE)

---

## 🙏 **Acknowledgments**

- **Signal Protocol** - For the cryptographic design
- **Open Whisper Systems** - For libsignal and reference implementations
- **Prisma** - For the excellent ORM

---

## ⭐ **Support**

If you find this project useful, please consider giving it a ⭐ on GitHub!

---

## 📬 **Contact**

- GitHub: [@telestack](https://github.com/telestack)
- Twitter: [@telestack](https://twitter.com/telestack)
- Email: security@telestack.dev

---

**Built with 🔐 for secure communication** use this 
[![GitHub](https://img.shields.io/badge/GitHub-codeforgebyaravinth--dev-black?style=for-the-badge\&logo=github)](https://github.com/codeforgebyaravinth-dev)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-BuildWithAravinth-blue?style=for-the-badge\&logo=linkedin)](https://www.linkedin.com/in/buildwitharavinth/)
[![X](https://img.shields.io/badge/X-TelestackCloud-black?style=for-the-badge\&logo=twitter)](https://x.com/telestackcloud)

📧 Email: [hello@telestack.dev](mailto:hello@telestack.dev)
