import { TelestackSEC } from './index';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { execSync } from 'child_process';

const TEST_MASTER_KEY = 'test-master-key-32chars-abcdefgh';

let tmpDir: string;
let dbPath: string;
let sdk: TelestackSEC;

function createTestSdk(dbUrl: string) {
  return new TelestackSEC({
    databaseUrl: dbUrl,
    masterKey: TEST_MASTER_KEY,
    maxPrekeys: 5,
    logLevel: 'error',
    messageHistoryEnabled: true,
  });
}

describe('TelestackSEC SDK', () => {
  beforeAll(async () => {
    // Create a temporary directory and SQLite database
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telestack-test-'));
    dbPath = path.join(tmpDir, 'test.db');
    const dbUrl = `file:${dbPath}`;

    // Push schema to the SQLite database before initializing the SDK
    execSync('npx prisma db push --skip-generate --accept-data-loss', {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_URL: dbUrl },
      stdio: 'pipe',
    });

    sdk = createTestSdk(dbUrl);
    await sdk.initialize();
  }, 60000);

  afterAll(async () => {
    await sdk.disconnect();
    try {
      fs.rmSync(tmpDir, { recursive: true });
    } catch {
      // best-effort cleanup
    }
  });

  describe('User management', () => {
    it('registers a user', async () => {
      const user = await sdk.user.register('test@example.com');
      expect(user.userId).toBeDefined();
      expect(user.email).toBe('test@example.com');
    });

    it('throws on duplicate email', async () => {
      await expect(sdk.user.register('test@example.com')).rejects.toThrow();
    });

    it('gets user info', async () => {
      const created = await sdk.user.register('get@example.com');
      const fetched = await sdk.user.get(created.userId);
      expect(fetched.userId).toBe(created.userId);
    });

    it('gets public key', async () => {
      const created = await sdk.user.register('key@example.com');
      const publicKey = await sdk.user.getPublicKey(created.userId);
      expect(publicKey).toBeDefined();
      expect(publicKey.length).toBeGreaterThan(0);
    });

    it('deletes a user', async () => {
      const created = await sdk.user.register('delete@example.com');
      await sdk.user.delete(created.userId);
      await expect(sdk.user.get(created.userId)).rejects.toThrow();
    });
  });

  describe('Encrypt and Decrypt', () => {
    let alice: { userId: string; email: string; createdAt: Date };
    let bob: { userId: string; email: string; createdAt: Date };

    beforeAll(async () => {
      alice = await sdk.user.register('alice@example.com');
      bob = await sdk.user.register('bob@example.com');
    });

    it('encrypts a message', async () => {
      const result = await sdk.encrypt({
        from: alice.userId,
        to: bob.userId,
        message: 'Hello Bob!',
      });
      expect(result.ciphertext).toBeDefined();
      expect(result.sessionId).toBeDefined();
    });

    it('decrypts a message', async () => {
      const encrypted = await sdk.encrypt({
        from: alice.userId,
        to: bob.userId,
        message: 'Hello again, Bob!',
      });

      const decrypted = await sdk.decrypt({
        to: bob.userId,
        ciphertext: encrypted.ciphertext,
        sessionId: encrypted.sessionId,
      });

      expect(decrypted.message).toBe('Hello again, Bob!');
    });

    it('encrypts and decrypts multiple messages in order', async () => {
      const messages = ['First', 'Second', 'Third'];
      const encrypted = [];

      for (const msg of messages) {
        encrypted.push(await sdk.encrypt({ from: alice.userId, to: bob.userId, message: msg }));
      }

      for (let i = 0; i < messages.length; i++) {
        const decrypted = await sdk.decrypt({
          to: bob.userId,
          ciphertext: encrypted[i].ciphertext,
          sessionId: encrypted[i].sessionId,
        });
        expect(decrypted.message).toBe(messages[i]);
      }
    });
  });

  describe('Session management', () => {
    let user1: { userId: string };
    let user2: { userId: string };

    beforeAll(async () => {
      user1 = await sdk.user.register('session1@example.com');
      user2 = await sdk.user.register('session2@example.com');
      // Establish a session by sending a message
      await sdk.encrypt({ from: user1.userId, to: user2.userId, message: 'test' });
    });

    it('gets session status', async () => {
      const status = await sdk.session.getStatus(user1.userId, user2.userId);
      expect(status.sessionId).toBeDefined();
    });

    it('lists sessions', async () => {
      const sessions = await sdk.session.list(user1.userId);
      expect(sessions.length).toBeGreaterThan(0);
    });

    it('resets a session', async () => {
      await sdk.session.reset(user1.userId, user2.userId);
      await expect(sdk.session.getStatus(user1.userId, user2.userId)).rejects.toThrow();
    });
  });

  describe('Admin operations', () => {
    it('returns health status', async () => {
      const health = await sdk.admin.health();
      expect(health.status).toBe('healthy');
      expect(health.database).toBe(true);
    });

    it('returns diagnostics', async () => {
      const diag = await sdk.admin.getDiagnostics();
      expect(typeof diag.totalUsers).toBe('number');
      expect(typeof diag.totalSessions).toBe('number');
    });
  });
});
