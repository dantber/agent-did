import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Keystore } from '../src/keystore';
import { generateKeyPair, KeyPair } from '../src/crypto';

describe('Keystore', () => {
  let tempDir: string;
  let keystore: Keystore;
  const passphrase = 'test-passphrase-with-16-chars-minimum';

  beforeEach(async () => {
    tempDir = path.join(os.tmpdir(), `agent-did-test-${Date.now()}`);
    keystore = new Keystore(tempDir, passphrase, true); // Skip validation for tests
    await keystore.init();
  });

  afterEach(async () => {
    try {
      await fs.promises.rm(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Initialization', () => {
    it('should create keystore directories', async () => {
      expect(await fs.promises.access(tempDir)).toBeUndefined();
      expect(await fs.promises.access(path.join(tempDir, 'keys'))).toBeUndefined();
      expect(await fs.promises.access(path.join(tempDir, 'credentials'))).toBeUndefined();
    });

    it('should create identities.json', async () => {
      const indexPath = path.join(tempDir, 'identities.json');
      const content = await fs.promises.readFile(indexPath, 'utf-8');
      const index = JSON.parse(content);
      expect(index.identities).toEqual([]);
    });
  });

  describe('Storing and retrieving identities', () => {
    it('should store and retrieve an identity', async () => {
      const keyPair = await generateKeyPair();
      const did = `did:key:z6Mk${Buffer.from(keyPair.publicKey).toString('hex').slice(0, 40)}`;

      const metadata = {
        did,
        type: 'owner' as const,
        name: 'Test Owner',
        createdAt: new Date().toISOString(),
      };

      await keystore.storeIdentity(metadata, keyPair);

      const retrieved = await keystore.getIdentity(did);
      expect(retrieved).toEqual(metadata);

      const retrievedPrivateKey = await keystore.getPrivateKey(did);
      expect(Buffer.from(retrievedPrivateKey).toString('hex')).toBe(
        Buffer.from(keyPair.privateKey).toString('hex')
      );
    });

    it('should list all identities', async () => {
      const keyPair1 = await generateKeyPair();
      const keyPair2 = await generateKeyPair();

      await keystore.storeIdentity(
        {
          did: 'did:key:test1',
          type: 'owner',
          name: 'Owner 1',
          createdAt: new Date().toISOString(),
        },
        keyPair1
      );

      await keystore.storeIdentity(
        {
          did: 'did:key:test2',
          type: 'agent',
          name: 'Agent 1',
          ownerDid: 'did:key:test1',
          createdAt: new Date().toISOString(),
        },
        keyPair2
      );

      const identities = await keystore.listIdentities();
      expect(identities).toHaveLength(2);
      expect(identities.map((i) => i.name)).toContain('Owner 1');
      expect(identities.map((i) => i.name)).toContain('Agent 1');
    });

    it('should update existing identity', async () => {
      const keyPair = await generateKeyPair();
      const did = 'did:key:update-test';

      await keystore.storeIdentity(
        {
          did,
          type: 'owner',
          name: 'Original Name',
          createdAt: new Date().toISOString(),
        },
        keyPair
      );

      await keystore.storeIdentity(
        {
          did,
          type: 'owner',
          name: 'Updated Name',
          createdAt: new Date().toISOString(),
        },
        keyPair
      );

      const identities = await keystore.listIdentities();
      expect(identities).toHaveLength(1);
      expect(identities[0].name).toBe('Updated Name');
    });
  });

  describe('Deleting identities', () => {
    it('should delete an identity and its key file', async () => {
      const keyPair = await generateKeyPair();
      const did = 'did:key:delete-test';

      await keystore.storeIdentity(
        {
          did,
          type: 'owner',
          name: 'Delete Me',
          createdAt: new Date().toISOString(),
        },
        keyPair
      );

      const deleted = await keystore.deleteIdentity(did);
      expect(deleted).toBe(true);

      const retrieved = await keystore.getIdentity(did);
      expect(retrieved).toBeUndefined();
    });
  });

  describe('Encryption', () => {
    it('should encrypt private keys', async () => {
      const keyPair = await generateKeyPair();
      const did = 'did:key:encrypt-test';

      await keystore.storeIdentity(
        {
          did,
          type: 'owner',
          name: 'Test',
          createdAt: new Date().toISOString(),
        },
        keyPair
      );

      // Read the encrypted file directly
      const keyPath = path.join(tempDir, 'keys', `${did.replace(/[^a-zA-Z0-9]/g, '_')}.json`);
      const encryptedData = JSON.parse(await fs.promises.readFile(keyPath, 'utf-8'));

      expect(encryptedData.encryptedPrivateKey).toBeDefined();
      expect(encryptedData.iv).toBeDefined();
      expect(encryptedData.authTag).toBeDefined();
      expect(encryptedData.salt).toBeDefined();
      expect(encryptedData.kdf).toBeDefined();
      expect(encryptedData.cipher).toBeDefined();

      // Encrypted data should not be raw private key
      expect(encryptedData.encryptedPrivateKey).not.toBe(Buffer.from(keyPair.privateKey).toString('hex'));
    });

    it('should fail decryption with wrong passphrase', async () => {
      const keyPair = await generateKeyPair();
      const did = 'did:key:wrong-pass-test';

      await keystore.storeIdentity(
        {
          did,
          type: 'owner',
          name: 'Test',
          createdAt: new Date().toISOString(),
        },
        keyPair
      );

      // Try to decrypt with wrong passphrase
      const wrongKeystore = new Keystore(tempDir, 'wrong-passphrase-16chars', true); // Skip validation for test

      await expect(wrongKeystore.getPrivateKey(did)).rejects.toThrow('Authentication failed');
    });

    it('should store keys unencrypted when encryption is disabled', async () => {
      const unencryptedKeystore = new Keystore(tempDir, null, true); // null passphrase = no encryption
      await unencryptedKeystore.init();

      const keyPair = await generateKeyPair();
      const did = 'did:key:unencrypted-test';

      await unencryptedKeystore.storeIdentity(
        {
          did,
          type: 'owner',
          name: 'Unencrypted',
          createdAt: new Date().toISOString(),
        },
        keyPair
      );

      // Read the file directly
      const keyPath = path.join(tempDir, 'keys', `${did.replace(/[^a-zA-Z0-9]/g, '_')}.json`);
      const storedData = JSON.parse(await fs.promises.readFile(keyPath, 'utf-8'));

      // Should NOT have encryption metadata
      expect(storedData.kdf).toBeUndefined();
      expect(storedData.cipher).toBeUndefined();
      expect(storedData.iv).toBe('');
      expect(storedData.authTag).toBe('');
      expect(storedData.salt).toBe('');

      // Private key should be stored as plaintext hex
      expect(storedData.encryptedPrivateKey).toBe(Buffer.from(keyPair.privateKey).toString('hex'));
    });

    it('should retrieve unencrypted keys', async () => {
      const unencryptedKeystore = new Keystore(tempDir, null, true);
      await unencryptedKeystore.init();

      const keyPair = await generateKeyPair();
      const did = 'did:key:retrieve-unencrypted';

      await unencryptedKeystore.storeIdentity(
        {
          did,
          type: 'owner',
          name: 'Test',
          createdAt: new Date().toISOString(),
        },
        keyPair
      );

      const retrievedPrivateKey = await unencryptedKeystore.getPrivateKey(did);
      expect(Buffer.from(retrievedPrivateKey).toString('hex')).toBe(
        Buffer.from(keyPair.privateKey).toString('hex')
      );
    });

    it('should support mixed encrypted and unencrypted keys', async () => {
      // Store an encrypted key
      const encryptedKeyPair = await generateKeyPair();
      const encryptedDid = 'did:key:encrypted-mixed';
      await keystore.storeIdentity(
        {
          did: encryptedDid,
          type: 'owner',
          name: 'Encrypted',
          createdAt: new Date().toISOString(),
        },
        encryptedKeyPair
      );

      // Store an unencrypted key
      const unencryptedKeystore = new Keystore(tempDir, null, true);
      const unencryptedKeyPair = await generateKeyPair();
      const unencryptedDid = 'did:key:unencrypted-mixed';
      await unencryptedKeystore.storeIdentity(
        {
          did: unencryptedDid,
          type: 'owner',
          name: 'Unencrypted',
          createdAt: new Date().toISOString(),
        },
        unencryptedKeyPair
      );

      // Both should be retrievable by their respective keystores
      const retrievedEncrypted = await keystore.getPrivateKey(encryptedDid);
      expect(Buffer.from(retrievedEncrypted).toString('hex')).toBe(
        Buffer.from(encryptedKeyPair.privateKey).toString('hex')
      );

      const retrievedUnencrypted = await unencryptedKeystore.getPrivateKey(unencryptedDid);
      expect(Buffer.from(retrievedUnencrypted).toString('hex')).toBe(
        Buffer.from(unencryptedKeyPair.privateKey).toString('hex')
      );

      // List should show both
      const identities = await keystore.listIdentities();
      expect(identities).toHaveLength(2);
      expect(identities.map((i) => i.name)).toContain('Encrypted');
      expect(identities.map((i) => i.name)).toContain('Unencrypted');
    });

    it('should report encryption status', () => {
      const encryptedKeystore = new Keystore(tempDir, passphrase, true);
      const unencryptedKeystore = new Keystore(tempDir, null, true);

      expect(encryptedKeystore.isEncrypted()).toBe(true);
      expect(unencryptedKeystore.isEncrypted()).toBe(false);
    });
  });

  describe('Agent relationships', () => {
    it('should find agents for an owner', async () => {
      const ownerDid = 'did:key:owner';

      await keystore.storeIdentity(
        {
          did: ownerDid,
          type: 'owner',
          name: 'Owner',
          createdAt: new Date().toISOString(),
        },
        await generateKeyPair()
      );

      await keystore.storeIdentity(
        {
          did: 'did:key:agent1',
          type: 'agent',
          name: 'Agent 1',
          ownerDid,
          createdAt: new Date().toISOString(),
        },
        await generateKeyPair()
      );

      await keystore.storeIdentity(
        {
          did: 'did:key:agent2',
          type: 'agent',
          name: 'Agent 2',
          ownerDid,
          createdAt: new Date().toISOString(),
        },
        await generateKeyPair()
      );

      const agents = await keystore.getAgentsForOwner(ownerDid);
      expect(agents).toHaveLength(2);
    });
  });

  describe('Credential storage', () => {
    it('should store and load credentials', async () => {
      const credential = {
        type: ['VerifiableCredential'],
        issuer: 'did:key:issuer',
      };

      await keystore.storeCredential('test-cred', credential);
      const loaded = await keystore.loadCredential('test-cred');

      expect(loaded).toEqual(credential);
    });

    it('should list stored credentials', async () => {
      const credential = { type: ['VerifiableCredential'], issuer: 'did:key:issuer' };
      await keystore.storeCredential('list-cred', credential);

      const list = await keystore.listCredentials();
      const found = list.find((item) => item.id === 'list-cred');
      expect(found).toBeDefined();
      expect(found?.data).toEqual(credential);
    });

    it('should delete a stored credential', async () => {
      const credential = { type: ['VerifiableCredential'], issuer: 'did:key:issuer' };
      await keystore.storeCredential('delete-cred', credential);

      const deleted = await keystore.deleteCredential('delete-cred');
      expect(deleted).toBe(true);

      const deletedAgain = await keystore.deleteCredential('delete-cred');
      expect(deletedAgain).toBe(false);
    });
  });
});
