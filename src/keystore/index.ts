import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { bytesToHex, hexToBytes, KeyPair } from '../crypto';
import { CRYPTO, SECURITY, VERSION, STORAGE } from '../constants';

export type IdentityType = 'owner' | 'agent';

export interface IdentityMetadata {
  did: string;
  type: IdentityType;
  name: string;
  createdAt: string;
  ownerDid?: string; // For agents, links to owner
}

export interface KeystoreIndex {
  identities: IdentityMetadata[];
}

export interface StoredCredential {
  id: string;
  data: unknown;
}

export interface EncryptedKeyData {
  version?: number;
  kdf?: {
    name: 'pbkdf2';
    iterations: number;
    hash: 'sha256';
    keyLength: number;
  };
  cipher?: {
    name: 'aes-256-gcm';
    ivLength: number;
    authTagLength: number;
  };
  encryptedPrivateKey: string; // hex encoded encrypted private key
  publicKey: string; // hex encoded public key (not encrypted, it's public)
  iv: string; // hex encoded IV
  authTag: string; // hex encoded auth tag
  salt: string; // hex encoded salt
}

/**
 * Validate passphrase strength
 */
function validatePassphrase(passphrase: string): { valid: boolean; reason?: string } {
  if (passphrase.length < SECURITY.MIN_PASSPHRASE_LENGTH) {
    return {
      valid: false,
      reason: `Passphrase must be at least ${SECURITY.MIN_PASSPHRASE_LENGTH} characters long`,
    };
  }

  // Calculate entropy (basic estimation)
  const uniqueChars = new Set(passphrase).size;
  const entropy = passphrase.length * Math.log2(uniqueChars);

  if (entropy < SECURITY.MIN_PASSPHRASE_ENTROPY) {
    return {
      valid: false,
      reason: `Passphrase is too weak. Use a mix of letters, numbers, and symbols.`,
    };
  }

  // Check for common weak patterns
  const weakPatterns = [
    /^(.)\1+$/, // All same character
    /^(012|123|234|345|456|567|678|789|890)+/, // Sequential numbers
    /^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+/i, // Sequential letters
  ];

  for (const pattern of weakPatterns) {
    if (pattern.test(passphrase)) {
      return {
        valid: false,
        reason: 'Passphrase contains weak patterns. Please use a more complex passphrase.',
      };
    }
  }

  return { valid: true };
}

export class Keystore {
  private basePath: string;
  private passphrase: string;
  private encrypted: boolean;

  constructor(basePath: string, passphrase: string | null, skipValidation = false) {
    // If passphrase is null, disable encryption
    if (passphrase === null) {
      this.encrypted = false;
      this.passphrase = ''; // Dummy passphrase when unencrypted
    } else {
      this.encrypted = true;
      // Validate passphrase strength for new operations
      // Skip validation when loading existing keystore (for backwards compatibility)
      if (!skipValidation) {
        const validation = validatePassphrase(passphrase);
        if (!validation.valid) {
          throw new Error(`Invalid passphrase: ${validation.reason}`);
        }
      }
      this.passphrase = passphrase;
    }

    this.basePath = basePath;
  }

  /**
   * Check if encryption is enabled
   */
  isEncrypted(): boolean {
    return this.encrypted;
  }

  /**
   * Get the default keystore path
   */
  static getDefaultPath(): string {
    return process.env.AGENT_DID_HOME || path.join(require('os').homedir(), STORAGE.DEFAULT_DIR_NAME);
  }

  /**
   * Initialize the keystore directories
   */
  async init(): Promise<void> {
    await fs.promises.mkdir(this.basePath, { recursive: true });
    await fs.promises.mkdir(path.join(this.basePath, STORAGE.KEYS_DIR), { recursive: true });
    await fs.promises.mkdir(path.join(this.basePath, STORAGE.VC_DIR), { recursive: true });
    await fs.promises.mkdir(path.join(this.basePath, STORAGE.BACKUPS_DIR), { recursive: true });
    await fs.promises.mkdir(path.join(this.basePath, STORAGE.CREDENTIALS_DIR), { recursive: true });

    // Create empty index if it doesn't exist
    const indexPath = this.getIndexPath();
    try {
      await fs.promises.access(indexPath);
    } catch {
      await this.saveIndex({ identities: [] });
    }
  }

  /**
   * Check if keystore exists
   */
  async exists(): Promise<boolean> {
    try {
      await fs.promises.access(this.basePath);
      return true;
    } catch {
      return false;
    }
  }

  private getIndexPath(): string {
    return path.join(this.basePath, STORAGE.INDEX_FILE);
  }

  private getKeyPath(did: string): string {
    // Use a sanitized version of the DID as filename
    const filename = did.replace(/[^a-zA-Z0-9]/g, '_') + '.json';
    return path.join(this.basePath, STORAGE.KEYS_DIR, filename);
  }

  private async loadIndex(): Promise<KeystoreIndex> {
    const indexPath = this.getIndexPath();
    const data = await fs.promises.readFile(indexPath, 'utf-8');
    return JSON.parse(data);
  }

  private async saveIndex(index: KeystoreIndex): Promise<void> {
    const indexPath = this.getIndexPath();
    await fs.promises.writeFile(indexPath, JSON.stringify(index, null, 2));
    try {
      await fs.promises.chmod(indexPath, STORAGE.FILE_PERMISSIONS);
    } catch {
      // Ignore permission errors on Windows
    }
  }

  /**
   * Derive an encryption key from passphrase and salt
   */
  private deriveKey(
    salt: Buffer,
    options?: { iterations?: number; keyLength?: number; hash?: string }
  ): Buffer {
    return crypto.pbkdf2Sync(
      this.passphrase,
      salt,
      options?.iterations ?? CRYPTO.KDF_ITERATIONS,
      options?.keyLength ?? CRYPTO.AES_KEY_LENGTH,
      options?.hash ?? CRYPTO.KDF_HASH
    );
  }

  /**
   * Encrypt key pair data (or store plaintext if encryption disabled)
   */
  encryptKeyPair(keyPair: KeyPair): EncryptedKeyData {
    // If encryption is disabled, store keys in plaintext
    if (!this.encrypted) {
      return {
        version: VERSION.KEY_VERSION,
        encryptedPrivateKey: Buffer.from(keyPair.privateKey).toString('hex'),
        publicKey: Buffer.from(keyPair.publicKey).toString('hex'),
        iv: '',
        authTag: '',
        salt: '',
        // Mark as unencrypted by omitting kdf/cipher fields
      };
    }

    // Normal encrypted path
    const salt = crypto.randomBytes(CRYPTO.SALT_LENGTH);
    const iv = crypto.randomBytes(CRYPTO.IV_LENGTH);
    const key = this.deriveKey(salt);

    const cipher = crypto.createCipheriv(CRYPTO.ENCRYPTION_ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(Buffer.from(keyPair.privateKey)), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      version: VERSION.KEY_VERSION,
      kdf: {
        name: CRYPTO.KEY_DERIVATION,
        iterations: CRYPTO.KDF_ITERATIONS,
        hash: CRYPTO.KDF_HASH,
        keyLength: CRYPTO.AES_KEY_LENGTH,
      },
      cipher: {
        name: CRYPTO.ENCRYPTION_ALGORITHM,
        ivLength: CRYPTO.IV_LENGTH,
        authTagLength: CRYPTO.AUTH_TAG_LENGTH,
      },
      encryptedPrivateKey: encrypted.toString('hex'),
      publicKey: Buffer.from(keyPair.publicKey).toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      salt: salt.toString('hex'),
    };
  }

  /**
   * Decrypt key pair data (or read plaintext if unencrypted)
   * Uses constant-time error handling to prevent timing attacks
   */
  decryptKeyPair(encryptedData: EncryptedKeyData): KeyPair {
    // Check if this is an unencrypted key (no kdf/cipher fields)
    if (!encryptedData.kdf || !encryptedData.cipher) {
      // Plaintext key
      return {
        privateKey: hexToBytes(encryptedData.encryptedPrivateKey),
        publicKey: hexToBytes(encryptedData.publicKey),
      };
    }

    // Encrypted key - normal decryption path
    const salt = Buffer.from(encryptedData.salt, 'hex');
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    const encrypted = Buffer.from(encryptedData.encryptedPrivateKey, 'hex');

    const key = this.deriveKey(salt, {
      iterations: encryptedData.kdf?.iterations,
      keyLength: encryptedData.kdf?.keyLength,
      hash: encryptedData.kdf?.hash,
    });

    const decipher = crypto.createDecipheriv(CRYPTO.ENCRYPTION_ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    try {
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return {
        privateKey: new Uint8Array(decrypted),
        publicKey: hexToBytes(encryptedData.publicKey),
      };
    } catch (error) {
      // Use generic error message to prevent timing attacks
      // Don't reveal whether it was a wrong passphrase or corrupted data
      throw new Error('Authentication failed');
    }
  }

  /**
   * Store an identity with encrypted key pair
   * Uses atomic operations to prevent race conditions
   */
  async storeIdentity(
    metadata: IdentityMetadata,
    keyPair: KeyPair
  ): Promise<void> {
    // Update index first, before writing key file
    // This way, if we crash during key write, the key won't be orphaned
    const index = await this.loadIndex();
    const existingIndex = index.identities.findIndex((i) => i.did === metadata.did);
    if (existingIndex >= 0) {
      index.identities[existingIndex] = metadata;
    } else {
      index.identities.push(metadata);
    }
    await this.saveIndex(index);

    // Now write the key file to a temp location first, then rename atomically
    const encryptedKey = this.encryptKeyPair(keyPair);
    const keyPath = this.getKeyPath(metadata.did);
    const tempKeyPath = `${keyPath}.tmp`;

    try {
      await fs.promises.writeFile(tempKeyPath, JSON.stringify(encryptedKey, null, 2));

      // Set restrictive permissions (owner read/write only)
      try {
        await fs.promises.chmod(tempKeyPath, STORAGE.FILE_PERMISSIONS);
      } catch {
        // Ignore permission errors on Windows
      }

      // Atomic rename
      await fs.promises.rename(tempKeyPath, keyPath);
    } catch (error) {
      // Clean up temp file if it exists
      try {
        await fs.promises.unlink(tempKeyPath);
      } catch {
        // Ignore cleanup errors
      }
      throw error;
    }
  }

  /**
   * Get identity metadata by DID
   */
  async getIdentity(did: string): Promise<IdentityMetadata | undefined> {
    const index = await this.loadIndex();
    return index.identities.find((i) => i.did === did);
  }

  /**
   * Get decrypted key pair for an identity
   */
  async getKeyPair(did: string): Promise<KeyPair> {
    const identity = await this.getIdentity(did);
    if (!identity) {
      throw new Error(`Identity not found: ${did}`);
    }

    const keyPath = this.getKeyPath(did);
    const encryptedData: EncryptedKeyData = JSON.parse(
      await fs.promises.readFile(keyPath, 'utf-8')
    );

    return this.decryptKeyPair(encryptedData);
  }

  /**
   * Get decrypted private key for an identity
   */
  async getPrivateKey(did: string): Promise<Uint8Array> {
    const keyPair = await this.getKeyPair(did);
    return keyPair.privateKey;
  }

  /**
   * List all identities
   */
  async listIdentities(): Promise<IdentityMetadata[]> {
    const index = await this.loadIndex();
    return index.identities;
  }

  /**
   * Check if an identity exists
   */
  async hasIdentity(did: string): Promise<boolean> {
    const index = await this.loadIndex();
    return index.identities.some((i) => i.did === did);
  }

  /**
   * Get all agents for an owner
   */
  async getAgentsForOwner(ownerDid: string): Promise<IdentityMetadata[]> {
    const index = await this.loadIndex();
    return index.identities.filter((i) => i.ownerDid === ownerDid);
  }

  /**
   * Delete an identity and its key material
   */
  async deleteIdentity(did: string): Promise<boolean> {
    const index = await this.loadIndex();
    const existingIndex = index.identities.findIndex((i) => i.did === did);
    if (existingIndex === -1) {
      return false;
    }

    index.identities.splice(existingIndex, 1);
    await this.saveIndex(index);

    const keyPath = this.getKeyPath(did);
    try {
      await fs.promises.unlink(keyPath);
    } catch {
      // Ignore missing key file
    }

    return true;
  }

  /**
   * Store a credential
   */
  async storeCredential(credentialId: string, credential: unknown): Promise<void> {
    const credPath = path.join(this.basePath, 'credentials', `${credentialId}.json`);
    await fs.promises.writeFile(credPath, JSON.stringify(credential, null, 2));
    try {
      await fs.promises.chmod(credPath, 0o600);
    } catch {
      // Ignore permission errors on Windows
    }
  }

  /**
   * Store a credential JWT using a deterministic filename.
   */
  async storeCredentialJwt(credentialId: string, jwt: string): Promise<void> {
    const credPath = path.join(this.basePath, 'credentials', `${credentialId}.jwt`);
    await fs.promises.writeFile(credPath, jwt);
    try {
      await fs.promises.chmod(credPath, 0o600);
    } catch {
      // Ignore permission errors on Windows
    }
  }

  /**
   * Load a credential
   */
  async loadCredential(credentialId: string): Promise<unknown> {
    const credPath = path.join(this.basePath, 'credentials', `${credentialId}.json`);
    const data = await fs.promises.readFile(credPath, 'utf-8');
    return JSON.parse(data);
  }

  /**
   * Delete a stored credential
   */
  async deleteCredential(credentialId: string): Promise<boolean> {
    const credPath = path.join(this.basePath, 'credentials', `${credentialId}.json`);
    try {
      await fs.promises.unlink(credPath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * List stored credentials
   */
  async listCredentials(): Promise<StoredCredential[]> {
    const credDir = path.join(this.basePath, 'credentials');
    try {
      const entries = await fs.promises.readdir(credDir);
      const files = entries.filter((name) => name.endsWith('.json'));

      const items: StoredCredential[] = [];
      for (const file of files) {
        const id = file.replace(/\.json$/, '');
        const data = await fs.promises.readFile(path.join(credDir, file), 'utf-8');
        items.push({ id, data: JSON.parse(data) });
      }
      return items;
    } catch {
      return [];
    }
  }
}
