/**
 * File-based key storage (current default implementation)
 */
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { KeyPair, sign, bytesToHex, hexToBytes } from '../crypto';
import { KeyStorage } from './interface';
import { CRYPTO, STORAGE } from '../constants';

interface FileStorageConfig {
  basePath: string;
  passphrase: string;
}

interface EncryptedKeyData {
  version: number;
  kdf: {
    name: string;
    iterations: number;
    hash: string;
    keyLength: number;
  };
  cipher: {
    name: string;
    ivLength: number;
    authTagLength: number;
  };
  encryptedPrivateKey: string;
  publicKey: string;
  iv: string;
  authTag: string;
  salt: string;
}

export class FileKeyStorage implements KeyStorage {
  private basePath: string;
  private passphrase: string;

  constructor(config: FileStorageConfig) {
    this.basePath = config.basePath;
    this.passphrase = config.passphrase;
  }

  private getKeyPath(id: string): string {
    const filename = id.replace(/[^a-zA-Z0-9]/g, '_') + '.json';
    return path.join(this.basePath, STORAGE.KEYS_DIR, filename);
  }

  private deriveKey(salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(
      this.passphrase,
      salt,
      CRYPTO.KDF_ITERATIONS,
      CRYPTO.AES_KEY_LENGTH,
      CRYPTO.KDF_HASH
    );
  }

  private encryptKeyPair(keyPair: KeyPair): EncryptedKeyData {
    const salt = crypto.randomBytes(CRYPTO.SALT_LENGTH);
    const iv = crypto.randomBytes(CRYPTO.IV_LENGTH);
    const key = this.deriveKey(salt);

    const cipher = crypto.createCipheriv(CRYPTO.ENCRYPTION_ALGORITHM, key, iv);
    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(keyPair.privateKey)),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    return {
      version: 1,
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

  private decryptKeyPair(encryptedData: EncryptedKeyData): KeyPair {
    const salt = Buffer.from(encryptedData.salt, 'hex');
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    const encrypted = Buffer.from(encryptedData.encryptedPrivateKey, 'hex');

    const key = this.deriveKey(salt);

    const decipher = crypto.createDecipheriv(CRYPTO.ENCRYPTION_ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    try {
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return {
        privateKey: new Uint8Array(decrypted),
        publicKey: hexToBytes(encryptedData.publicKey),
      };
    } catch (error) {
      throw new Error('Authentication failed');
    }
  }

  async storeKey(id: string, keyPair: KeyPair): Promise<void> {
    const encryptedKey = this.encryptKeyPair(keyPair);
    const keyPath = this.getKeyPath(id);
    const tempKeyPath = `${keyPath}${STORAGE.TEMP_FILE_SUFFIX}`;

    // Ensure directory exists
    await fs.promises.mkdir(path.dirname(keyPath), { recursive: true });

    try {
      await fs.promises.writeFile(tempKeyPath, JSON.stringify(encryptedKey, null, 2));

      try {
        await fs.promises.chmod(tempKeyPath, STORAGE.FILE_PERMISSIONS);
      } catch {
        // Ignore on Windows
      }

      // Atomic rename
      await fs.promises.rename(tempKeyPath, keyPath);
    } catch (error) {
      // Clean up temp file
      try {
        await fs.promises.unlink(tempKeyPath);
      } catch {
        // Ignore
      }
      throw error;
    }
  }

  async getKey(id: string): Promise<KeyPair> {
    const keyPath = this.getKeyPath(id);
    const encryptedData: EncryptedKeyData = JSON.parse(
      await fs.promises.readFile(keyPath, 'utf-8')
    );
    return this.decryptKeyPair(encryptedData);
  }

  async hasKey(id: string): Promise<boolean> {
    const keyPath = this.getKeyPath(id);
    try {
      await fs.promises.access(keyPath);
      return true;
    } catch {
      return false;
    }
  }

  async deleteKey(id: string): Promise<void> {
    const keyPath = this.getKeyPath(id);
    await fs.promises.unlink(keyPath);
  }

  async listKeys(): Promise<string[]> {
    const keysDir = path.join(this.basePath, STORAGE.KEYS_DIR);
    try {
      const files = await fs.promises.readdir(keysDir);
      return files
        .filter((f) => f.endsWith('.json'))
        .map((f) => f.replace(/\.json$/, '').replace(/_/g, ':'));
    } catch {
      return [];
    }
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    const keyPair = await this.getKey(id);
    return sign(data, keyPair.privateKey, keyPair.publicKey);
  }
}
