/**
 * Storage interface abstraction
 * Allows different backends (file, HSM, cloud KMS, etc.)
 */
import { KeyPair } from '../crypto';

export interface KeyStorage {
  /**
   * Store a key pair
   */
  storeKey(id: string, keyPair: KeyPair): Promise<void>;

  /**
   * Retrieve a key pair
   */
  getKey(id: string): Promise<KeyPair>;

  /**
   * Check if a key exists
   */
  hasKey(id: string): Promise<boolean>;

  /**
   * Delete a key
   */
  deleteKey(id: string): Promise<void>;

  /**
   * List all key IDs
   */
  listKeys(): Promise<string[]>;

  /**
   * Sign data with a key (may be done in hardware for HSM)
   */
  sign(id: string, data: Uint8Array): Promise<Uint8Array>;
}

export interface KeyStorageConfig {
  type: 'file' | 'aws-kms' | 'yubikey' | 'memory';
  config?: Record<string, unknown>;
}

/**
 * Factory for creating key storage backends
 */
export class KeyStorageFactory {
  static create(config: KeyStorageConfig): KeyStorage {
    switch (config.type) {
      case 'file':
        // Import dynamically to avoid circular dependencies
        const { FileKeyStorage } = require('./file');
        return new FileKeyStorage(config.config as any);

      case 'aws-kms':
        const { AWSKMSStorage } = require('./aws-kms');
        return new AWSKMSStorage(config.config as any);

      case 'yubikey':
        const { YubiKeyStorage } = require('./yubikey');
        return new YubiKeyStorage(config.config as any);

      case 'memory':
        const { MemoryKeyStorage } = require('./memory');
        return new MemoryKeyStorage();

      default:
        throw new Error(`Unknown storage type: ${config.type}`);
    }
  }
}
