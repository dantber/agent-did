/**
 * In-memory key storage (for testing only)
 */
import { KeyPair, sign } from '../crypto';
import { KeyStorage } from './interface';

export class MemoryKeyStorage implements KeyStorage {
  private keys: Map<string, KeyPair> = new Map();

  async storeKey(id: string, keyPair: KeyPair): Promise<void> {
    this.keys.set(id, keyPair);
  }

  async getKey(id: string): Promise<KeyPair> {
    const keyPair = this.keys.get(id);
    if (!keyPair) {
      throw new Error(`Key not found: ${id}`);
    }
    return keyPair;
  }

  async hasKey(id: string): Promise<boolean> {
    return this.keys.has(id);
  }

  async deleteKey(id: string): Promise<void> {
    this.keys.delete(id);
  }

  async listKeys(): Promise<string[]> {
    return Array.from(this.keys.keys());
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    const keyPair = await this.getKey(id);
    return sign(data, keyPair.privateKey, keyPair.publicKey);
  }

  /**
   * Clear all keys (for testing)
   */
  clear(): void {
    this.keys.clear();
  }
}
