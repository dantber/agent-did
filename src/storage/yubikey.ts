/**
 * YubiKey hardware key storage implementation (STUB)
 *
 * To complete this implementation:
 * 1. Install YubiKey libraries: npm install @yubico/yubikey-manager
 * 2. Ensure YubiKey is connected via USB
 * 3. Configure PIV (Personal Identity Verification) slots
 * 4. Implement key generation on the YubiKey
 *
 * Benefits:
 * - Private keys never leave the hardware device
 * - Physical presence required for sensitive operations
 * - Tamper-resistant storage
 * - FIPS 140-2 Level 2 certified (YubiKey 5 FIPS)
 *
 * YubiKey PIV Slots:
 * - 9a: PIV Authentication
 * - 9c: Digital Signature
 * - 9d: Key Management
 * - 9e: Card Authentication
 */

import { KeyPair } from '../crypto';
import { KeyStorage } from './interface';

interface YubiKeyConfig {
  slot?: string; // PIV slot (default: '9a')
  pin?: string; // PIN for YubiKey access
  requireTouch?: boolean; // Require physical touch for signing
}

export class YubiKeyStorage implements KeyStorage {
  private config: YubiKeyConfig;
  // private ykman: any; // TODO: Import YubiKey manager

  constructor(config?: YubiKeyConfig) {
    this.config = {
      slot: config?.slot || '9a',
      pin: config?.pin,
      requireTouch: config?.requireTouch !== false,
    };

    // TODO: Initialize YubiKey manager
    // this.ykman = new YubiKeyManager();
    // await this.ykman.connect();

    throw new Error(
      'YubiKey storage is not yet implemented. ' +
        'See src/storage/yubikey.ts for implementation guide.'
    );
  }

  async storeKey(id: string, keyPair: KeyPair): Promise<void> {
    // TODO: Generate key on YubiKey
    // Note: Best practice is to generate the key ON the YubiKey, not import it
    // This ensures the private key never exists in software

    // Example:
    // await this.ykman.generateKey({
    //   slot: this.config.slot,
    //   algorithm: 'ECCP256', // or 'RSA2048'
    //   pin: this.config.pin,
    //   touchPolicy: this.config.requireTouch ? 'ALWAYS' : 'NEVER'
    // });
    //
    // // Store public key separately for retrieval
    // const publicKey = await this.ykman.getPublicKey(this.config.slot);
    // await this.storePublicKeyMetadata(id, publicKey);

    throw new Error('Not implemented');
  }

  async getKey(id: string): Promise<KeyPair> {
    // TODO: Retrieve public key (private key stays on YubiKey)
    // Note: We can only get the public key; private key never leaves the device

    // const publicKey = await this.getPublicKeyMetadata(id);
    // return {
    //   publicKey,
    //   privateKey: new Uint8Array(0) // Not accessible!
    // };

    throw new Error('Not implemented');
  }

  async hasKey(id: string): Promise<boolean> {
    // TODO: Check if key exists in metadata storage
    throw new Error('Not implemented');
  }

  async deleteKey(id: string): Promise<void> {
    // TODO: Delete key from YubiKey slot
    // WARNING: This is destructive and cannot be undone

    // await this.ykman.deleteKey({
    //   slot: this.config.slot,
    //   pin: this.config.pin
    // });

    throw new Error('Not implemented');
  }

  async listKeys(): Promise<string[]> {
    // TODO: List all keys in metadata storage
    throw new Error('Not implemented');
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    // TODO: Sign using YubiKey
    // This is the main operation - signing happens on the hardware

    // If touch is required, prompt user to touch the YubiKey
    // if (this.config.requireTouch) {
    //   console.log('Please touch your YubiKey...');
    // }

    // const signature = await this.ykman.sign({
    //   slot: this.config.slot,
    //   data,
    //   pin: this.config.pin,
    //   algorithm: 'ECDSA-SHA256'
    // });

    // return new Uint8Array(signature);

    throw new Error('Not implemented');
  }

  // TODO: Add helper methods
  // private async storePublicKeyMetadata(id: string, publicKey: Uint8Array): Promise<void> { }
  // private async getPublicKeyMetadata(id: string): Promise<Uint8Array> { }
  // private async verifyPin(): Promise<void> { }
  // private async checkYubiKeyConnected(): Promise<boolean> { }
}

/**
 * Example usage (when implemented):
 *
 * // Initialize YubiKey storage
 * const storage = new YubiKeyStorage({
 *   slot: '9a',
 *   pin: '123456',
 *   requireTouch: true
 * });
 *
 * // Generate key on YubiKey (private key never leaves device)
 * await storage.storeKey('my-did', keyPair);
 *
 * // Sign data (user must touch YubiKey)
 * const signature = await storage.sign('my-did', messageHash);
 */
