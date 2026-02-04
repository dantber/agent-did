/**
 * W3C Bitstring Status List implementation
 * https://www.w3.org/TR/vc-bitstring-status-list/
 *
 * Supersedes Status List 2021 (https://www.w3.org/TR/2023/WD-vc-status-list-20230427/)
 *
 * Provides a privacy-preserving way to check credential revocation status
 * using compressed bitstrings.
 */
import * as fs from 'fs';
import * as path from 'path';
import { gzipSync, gunzipSync } from 'zlib';

export interface BitstringStatusListCredential {
  '@context': string[];
  type: string[];
  id: string;
  issuer: string;
  validFrom: string;
  credentialSubject: {
    id: string;
    type: 'BitstringStatusList';
    statusPurpose: 'revocation' | 'suspension';
    encodedList: string; // Base64-encoded gzipped bitstring
  };
}

export interface BitstringStatusListEntry {
  id: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string; // Bit position as string
  statusListCredential: string; // URL or ID of status list credential
}

export class BitstringStatusList {
  private bitstring: Uint8Array;
  private purpose: 'revocation' | 'suspension';
  private issuer: string;
  private id: string;

  constructor(
    size: number,
    issuer: string,
    id: string,
    purpose: 'revocation' | 'suspension' = 'revocation'
  ) {
    // Bitstring size in bytes (8 bits per byte)
    this.bitstring = new Uint8Array(Math.ceil(size / 8));
    this.purpose = purpose;
    this.issuer = issuer;
    this.id = id;
  }

  /**
   * Set a bit in the status list (mark as revoked/suspended)
   */
  setBit(index: number): void {
    if (index < 0 || index >= this.bitstring.length * 8) {
      throw new Error(`Index ${index} out of bounds`);
    }

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    this.bitstring[byteIndex] |= 1 << bitIndex;
  }

  /**
   * Clear a bit in the status list (mark as not revoked/suspended)
   */
  clearBit(index: number): void {
    if (index < 0 || index >= this.bitstring.length * 8) {
      throw new Error(`Index ${index} out of bounds`);
    }

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    this.bitstring[byteIndex] &= ~(1 << bitIndex);
  }

  /**
   * Check if a bit is set
   */
  getBit(index: number): boolean {
    if (index < 0 || index >= this.bitstring.length * 8) {
      throw new Error(`Index ${index} out of bounds`);
    }

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    return (this.bitstring[byteIndex] & (1 << bitIndex)) !== 0;
  }

  /**
   * Encode the bitstring as base64-encoded gzipped data
   */
  encode(): string {
    const compressed = gzipSync(this.bitstring);
    return Buffer.from(compressed).toString('base64');
  }

  /**
   * Decode a base64-encoded gzipped bitstring
   */
  static decode(encoded: string): Uint8Array {
    const compressed = Buffer.from(encoded, 'base64');
    const decompressed = gunzipSync(compressed);
    return new Uint8Array(decompressed);
  }

  /**
   * Create a Bitstring Status List Verifiable Credential
   */
  toCredential(): BitstringStatusListCredential {
    return {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/vc-status-list-2021/v1',
      ],
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      id: this.id,
      issuer: this.issuer,
      validFrom: new Date().toISOString(),
      credentialSubject: {
        id: `${this.id}#list`,
        type: 'BitstringStatusList',
        statusPurpose: this.purpose,
        encodedList: this.encode(),
      },
    };
  }

  /**
   * Load from a Bitstring Status List credential
   */
  static fromCredential(credential: BitstringStatusListCredential): BitstringStatusList {
    const bitstring = BitstringStatusList.decode(credential.credentialSubject.encodedList);
    const statusList = new BitstringStatusList(
      bitstring.length * 8,
      credential.issuer,
      credential.id,
      credential.credentialSubject.statusPurpose
    );
    statusList.bitstring = bitstring;
    return statusList;
  }

  /**
   * Get the next available index
   */
  getNextAvailableIndex(): number {
    for (let i = 0; i < this.bitstring.length * 8; i++) {
      if (!this.getBit(i)) {
        return i;
      }
    }
    throw new Error('Status list is full');
  }

  /**
   * Get statistics about the status list
   */
  getStats(): { total: number; set: number; available: number; utilization: number } {
    const total = this.bitstring.length * 8;
    let set = 0;

    for (let i = 0; i < total; i++) {
      if (this.getBit(i)) {
        set++;
      }
    }

    return {
      total,
      set,
      available: total - set,
      utilization: set / total,
    };
  }
}

export class BitstringStatusListManager {
  private basePath: string;
  private defaultSize = 131072; // 16KB compressed to ~2KB

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  private getStatusListPath(issuer: string, purpose: 'revocation' | 'suspension'): string {
    const filename = `${issuer.replace(/[^a-zA-Z0-9]/g, '_')}-${purpose}.json`;
    return path.join(this.basePath, 'status-lists', filename);
  }

  /**
   * Initialize status lists directory
   */
  async init(): Promise<void> {
    await fs.promises.mkdir(path.join(this.basePath, 'status-lists'), { recursive: true });
  }

  /**
   * Create a new status list
   */
  async createStatusList(
    issuer: string,
    purpose: 'revocation' | 'suspension' = 'revocation',
    size?: number
  ): Promise<BitstringStatusList> {
    const id = `${issuer}/status-lists/${purpose}`;
    const statusList = new BitstringStatusList(size || this.defaultSize, issuer, id, purpose);

    await this.saveStatusList(issuer, statusList);
    return statusList;
  }

  /**
   * Load a status list
   */
  async loadStatusList(
    issuer: string,
    purpose: 'revocation' | 'suspension' = 'revocation'
  ): Promise<BitstringStatusList> {
    const listPath = this.getStatusListPath(issuer, purpose);

    try {
      const content = await fs.promises.readFile(listPath, 'utf-8');
      const credential: BitstringStatusListCredential = JSON.parse(content);
      return BitstringStatusList.fromCredential(credential);
    } catch {
      // Create new if doesn't exist
      return await this.createStatusList(issuer, purpose);
    }
  }

  /**
   * Save a status list
   */
  async saveStatusList(issuer: string, statusList: BitstringStatusList): Promise<void> {
    const credential = statusList.toCredential();
    const listPath = this.getStatusListPath(issuer, statusList['purpose']);

    await fs.promises.mkdir(path.dirname(listPath), { recursive: true });
    await fs.promises.writeFile(listPath, JSON.stringify(credential, null, 2));

    try {
      await fs.promises.chmod(listPath, 0o600);
    } catch {
      // Ignore on Windows
    }
  }

  /**
   * Allocate a new status list entry
   */
  async allocateEntry(
    issuer: string,
    purpose: 'revocation' | 'suspension' = 'revocation'
  ): Promise<BitstringStatusListEntry> {
    const statusList = await this.loadStatusList(issuer, purpose);
    const index = statusList.getNextAvailableIndex();

    // Mark as allocated (initially not revoked/suspended)
    // The bit will be set to 1 when actually revoked/suspended

    await this.saveStatusList(issuer, statusList);

    return {
      id: `${statusList['id']}#${index}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: purpose,
      statusListIndex: index.toString(),
      statusListCredential: statusList['id'],
    };
  }

  /**
   * Set status (revoke/suspend)
   */
  async setStatus(
    issuer: string,
    index: number,
    purpose: 'revocation' | 'suspension' = 'revocation'
  ): Promise<void> {
    const statusList = await this.loadStatusList(issuer, purpose);
    statusList.setBit(index);
    await this.saveStatusList(issuer, statusList);
  }

  /**
   * Clear status (un-revoke/un-suspend)
   */
  async clearStatus(
    issuer: string,
    index: number,
    purpose: 'revocation' | 'suspension' = 'revocation'
  ): Promise<void> {
    const statusList = await this.loadStatusList(issuer, purpose);
    statusList.clearBit(index);
    await this.saveStatusList(issuer, statusList);
  }

  /**
   * Check status
   */
  async checkStatus(
    issuer: string,
    index: number,
    purpose: 'revocation' | 'suspension' = 'revocation'
  ): Promise<boolean> {
    const statusList = await this.loadStatusList(issuer, purpose);
    return statusList.getBit(index);
  }

  /**
   * Get status list statistics
   */
  async getStats(
    issuer: string,
    purpose: 'revocation' | 'suspension' = 'revocation'
  ): Promise<{ total: number; set: number; available: number; utilization: number }> {
    const statusList = await this.loadStatusList(issuer, purpose);
    return statusList.getStats();
  }
}
