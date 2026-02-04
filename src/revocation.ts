/**
 * Credential revocation registry
 *
 * Implements a simple revocation list for issued credentials.
 * In production, this would typically use a Status List 2021 or similar standard.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export interface RevocationEntry {
  credentialId: string;
  issuer: string;
  subject: string;
  revokedAt: string;
  reason?: string;
}

export interface RevocationList {
  version: number;
  issuer: string;
  lastUpdated: string;
  revoked: RevocationEntry[];
}

export class RevocationRegistry {
  private basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  private getListPath(issuerDid: string): string {
    const filename = issuerDid.replace(/[^a-zA-Z0-9]/g, '_') + '-revocations.json';
    return path.join(this.basePath, 'revocations', filename);
  }

  /**
   * Initialize revocation directory
   */
  async init(): Promise<void> {
    await fs.promises.mkdir(path.join(this.basePath, 'revocations'), { recursive: true });
  }

  /**
   * Load revocation list for an issuer
   */
  private async loadList(issuerDid: string): Promise<RevocationList> {
    const listPath = this.getListPath(issuerDid);

    try {
      const content = await fs.promises.readFile(listPath, 'utf-8');
      return JSON.parse(content);
    } catch {
      // Create new list if doesn't exist
      return {
        version: 1,
        issuer: issuerDid,
        lastUpdated: new Date().toISOString(),
        revoked: [],
      };
    }
  }

  /**
   * Save revocation list
   */
  private async saveList(list: RevocationList): Promise<void> {
    const listPath = this.getListPath(list.issuer);
    await fs.promises.mkdir(path.dirname(listPath), { recursive: true });

    list.lastUpdated = new Date().toISOString();
    await fs.promises.writeFile(listPath, JSON.stringify(list, null, 2));

    try {
      await fs.promises.chmod(listPath, 0o600);
    } catch {
      // Ignore on Windows
    }
  }

  /**
   * Revoke a credential
   */
  async revoke(
    credentialId: string,
    issuerDid: string,
    subjectDid: string,
    reason?: string
  ): Promise<void> {
    const list = await this.loadList(issuerDid);

    // Check if already revoked
    const existing = list.revoked.find((r) => r.credentialId === credentialId);
    if (existing) {
      throw new Error(`Credential already revoked at ${existing.revokedAt}`);
    }

    // Add to revocation list
    list.revoked.push({
      credentialId,
      issuer: issuerDid,
      subject: subjectDid,
      revokedAt: new Date().toISOString(),
      reason,
    });

    await this.saveList(list);
  }

  /**
   * Check if a credential is revoked
   */
  async isRevoked(credentialId: string, issuerDid: string): Promise<boolean> {
    const list = await this.loadList(issuerDid);
    return list.revoked.some((r) => r.credentialId === credentialId);
  }

  /**
   * Get revocation status for a credential
   */
  async getStatus(credentialId: string, issuerDid: string): Promise<RevocationEntry | null> {
    const list = await this.loadList(issuerDid);
    return list.revoked.find((r) => r.credentialId === credentialId) || null;
  }

  /**
   * List all revoked credentials for an issuer
   */
  async listRevoked(issuerDid: string): Promise<RevocationEntry[]> {
    const list = await this.loadList(issuerDid);
    return list.revoked;
  }

  /**
   * Generate a revocation status for embedding in credentials
   * Returns a hash of the credential ID that can be checked against the registry
   */
  generateStatusId(credentialId: string): string {
    return crypto.createHash('sha256').update(credentialId).digest('hex');
  }
}
