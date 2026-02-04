/**
 * Credential expiration management and warnings
 */
import * as fs from 'fs';
import * as path from 'path';
import { decodeCredential } from './vc';

export interface ExpiringCredential {
  id: string;
  issuer: string;
  subject: string;
  expiresAt: string;
  daysUntilExpiry: number;
  expired: boolean;
}

export class ExpirationManager {
  private basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  /**
   * Get all credentials from storage
   */
  private async getAllCredentials(): Promise<Array<{ id: string; jwt: string }>> {
    const credDir = path.join(this.basePath, 'credentials');
    const credentials: Array<{ id: string; jwt: string }> = [];

    try {
      const files = await fs.promises.readdir(credDir);

      for (const file of files) {
        if (!file.endsWith('.json')) continue;

        const id = file.replace(/\.json$/, '');
        const content = await fs.promises.readFile(path.join(credDir, file), 'utf-8');

        try {
          const data = JSON.parse(content);
          const jwt = data.jwt || data.credential;
          if (jwt) {
            credentials.push({ id, jwt });
          }
        } catch {
          // Skip invalid files
        }
      }
    } catch {
      // No credentials directory
    }

    return credentials;
  }

  /**
   * Calculate days until expiration
   */
  private daysUntilExpiry(expiryDate: Date): number {
    const now = new Date();
    const diff = expiryDate.getTime() - now.getTime();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  }

  /**
   * Check for expiring credentials
   */
  async checkExpiring(daysThreshold = 30): Promise<ExpiringCredential[]> {
    const credentials = await this.getAllCredentials();
    const expiring: ExpiringCredential[] = [];

    for (const { id, jwt } of credentials) {
      const decoded = decodeCredential(jwt);
      if (!decoded || !decoded.payload) continue;

      const exp = decoded.payload.exp;
      if (!exp) continue;

      const expiryDate = new Date(exp * 1000);
      const days = this.daysUntilExpiry(expiryDate);

      if (days <= daysThreshold) {
        expiring.push({
          id,
          issuer: decoded.payload.iss,
          subject: decoded.payload.sub,
          expiresAt: expiryDate.toISOString(),
          daysUntilExpiry: days,
          expired: days < 0,
        });
      }
    }

    // Sort by days until expiry (soonest first)
    return expiring.sort((a, b) => a.daysUntilExpiry - b.daysUntilExpiry);
  }

  /**
   * Check if a specific credential is expired or expiring soon
   */
  async checkCredentialExpiry(
    jwt: string
  ): Promise<{ expired: boolean; expiresAt?: string; daysUntilExpiry?: number }> {
    const decoded = decodeCredential(jwt);
    if (!decoded || !decoded.payload) {
      return { expired: false };
    }

    const exp = decoded.payload.exp;
    if (!exp) {
      return { expired: false };
    }

    const expiryDate = new Date(exp * 1000);
    const days = this.daysUntilExpiry(expiryDate);

    return {
      expired: days < 0,
      expiresAt: expiryDate.toISOString(),
      daysUntilExpiry: days,
    };
  }

  /**
   * Get expiration summary
   */
  async getSummary(): Promise<{
    total: number;
    expired: number;
    expiringSoon: number;
    healthy: number;
  }> {
    const credentials = await this.getAllCredentials();
    let expired = 0;
    let expiringSoon = 0;
    let healthy = 0;

    for (const { jwt } of credentials) {
      const status = await this.checkCredentialExpiry(jwt);

      if (status.expired) {
        expired++;
      } else if (status.daysUntilExpiry !== undefined && status.daysUntilExpiry <= 30) {
        expiringSoon++;
      } else {
        healthy++;
      }
    }

    return {
      total: credentials.length,
      expired,
      expiringSoon,
      healthy,
    };
  }

  /**
   * Generate expiration warnings
   */
  async generateWarnings(daysThreshold = 30): Promise<string[]> {
    const expiring = await this.checkExpiring(daysThreshold);
    const warnings: string[] = [];

    for (const cred of expiring) {
      if (cred.expired) {
        warnings.push(
          `EXPIRED: Credential ${cred.id} expired ${Math.abs(cred.daysUntilExpiry)} days ago`
        );
      } else if (cred.daysUntilExpiry <= 7) {
        warnings.push(
          `URGENT: Credential ${cred.id} expires in ${cred.daysUntilExpiry} day(s)`
        );
      } else {
        warnings.push(
          `WARNING: Credential ${cred.id} expires in ${cred.daysUntilExpiry} days`
        );
      }
    }

    return warnings;
  }
}
