/**
 * Key rotation mechanism
 * Allows rotating keys while maintaining identity continuity
 */
import * as fs from 'fs';
import * as path from 'path';
import { KeyPair, generateKeyPair } from './crypto';
import { publicKeyToDidKey } from './did';
import { Keystore, IdentityMetadata } from './keystore';
import { AuditLog } from './audit';

export interface KeyRotationRecord {
  oldDid: string;
  newDid: string;
  rotatedAt: string;
  reason?: string;
  credentialsReissued: number;
  status: 'pending' | 'completed' | 'failed';
}

export interface KeyRotationHistory {
  version: number;
  identity: string; // Original identity name
  rotations: KeyRotationRecord[];
}

export class KeyRotationManager {
  private basePath: string;
  private keystore: Keystore;
  private auditLog?: AuditLog;

  constructor(basePath: string, keystore: Keystore, auditLog?: AuditLog) {
    this.basePath = basePath;
    this.keystore = keystore;
    this.auditLog = auditLog;
  }

  private getRotationHistoryPath(): string {
    return path.join(this.basePath, 'rotation-history.json');
  }

  /**
   * Load rotation history
   */
  private async loadHistory(): Promise<KeyRotationHistory> {
    const historyPath = this.getRotationHistoryPath();
    try {
      const content = await fs.promises.readFile(historyPath, 'utf-8');
      return JSON.parse(content);
    } catch {
      return {
        version: 1,
        identity: '',
        rotations: [],
      };
    }
  }

  /**
   * Save rotation history
   */
  private async saveHistory(history: KeyRotationHistory): Promise<void> {
    const historyPath = this.getRotationHistoryPath();
    await fs.promises.writeFile(historyPath, JSON.stringify(history, null, 2));
    try {
      await fs.promises.chmod(historyPath, 0o600);
    } catch {
      // Ignore on Windows
    }
  }

  /**
   * Rotate a key for an identity
   */
  async rotateKey(
    oldDid: string,
    reason?: string
  ): Promise<{ newDid: string; record: KeyRotationRecord }> {
    // Get the old identity
    const oldIdentity = await this.keystore.getIdentity(oldDid);
    if (!oldIdentity) {
      throw new Error(`Identity not found: ${oldDid}`);
    }

    // Generate new key pair
    const newKeyPair = await generateKeyPair();
    const newDid = publicKeyToDidKey(newKeyPair.publicKey);

    // Create new identity with same metadata
    const newIdentity: IdentityMetadata = {
      ...oldIdentity,
      did: newDid,
      createdAt: new Date().toISOString(),
    };

    // Store new identity
    await this.keystore.storeIdentity(newIdentity, newKeyPair);

    // Create rotation record
    const record: KeyRotationRecord = {
      oldDid,
      newDid,
      rotatedAt: new Date().toISOString(),
      reason,
      credentialsReissued: 0,
      status: 'completed',
    };

    // Update history
    const history = await this.loadHistory();
    if (!history.identity) {
      history.identity = oldIdentity.name;
    }
    history.rotations.push(record);
    await this.saveHistory(history);

    // Log to audit
    if (this.auditLog) {
      await this.auditLog.log({
        type: 'identity.created',
        actor: oldDid,
        subject: newDid,
        success: true,
        details: {
          action: 'key-rotation',
          reason,
        },
      });
    }

    return { newDid, record };
  }

  /**
   * Get rotation history for a DID
   */
  async getRotationHistory(did: string): Promise<KeyRotationRecord[]> {
    const history = await this.loadHistory();
    return history.rotations.filter((r) => r.oldDid === did || r.newDid === did);
  }

  /**
   * Get current DID (after all rotations)
   */
  async getCurrentDid(originalDid: string): Promise<string> {
    const history = await this.loadHistory();

    let currentDid = originalDid;
    let foundRotation = true;

    // Follow the chain of rotations
    while (foundRotation) {
      foundRotation = false;
      for (const rotation of history.rotations) {
        if (rotation.oldDid === currentDid) {
          currentDid = rotation.newDid;
          foundRotation = true;
          break;
        }
      }
    }

    return currentDid;
  }

  /**
   * Check if a DID has been rotated
   */
  async isRotated(did: string): Promise<boolean> {
    const history = await this.loadHistory();
    return history.rotations.some((r) => r.oldDid === did);
  }

  /**
   * Mark old identity as deprecated
   */
  async markDeprecated(oldDid: string): Promise<void> {
    const identity = await this.keystore.getIdentity(oldDid);
    if (!identity) return;

    // We could add a 'deprecated' flag to IdentityMetadata
    // For now, we'll rely on the rotation history

    if (this.auditLog) {
      await this.auditLog.log({
        type: 'identity.deleted',
        subject: oldDid,
        success: true,
        details: {
          action: 'deprecated-due-to-rotation',
        },
      });
    }
  }

  /**
   * List all rotations
   */
  async listRotations(): Promise<KeyRotationRecord[]> {
    const history = await this.loadHistory();
    return history.rotations;
  }
}
