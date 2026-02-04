/**
 * Audit logging for security-critical operations
 */
import * as fs from 'fs';
import * as path from 'path';

export type AuditEventType =
  | 'identity.created'
  | 'identity.deleted'
  | 'credential.issued'
  | 'credential.verified'
  | 'credential.revoked'
  | 'auth.signed'
  | 'auth.verified'
  | 'auth.failed'
  | 'keystore.init'
  | 'keystore.backup'
  | 'keystore.restore';

export interface AuditEvent {
  timestamp: string;
  type: AuditEventType;
  actor?: string; // DID performing the action
  subject?: string; // DID being acted upon
  details?: Record<string, unknown>;
  success: boolean;
  error?: string;
}

export class AuditLog {
  private logPath: string;
  private enabled: boolean;

  constructor(basePath: string, enabled = true) {
    this.logPath = path.join(basePath, 'audit.log');
    this.enabled = enabled;
  }

  /**
   * Log an audit event
   */
  async log(event: Omit<AuditEvent, 'timestamp'>): Promise<void> {
    if (!this.enabled) return;

    const fullEvent: AuditEvent = {
      ...event,
      timestamp: new Date().toISOString(),
    };

    const logLine = JSON.stringify(fullEvent) + '\n';

    try {
      await fs.promises.appendFile(this.logPath, logLine, 'utf-8');
      // Set restrictive permissions
      try {
        await fs.promises.chmod(this.logPath, 0o600);
      } catch {
        // Ignore on Windows
      }
    } catch (error) {
      // Don't throw - logging failure shouldn't break the operation
      console.warn('Failed to write audit log:', error);
    }
  }

  /**
   * Read recent audit events
   */
  async getRecent(limit = 100): Promise<AuditEvent[]> {
    try {
      const content = await fs.promises.readFile(this.logPath, 'utf-8');
      const lines = content.trim().split('\n');
      const events = lines
        .slice(-limit)
        .map((line) => {
          try {
            return JSON.parse(line) as AuditEvent;
          } catch {
            return null;
          }
        })
        .filter((e): e is AuditEvent => e !== null);

      return events.reverse(); // Most recent first
    } catch {
      return [];
    }
  }

  /**
   * Query audit events by criteria
   */
  async query(criteria: {
    type?: AuditEventType;
    actor?: string;
    subject?: string;
    since?: Date;
    until?: Date;
  }): Promise<AuditEvent[]> {
    const events = await this.getRecent(1000);

    return events.filter((event) => {
      if (criteria.type && event.type !== criteria.type) return false;
      if (criteria.actor && event.actor !== criteria.actor) return false;
      if (criteria.subject && event.subject !== criteria.subject) return false;

      const eventTime = new Date(event.timestamp);
      if (criteria.since && eventTime < criteria.since) return false;
      if (criteria.until && eventTime > criteria.until) return false;

      return true;
    });
  }
}
