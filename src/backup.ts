/**
 * Backup and restore functionality for the keystore
 */
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { promisify } from 'util';
import { pipeline } from 'stream';
import { createGzip, createGunzip } from 'zlib';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const pipelineAsync = promisify(pipeline);

export interface BackupMetadata {
  version: number;
  createdAt: string;
  keystorePath: string;
  identityCount: number;
  credentialCount: number;
  encrypted: boolean;
}

export class BackupManager {
  private keystorePath: string;

  constructor(keystorePath: string) {
    this.keystorePath = keystorePath;
  }

  /**
   * Create a backup of the keystore
   */
  async backup(
    backupPath: string,
    options: {
      encrypt?: boolean;
      password?: string;
      includeCredentials?: boolean;
    } = {}
  ): Promise<BackupMetadata> {
    const { encrypt = false, password, includeCredentials = true } = options;

    if (encrypt && !password) {
      throw new Error('Password required for encrypted backup');
    }

    // Gather files to backup
    const filesToBackup: Array<{ relativePath: string; fullPath: string }> = [];

    // Add identities.json
    const indexPath = path.join(this.keystorePath, 'identities.json');
    if (await this.fileExists(indexPath)) {
      filesToBackup.push({
        relativePath: 'identities.json',
        fullPath: indexPath,
      });
    }

    // Add all keys
    const keysDir = path.join(this.keystorePath, 'keys');
    if (await this.fileExists(keysDir)) {
      const keyFiles = await fs.promises.readdir(keysDir);
      for (const file of keyFiles) {
        if (file.endsWith('.json')) {
          filesToBackup.push({
            relativePath: `keys/${file}`,
            fullPath: path.join(keysDir, file),
          });
        }
      }
    }

    // Optionally include credentials
    if (includeCredentials) {
      const credDir = path.join(this.keystorePath, 'credentials');
      if (await this.fileExists(credDir)) {
        const credFiles = await fs.promises.readdir(credDir);
        for (const file of credFiles) {
          if (file.endsWith('.json')) {
            filesToBackup.push({
              relativePath: `credentials/${file}`,
              fullPath: path.join(credDir, file),
            });
          }
        }
      }
    }

    // Create backup archive
    const archive: Record<string, string> = {};
    let identityCount = 0;
    let credentialCount = 0;

    for (const file of filesToBackup) {
      const content = await fs.promises.readFile(file.fullPath, 'utf-8');
      archive[file.relativePath] = content;

      if (file.relativePath.startsWith('keys/')) identityCount++;
      if (file.relativePath.startsWith('credentials/')) credentialCount++;
    }

    const metadata: BackupMetadata = {
      version: 1,
      createdAt: new Date().toISOString(),
      keystorePath: this.keystorePath,
      identityCount,
      credentialCount,
      encrypted: encrypt,
    };

    const backupData = {
      metadata,
      files: archive,
    };

    let finalData = JSON.stringify(backupData);

    // Encrypt if requested
    if (encrypt && password) {
      finalData = await this.encryptBackup(finalData, password);
    }

    // Write to file
    await fs.promises.writeFile(backupPath, finalData);

    // Set restrictive permissions
    try {
      await fs.promises.chmod(backupPath, 0o600);
    } catch {
      // Ignore on Windows
    }

    return metadata;
  }

  /**
   * Restore from a backup
   */
  async restore(
    backupPath: string,
    options: {
      password?: string;
      targetPath?: string;
    } = {}
  ): Promise<BackupMetadata> {
    const { password, targetPath = this.keystorePath } = options;

    // Read backup file
    let backupContent = await fs.promises.readFile(backupPath, 'utf-8');

    // Try to decrypt if password provided
    if (password) {
      try {
        backupContent = await this.decryptBackup(backupContent, password);
      } catch (error) {
        throw new Error('Failed to decrypt backup: incorrect password or corrupted file');
      }
    }

    // Parse backup
    let backupData: { metadata: BackupMetadata; files: Record<string, string> };
    try {
      backupData = JSON.parse(backupContent);
    } catch {
      throw new Error('Invalid backup file format');
    }

    if (backupData.metadata.encrypted && !password) {
      throw new Error('Backup is encrypted but no password provided');
    }

    // Create target directory structure
    await fs.promises.mkdir(targetPath, { recursive: true });
    await fs.promises.mkdir(path.join(targetPath, 'keys'), { recursive: true });
    await fs.promises.mkdir(path.join(targetPath, 'credentials'), { recursive: true });

    // Restore files
    for (const [relativePath, content] of Object.entries(backupData.files)) {
      const fullPath = path.join(targetPath, relativePath);
      await fs.promises.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.promises.writeFile(fullPath, content);

      // Set restrictive permissions
      try {
        await fs.promises.chmod(fullPath, 0o600);
      } catch {
        // Ignore on Windows
      }
    }

    return backupData.metadata;
  }

  /**
   * Encrypt backup data
   */
  private async encryptBackup(data: string, password: string): Promise<string> {
    const salt = randomBytes(32);
    const iv = randomBytes(16);

    // Derive key from password
    const key = crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256');

    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
      cipher.update(data, 'utf-8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // Package everything together
    const package_ = {
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      data: encrypted.toString('hex'),
    };

    return JSON.stringify(package_);
  }

  /**
   * Decrypt backup data
   */
  private async decryptBackup(encrypted: string, password: string): Promise<string> {
    const package_ = JSON.parse(encrypted);

    const salt = Buffer.from(package_.salt, 'hex');
    const iv = Buffer.from(package_.iv, 'hex');
    const authTag = Buffer.from(package_.authTag, 'hex');
    const data = Buffer.from(package_.data, 'hex');

    // Derive key from password
    const key = crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256');

    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(data),
      decipher.final(),
    ]);

    return decrypted.toString('utf-8');
  }

  /**
   * Check if file exists
   */
  private async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.promises.access(filePath);
      return true;
    } catch {
      return false;
    }
  }
}
