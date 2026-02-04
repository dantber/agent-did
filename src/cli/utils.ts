import * as path from 'path';
import * as os from 'os';
import { Keystore } from '../keystore';
import { promptPassword } from './prompt';

/**
 * Get the keystore path
 */
export function getStorePath(customPath?: string): string {
  if (customPath) return path.resolve(customPath);
  return process.env.AGENT_DID_HOME || path.join(os.homedir(), '.agent-did');
}

/**
 * Get the passphrase with fallback chain:
 * 1. If noEncryption is true, return null
 * 2. Try environment variable
 * 3. If interactive (TTY), prompt user
 * 4. Otherwise error
 */
export async function getPassphrase(noEncryption = false): Promise<string | null> {
  // Option 1: No encryption requested
  if (noEncryption) {
    return null;
  }

  // Option 2: Environment variable
  const envPassphrase = process.env.AGENT_DID_PASSPHRASE;
  if (envPassphrase !== undefined) {
    // Empty string means no encryption
    if (envPassphrase === '') {
      return null;
    }
    return envPassphrase;
  }

  // Option 3: Interactive prompt
  if (process.stdin.isTTY) {
    try {
      console.log('\n⚠️  No passphrase found in AGENT_DID_PASSPHRASE environment variable.');
      const passphrase = await promptPassword('Enter passphrase to encrypt keys: ');
      if (!passphrase) {
        throw new Error('Passphrase cannot be empty');
      }
      return passphrase;
    } catch (error) {
      throw new Error(
        `Failed to get passphrase: ${error instanceof Error ? error.message : error}`
      );
    }
  }

  // Option 4: No passphrase available and not interactive
  throw new Error(
    'Passphrase required but not available. ' +
      'Set AGENT_DID_PASSPHRASE environment variable, use --no-encryption flag, ' +
      'or run in an interactive terminal.'
  );
}

/**
 * Output data as formatted JSON
 */
export function outputJson(data: unknown): string {
  return JSON.stringify(data, null, 2);
}

/**
 * Output data as a simple table
 */
export function outputTable(data: Record<string, unknown>): string {
  const lines: string[] = [];
  const maxKeyLength = Math.max(...Object.keys(data).map((k) => k.length));

  for (const [key, value] of Object.entries(data)) {
    const paddedKey = key.padEnd(maxKeyLength);
    lines.push(`${paddedKey} : ${value}`);
  }

  return lines.join('\n');
}

/**
 * Format a DID for display (truncate if too long)
 */
export function formatDid(did: string, maxLength = 60): string {
  if (did.length <= maxLength) return did;
  return did.slice(0, maxLength - 3) + '...';
}

/**
 * Parse a date string for display
 */
export function formatDate(dateStr: string): string {
  try {
    const date = new Date(dateStr);
    return date.toLocaleString();
  } catch {
    return dateStr;
  }
}

/**
 * Validate that a string is a valid DID
 */
export function validateDid(did: string): void {
  if (!did || !did.startsWith('did:')) {
    throw new Error(`Invalid DID format: ${did}`);
  }
}

/**
 * Get a keystore instance for reading existing data
 * Skips passphrase validation for backwards compatibility
 */
export async function getExistingKeystore(
  storePath?: string,
  noEncryption = false
): Promise<Keystore> {
  const resolvedPath = getStorePath(storePath);
  const passphrase = await getPassphrase(noEncryption);
  return new Keystore(resolvedPath, passphrase, true); // Skip validation
}

/**
 * Get a keystore instance for creating new data
 * Validates passphrase strength
 */
export async function getNewKeystore(
  storePath?: string,
  noEncryption = false
): Promise<Keystore> {
  const resolvedPath = getStorePath(storePath);
  const passphrase = await getPassphrase(noEncryption);

  if (noEncryption) {
    console.log('\n⚠️  WARNING: Keys will be stored UNENCRYPTED on disk!');
    console.log('This is NOT recommended for production use.\n');
  }

  // Will throw if passphrase is weak
  return new Keystore(resolvedPath, passphrase, false);
}
