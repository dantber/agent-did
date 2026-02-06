import * as path from 'path';
import * as os from 'os';
import { Keystore } from '../keystore';
import { promptPassword } from './prompt';

export type PassphraseRole = 'owner' | 'agent';
export type PassphrasePurpose = 'encrypt' | 'decrypt';

const OWNER_PASSPHRASE_ENV = 'OWNER_DID_PASSPHRASE';
const OWNER_PASSPHRASE_ENV_ALIAS = 'AGENT_DID_OWNER_PASSPHRASE';
const AGENT_PASSPHRASE_ENV = 'AGENT_DID_PASSPHRASE';

const PASSPHRASE_ERROR_CODES = {
  ownerRequired: 'AGENT_DID_ERR_OWNER_PASSPHRASE_REQUIRED',
  ownerInvalid: 'AGENT_DID_ERR_OWNER_PASSPHRASE_INVALID',
  agentRequired: 'AGENT_DID_ERR_AGENT_PASSPHRASE_REQUIRED',
  agentInvalid: 'AGENT_DID_ERR_AGENT_PASSPHRASE_INVALID',
} as const;

const issuedWarnings = new Set<string>();

function withErrorCode(code: string, message: string): string {
  return `[${code}] ${message}`;
}

function getRoleDisplayLabel(role: PassphraseRole): string {
  if (role === 'owner') {
    return 'ISSUER/OWNER DID key';
  }
  return 'AGENT DID key';
}

function getRoleEnvName(role: PassphraseRole): string {
  if (role === 'owner') {
    return OWNER_PASSPHRASE_ENV;
  }
  return AGENT_PASSPHRASE_ENV;
}

function getRequiredCode(role: PassphraseRole): string {
  if (role === 'owner') {
    return PASSPHRASE_ERROR_CODES.ownerRequired;
  }
  return PASSPHRASE_ERROR_CODES.agentRequired;
}

function getInvalidCode(role: PassphraseRole): string {
  if (role === 'owner') {
    return PASSPHRASE_ERROR_CODES.ownerInvalid;
  }
  return PASSPHRASE_ERROR_CODES.agentInvalid;
}

function buildRequiredPassphraseMessage(
  role: PassphraseRole,
  purpose: PassphrasePurpose,
  flagName: '--owner-passphrase' | '--agent-passphrase'
): string {
  const action = purpose === 'encrypt' ? 'encrypt' : 'decrypt';
  const message = `Passphrase required to ${action} ${getRoleDisplayLabel(role)}. Set ${getRoleEnvName(role)} or use ${flagName}.`;
  return withErrorCode(getRequiredCode(role), message);
}

function defaultPrompt(role: PassphraseRole, purpose: PassphrasePurpose): string {
  const action = purpose === 'encrypt' ? 'encrypt' : 'decrypt';
  return `Enter passphrase to ${action} ${getRoleDisplayLabel(role)}: `;
}

function resolveFromEnv(role: PassphraseRole): string | null | undefined {
  if (role === 'agent') {
    const passphrase = process.env[AGENT_PASSPHRASE_ENV];
    if (passphrase !== undefined) {
      return passphrase === '' ? null : passphrase;
    }
    return undefined;
  }

  const ownerEnv = process.env[OWNER_PASSPHRASE_ENV];
  if (ownerEnv !== undefined) {
    return ownerEnv === '' ? null : ownerEnv;
  }

  const ownerAliasEnv = process.env[OWNER_PASSPHRASE_ENV_ALIAS];
  if (ownerAliasEnv !== undefined) {
    return ownerAliasEnv === '' ? null : ownerAliasEnv;
  }

  const legacyEnv = process.env[AGENT_PASSPHRASE_ENV];
  if (legacyEnv !== undefined) {
    const warningKey = `legacy-owner-fallback:${legacyEnv}`;
    if (!issuedWarnings.has(warningKey)) {
      issuedWarnings.add(warningKey);
      console.warn(
        `⚠️  ${AGENT_PASSPHRASE_ENV} is a legacy fallback for owner/issuer keys. Prefer ${OWNER_PASSPHRASE_ENV}.`
      );
    }
    return legacyEnv === '' ? null : legacyEnv;
  }

  return undefined;
}

export async function resolveRolePassphrase(options: {
  role: PassphraseRole;
  purpose: PassphrasePurpose;
  noEncryption?: boolean;
  passphraseFlagValue?: string;
  passphraseFlagName: '--owner-passphrase' | '--agent-passphrase';
  promptText?: string;
}): Promise<string | null> {
  if (options.noEncryption) {
    return null;
  }

  if (options.passphraseFlagValue !== undefined) {
    return options.passphraseFlagValue === '' ? null : options.passphraseFlagValue;
  }

  const envPassphrase = resolveFromEnv(options.role);
  if (envPassphrase !== undefined) {
    return envPassphrase;
  }

  if (process.stdin.isTTY) {
    try {
      const promptText = options.promptText || defaultPrompt(options.role, options.purpose);
      const passphrase = await promptPassword(promptText);
      if (!passphrase) {
        throw new Error(
          buildRequiredPassphraseMessage(
            options.role,
            options.purpose,
            options.passphraseFlagName
          )
        );
      }
      return passphrase;
    } catch (error) {
      if (error instanceof Error && error.message.includes('AGENT_DID_ERR_')) {
        throw error;
      }
      throw new Error(
        `Failed to get passphrase: ${error instanceof Error ? error.message : error}`
      );
    }
  }

  throw new Error(
    buildRequiredPassphraseMessage(options.role, options.purpose, options.passphraseFlagName)
  );
}

export function mapInvalidPassphraseError(
  error: unknown,
  role: PassphraseRole,
  flagName: '--owner-passphrase' | '--agent-passphrase'
): Error {
  if (error instanceof Error && error.message === 'Authentication failed') {
    return new Error(
      withErrorCode(
        getInvalidCode(role),
        `Invalid passphrase for ${getRoleDisplayLabel(role)}. Set ${getRoleEnvName(role)} or use ${flagName}.`
      )
    );
  }
  if (error instanceof Error) {
    return error;
  }
  return new Error(String(error));
}

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
  noEncryption = false,
  passphraseOverride?: string | null
): Promise<Keystore> {
  const resolvedPath = getStorePath(storePath);
  const passphrase =
    passphraseOverride !== undefined ? passphraseOverride : await getPassphrase(noEncryption);
  return new Keystore(resolvedPath, passphrase, true); // Skip validation
}

/**
 * Get a keystore instance for creating new data
 * Validates passphrase strength
 */
export async function getNewKeystore(
  storePath?: string,
  noEncryption = false,
  passphraseOverride?: string | null
): Promise<Keystore> {
  const resolvedPath = getStorePath(storePath);
  const passphrase =
    passphraseOverride !== undefined ? passphraseOverride : await getPassphrase(noEncryption);

  if (noEncryption) {
    console.log('\n⚠️  WARNING: Keys will be stored UNENCRYPTED on disk!');
    console.log('This is NOT recommended for production use.\n');
  }

  // Will throw if passphrase is weak
  return new Keystore(resolvedPath, passphrase, false);
}
