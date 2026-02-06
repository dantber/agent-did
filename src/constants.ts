/**
 * Cryptographic algorithm constants
 */
export const CRYPTO = {
  // Signature algorithms
  SIGNATURE_ALGORITHM: 'Ed25519' as const,
  SIGNATURE_ALG_NAME: 'EdDSA' as const,

  // Encryption
  ENCRYPTION_ALGORITHM: 'aes-256-gcm' as const,
  KEY_DERIVATION: 'pbkdf2' as const,
  KDF_HASH: 'sha256' as const,

  // Key lengths (in bytes)
  ED25519_PUBLIC_KEY_LENGTH: 32,
  ED25519_PRIVATE_KEY_LENGTH: 32,
  ED25519_SIGNATURE_LENGTH: 64,
  AES_KEY_LENGTH: 32,
  IV_LENGTH: 16,
  AUTH_TAG_LENGTH: 16,
  SALT_LENGTH: 32,

  // OWASP 2024 recommendation for PBKDF2-SHA256
  KDF_ITERATIONS: 600000,
} as const;

/**
 * DID constants
 */
export const DID = {
  METHOD: 'did:key:' as const,
  MULTIBASE_PREFIX: 'z' as const, // base58btc

  // Ed25519 multicodec prefix
  ED25519_MULTICODEC: new Uint8Array([0xed, 0x01]),
} as const;

/**
 * Verifiable Credential constants
 * Using W3C VC Data Model 2.0
 */
export const VC = {
  CONTEXT: ['https://www.w3.org/ns/credentials/v2'] as const,
  BASE_TYPE: 'VerifiableCredential' as const,
  OWNERSHIP_TYPE: 'AgentOwnershipCredential' as const,
  CAPABILITY_TYPE: 'AgentCapabilityCredential' as const,
  JWT_TYPE: 'JWT' as const,
} as const;

/**
 * Security policy constants
 */
export const SECURITY = {
  MIN_PASSPHRASE_LENGTH: 16,
  MIN_PASSPHRASE_ENTROPY: 40, // bits
  DEFAULT_AUTH_EXPIRY: 120, // seconds
  MAX_DID_LENGTH: 200, // prevent extremely long DIDs
} as const;

/**
 * File and storage constants
 */
export const STORAGE = {
  DEFAULT_DIR_NAME: '.agent-did' as const,
  INDEX_FILE: 'identities.json' as const,
  KEYS_DIR: 'keys' as const,
  VC_DIR: 'vc' as const,
  BACKUPS_DIR: 'backups' as const,
  CREDENTIALS_DIR: 'credentials' as const,
  FILE_PERMISSIONS: 0o600, // Owner read/write only
  TEMP_FILE_SUFFIX: '.tmp' as const,
} as const;

/**
 * Version constants
 */
export const VERSION = {
  KEY_VERSION: 1,
  KEYSTORE_VERSION: 1,
} as const;
