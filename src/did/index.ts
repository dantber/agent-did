import { encode as base58Encode, decode as base58Decode } from './base58';
import { bytesToHex } from '../crypto';

// Multicodec prefix for Ed25519 public key (0xed01)
const ED25519_PUBKEY_CODE = new Uint8Array([0xed, 0x01]);

export interface DidDocument {
  '@context': string | string[];
  id: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase: string;
}

/**
 * Encode an Ed25519 public key to a did:key identifier
 */
export function publicKeyToDidKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32 bytes, got ${publicKey.length}`);
  }
  const multibaseKey = publicKeyToMultibase(publicKey);
  return `did:key:${multibaseKey}`;
}

/**
 * Extract the raw public key from a did:key identifier
 */
export function didKeyToPublicKey(didKey: string): Uint8Array {
  if (!didKey || typeof didKey !== 'string') {
    throw new Error('DID must be a non-empty string');
  }

  if (!didKey.startsWith('did:key:')) {
    throw new Error(`Invalid DID format: expected 'did:key:', got '${didKey.substring(0, 8)}'`);
  }

  let multibaseKey = didKey.slice(8); // Remove 'did:key:' prefix

  if (!multibaseKey.startsWith('z')) {
    throw new Error('Invalid multibase encoding: expected base58btc (z prefix)');
  }

  multibaseKey = multibaseKey.slice(1);

  if (multibaseKey.length === 0) {
    throw new Error('Invalid DID: empty key component');
  }

  let prefixedKey: Uint8Array;
  try {
    prefixedKey = base58Decode(multibaseKey);
  } catch (error) {
    throw new Error(`Invalid base58 encoding: ${error instanceof Error ? error.message : error}`);
  }

  // Verify the multicodec prefix
  if (prefixedKey.length < 34) { // 2 bytes prefix + 32 bytes key
    throw new Error(`Invalid key length: expected at least 34 bytes, got ${prefixedKey.length}`);
  }

  const prefix = prefixedKey.slice(0, 2);
  if (prefix[0] !== 0xed || prefix[1] !== 0x01) {
    throw new Error(`Unsupported key type: expected Ed25519 (0xed01), got 0x${prefix[0].toString(16)}${prefix[1].toString(16)}`);
  }

  const publicKey = prefixedKey.slice(2);

  if (publicKey.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32 bytes, got ${publicKey.length}`);
  }

  return publicKey;
}

/**
 * Generate a verification method ID from a DID
 */
export function getVerificationMethodId(did: string): string {
  const parts = did.split(':');
  if (parts.length < 3) {
    throw new Error(`Invalid DID format: ${did}`);
  }
  return `${did}#${parts[2]}`;
}

/**
 * Derive a DID Document from a did:key identifier
 */
export function deriveDidDocument(didKey: string): DidDocument {
  const publicKey = didKeyToPublicKey(didKey);
  const multibaseKey = publicKeyToMultibase(publicKey);
  const vmId = getVerificationMethodId(didKey);

  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
    id: didKey,
    verificationMethod: [
      {
        id: vmId,
        type: 'Ed25519VerificationKey2020',
        controller: didKey,
        publicKeyMultibase: multibaseKey,
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
}

/**
 * Get the public key hex from a did:key
 */
export function getPublicKeyHex(didKey: string): string {
  const publicKey = didKeyToPublicKey(didKey);
  return bytesToHex(publicKey);
}

/**
 * Validate a did:key string
 */
export function isValidDidKey(did: string): boolean {
  if (!did || typeof did !== 'string') return false;
  if (!did.startsWith('did:key:')) return false;

  try {
    didKeyToPublicKey(did);
    return true;
  } catch {
    return false;
  }
}

function publicKeyToMultibase(publicKey: Uint8Array): string {
  // Prepend the Ed25519 multicodec prefix
  const prefixedKey = new Uint8Array(ED25519_PUBKEY_CODE.length + publicKey.length);
  prefixedKey.set(ED25519_PUBKEY_CODE);
  prefixedKey.set(publicKey, ED25519_PUBKEY_CODE.length);

  // base58btc multibase prefix (z)
  return `z${base58Encode(prefixedKey)}`;
}
