import { randomBytes, sign as nodeSign, verify as nodeVerify, createPrivateKey, createPublicKey } from 'crypto';

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Generate a new Ed25519 key pair using Web Crypto API
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const crypto = globalThis.crypto;
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

  // Export private key
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  if (!privateKeyJwk.d) {
    throw new Error('Failed to export private key');
  }
  const privateKeyBytes = base64urlToBytes(privateKeyJwk.d);

  // Export public key
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  if (!publicKeyJwk.x) {
    throw new Error('Failed to export public key');
  }
  const publicKeyBytes = base64urlToBytes(publicKeyJwk.x);

  return {
    publicKey: publicKeyBytes,
    privateKey: privateKeyBytes,
  };
}

/**
 * Create a PKCS#8 private key for Ed25519
 * Format: version(0) + algorithm identifier + private key octet string
 */
function createPkcs8PrivateKey(privateKey: Uint8Array, publicKey: Uint8Array): Buffer {
  // Ed25519 OID: 1.3.101.112
  const ed25519Oid = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]);
  
  // Algorithm identifier sequence
  const algorithmId = Buffer.concat([
    Buffer.from([0x30, 0x05]), // SEQUENCE
    ed25519Oid
  ]);
  
  // Private key octet string (includes the public key for Ed25519)
  // Format: OCTET STRING { OCTET STRING { privateKey } [1] BIT STRING { publicKey } }
  const innerOctetString = Buffer.concat([
    Buffer.from([0x04, 0x20]), // OCTET STRING, 32 bytes
    privateKey
  ]);
  
  const contextTag = Buffer.concat([
    Buffer.from([0xa1, 0x23]), // Context-specific [1] constructed, 35 bytes
    Buffer.from([0x03, 0x21, 0x00]), // BIT STRING, 33 bits (1 unused + 32 bytes)
    publicKey
  ]);
  
  const privateKeyInfo = Buffer.concat([
    innerOctetString,
    contextTag
  ]);
  
  const outerOctetString = Buffer.concat([
    Buffer.from([0x04, privateKeyInfo.length]),
    privateKeyInfo
  ]);
  
  // Full PKCS#8 structure
  const content = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x00]), // INTEGER version 0
    algorithmId,
    outerOctetString
  ]);
  
  return Buffer.concat([
    Buffer.from([0x30, content.length]),
    content
  ]);
}

/**
 * Create an SPKI public key for Ed25519
 */
function createSpkiPublicKey(publicKey: Uint8Array): Buffer {
  // Ed25519 OID: 1.3.101.112
  const ed25519Oid = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]);
  
  // Algorithm identifier sequence
  const algorithmId = Buffer.concat([
    Buffer.from([0x30, 0x05]), // SEQUENCE
    ed25519Oid
  ]);
  
  // BIT STRING containing the raw public key
  const bitString = Buffer.concat([
    Buffer.from([0x03, 0x21, 0x00]), // BIT STRING, 33 bytes (1 unused + 32 bytes key)
    publicKey
  ]);
  
  const content = Buffer.concat([
    algorithmId,
    bitString
  ]);
  
  return Buffer.concat([
    Buffer.from([0x30, content.length]),
    content
  ]);
}

/**
 * Sign a message with an Ed25519 private key
 * Uses Node.js native crypto with proper key formatting
 * @param message - Message to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @param publicKey - 32-byte Ed25519 public key (required for PKCS#8 format)
 */
export async function sign(
  message: Uint8Array,
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Promise<Uint8Array> {
  const privateKeyDer = createPkcs8PrivateKey(privateKey, publicKey);
  const privateKeyObj = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });

  const signature = nodeSign(null, message, privateKeyObj);
  return new Uint8Array(signature);
}

/**
 * Verify a signature with an Ed25519 public key
 * Uses Node.js native crypto with proper key formatting
 */
export async function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    const publicKeyDer = createSpkiPublicKey(publicKey);
    const publicKeyObj = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    
    return nodeVerify(null, message, publicKeyObj, signature);
  } catch {
    return false;
  }
}

/**
 * Convert a Uint8Array to a base64url string
 */
export function bytesToBase64url(bytes: Uint8Array): string {
  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Convert a base64url string to a Uint8Array
 */
export function base64urlToBytes(base64url: string): Uint8Array {
  // Add padding if necessary (only when needed, not when length is already multiple of 4)
  const padding = (4 - (base64url.length % 4)) % 4;
  if (padding > 0) {
    base64url += '='.repeat(padding);
  }
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64');
}

/**
 * Convert a Uint8Array to a hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/**
 * Convert a hex string to a Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  return Buffer.from(hex, 'hex');
}
