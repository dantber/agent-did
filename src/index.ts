/**
 * Main export file for agent-did library
 *
 * This allows other packages to import agent-did functionality:
 * import { Keystore, generateKeyPair, createOwnershipCredential } from 'agent-did';
 */

// Keystore
export { Keystore } from './keystore/index.js';
export type { IdentityType, IdentityMetadata } from './keystore/index.js';

// Crypto
export {
  generateKeyPair,
  sign,
  verify,
  bytesToHex,
  hexToBytes,
} from './crypto/index.js';
export type { KeyPair } from './crypto/index.js';

// DID
export {
  publicKeyToDidKey,
  didKeyToPublicKey,
  isValidDidKey,
} from './did/index.js';

// VC
export {
  createOwnershipCredential,
  createCapabilityCredential,
  signCredential,
  verifyCredential,
  decodeCredential,
} from './vc/index.js';
export type {
  VerifiableCredential,
  CredentialSubject,
  JWTPayload,
} from './vc/index.js';

// Auth
export {
  signAuthChallenge,
  verifyAuthChallenge,
  createAuthPayload,
} from './crypto/auth.js';
export type {
  AuthPayload,
  AuthSignResult,
  AuthVerifyResult,
} from './crypto/auth.js';
