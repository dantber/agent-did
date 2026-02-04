import { sign, verify, bytesToBase64url, base64urlToBytes } from './index';
import { didKeyToPublicKey, getVerificationMethodId } from '../did';

export interface AuthPayload {
  nonce: string;
  aud?: string;
  domain?: string;
  iat: number;
  exp: number;
  did: string;
}

export interface AuthSignResult {
  did: string;
  kid: string;
  payload: AuthPayload;
  payloadEncoded: string;
  signature: string;
  alg: 'EdDSA';
  createdAt: string;
  expiresAt: string;
}

export interface AuthVerifyResult {
  valid: boolean;
  reason?: string;
  payload?: AuthPayload;
}

/**
 * Create an auth payload for signing
 */
export function createAuthPayload(
  did: string,
  nonce: string,
  options: {
    audience?: string;
    domain?: string;
    expiresIn?: number;
  } = {}
): AuthPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    nonce,
    ...(options.audience && { aud: options.audience }),
    ...(options.domain && { domain: options.domain }),
    iat: now,
    exp: now + (options.expiresIn ?? 120),
    did,
  };
}

/**
 * Sign an authentication challenge
 */
export async function signAuthChallenge(
  did: string,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  challenge: string,
  options: {
    audience?: string;
    domain?: string;
    expiresIn?: number;
  } = {}
): Promise<AuthSignResult> {
  const payload = createAuthPayload(did, challenge, options);

  // Encode payload as compact JWT-style (base64url JSON)
  const payloadEncoded = bytesToBase64url(Buffer.from(JSON.stringify(payload)));

  // Sign the encoded payload
  const signature = await sign(Buffer.from(payloadEncoded), privateKey, publicKey);
  const signatureEncoded = bytesToBase64url(signature);

  return {
    did,
    kid: getVerificationMethodId(did),
    payload,
    payloadEncoded,
    signature: signatureEncoded,
    alg: 'EdDSA',
    createdAt: new Date(payload.iat * 1000).toISOString(),
    expiresAt: new Date(payload.exp * 1000).toISOString(),
  };
}

/**
 * Verify an authentication signature
 */
export async function verifyAuthChallenge(
  did: string,
  payloadEncoded: string,
  signature: string,
  options: {
    expectedNonce?: string;
    expectedAudience?: string;
    expectedDomain?: string;
  } = {}
): Promise<AuthVerifyResult> {
  try {
    // Decode payload
    let payload: AuthPayload;
    try {
      payload = JSON.parse(Buffer.from(base64urlToBytes(payloadEncoded)).toString());
    } catch {
      return { valid: false, reason: 'Invalid payload encoding' };
    }

    // Verify payload fields
    if (payload.did !== did) {
      return { valid: false, reason: 'DID mismatch in payload' };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return { valid: false, reason: 'Signature has expired' };
    }

    // Verify expected values
    if (options.expectedNonce && payload.nonce !== options.expectedNonce) {
      return { valid: false, reason: 'Nonce mismatch' };
    }

    if (options.expectedAudience && payload.aud !== options.expectedAudience) {
      return { valid: false, reason: 'Audience mismatch' };
    }

    if (options.expectedDomain && payload.domain !== options.expectedDomain) {
      return { valid: false, reason: 'Domain mismatch' };
    }

    // Get public key from DID
    let publicKey: Uint8Array;
    try {
      publicKey = didKeyToPublicKey(did);
    } catch (error) {
      return { valid: false, reason: `Invalid DID: ${error}` };
    }

    // Verify signature
    const signatureBytes = base64urlToBytes(signature);
    const valid = await verify(Buffer.from(payloadEncoded), signatureBytes, publicKey);

    if (!valid) {
      return { valid: false, reason: 'Invalid signature' };
    }

    return { valid: true, payload };
  } catch (error) {
    return { valid: false, reason: `Verification error: ${error}` };
  }
}
