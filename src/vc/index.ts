import { sign, verify, bytesToBase64url, base64urlToBytes } from '../crypto';
import { didKeyToPublicKey } from '../did';

export type CredentialType = 'AgentOwnershipCredential' | 'AgentCapabilityCredential';

export interface CredentialSubject {
  id: string; // Agent DID
  [key: string]: unknown;
}

export interface VerifiableCredential {
  '@context': string | string[];
  type: string[];
  issuer: string; // Owner DID
  validFrom: string;
  credentialSubject: CredentialSubject;
  validUntil?: string;
}

export interface JWTPayload {
  iss: string;
  sub: string;
  iat: number;
  exp?: number;
  vc: VerifiableCredential;
}

export interface VerificationResult {
  valid: boolean;
  reason?: string;
  payload?: JWTPayload;
}

export interface VerificationExpectations {
  allowedIssuers?: string[];
  expectedSubject?: string;
  expectedAudience?: string;
  expectedDomain?: string;
}

const VC_CONTEXT = ['https://www.w3.org/ns/credentials/v2'];

/**
 * Create an ownership credential
 */
export function createOwnershipCredential(
  issuerDid: string,
  agentDid: string,
  options: { name?: string; createdAt?: string } = {}
): VerifiableCredential {
  return {
    '@context': VC_CONTEXT,
    type: ['VerifiableCredential', 'AgentOwnershipCredential'],
    issuer: issuerDid,
    validFrom: new Date().toISOString(),
    credentialSubject: {
      id: agentDid,
      owner: issuerDid,
      ...(options.name && { name: options.name }),
      ...(options.createdAt && { createdAt: options.createdAt }),
    },
  };
}

/**
 * Create a capability credential
 */
export function createCapabilityCredential(
  issuerDid: string,
  agentDid: string,
  scopes: string[],
  options: {
    audience?: string;
    limits?: Record<string, unknown>;
    expires?: string;
  } = {}
): VerifiableCredential {
  const credential: VerifiableCredential = {
    '@context': VC_CONTEXT,
    type: ['VerifiableCredential', 'AgentCapabilityCredential'],
    issuer: issuerDid,
    validFrom: new Date().toISOString(),
    credentialSubject: {
      id: agentDid,
      scopes,
      ...(options.audience && { audience: options.audience }),
      ...(options.limits && { limits: options.limits }),
    },
  };

  if (options.expires) {
    credential.validUntil = options.expires;
  }

  return credential;
}

/**
 * Sign a credential as JWT (JWS with EdDSA)
 */
export async function signCredential(
  credential: VerifiableCredential,
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const payload: JWTPayload = {
    iss: credential.issuer,
    sub: credential.credentialSubject.id,
    iat: now,
    vc: credential,
  };

  if (credential.validUntil) {
    payload.exp = Math.floor(new Date(credential.validUntil).getTime() / 1000);
  }

  // Create JWT header
  const header = {
    alg: 'EdDSA',
    typ: 'JWT',
    kid: `${credential.issuer}#${credential.issuer.split(':')[2]}`,
  };

  // Encode header and payload
  const encodedHeader = bytesToBase64url(Buffer.from(JSON.stringify(header)));
  const encodedPayload = bytesToBase64url(Buffer.from(JSON.stringify(payload)));

  // Create signing input
  const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);

  // Sign
  const signature = await sign(signingInput, privateKey, publicKey);
  const encodedSignature = bytesToBase64url(signature);

  // Return compact JWT
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

/**
 * Verify a JWT credential
 */
export async function verifyCredential(
  jwt: string,
  options: VerificationExpectations = {}
): Promise<VerificationResult> {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return { valid: false, reason: 'Invalid JWT format' };
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;

    // Decode header
    let header: { alg?: string; kid?: string };
    try {
      header = JSON.parse(Buffer.from(base64urlToBytes(encodedHeader)).toString());
    } catch {
      return { valid: false, reason: 'Invalid JWT header' };
    }

    if (header.alg !== 'EdDSA') {
      return { valid: false, reason: `Unsupported algorithm: ${header.alg}` };
    }

    // Decode payload
    let payload: JWTPayload;
    try {
      payload = JSON.parse(Buffer.from(base64urlToBytes(encodedPayload)).toString());
    } catch {
      return { valid: false, reason: 'Invalid JWT payload' };
    }

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false, reason: 'Credential has expired' };
    }

    // Check issuer
    if (options.allowedIssuers && !options.allowedIssuers.includes(payload.iss)) {
      return { valid: false, reason: 'Issuer not allowed' };
    }

    if (options.expectedSubject && payload.sub !== options.expectedSubject) {
      return { valid: false, reason: 'Subject mismatch' };
    }

    const credentialAudience = payload.vc.credentialSubject?.audience as string | undefined;
    if (options.expectedAudience && credentialAudience !== options.expectedAudience) {
      return { valid: false, reason: 'Audience mismatch' };
    }

    const credentialDomain = payload.vc.credentialSubject?.domain as string | undefined;
    if (options.expectedDomain && credentialDomain !== options.expectedDomain) {
      return { valid: false, reason: 'Domain mismatch' };
    }

    // Extract public key from issuer DID
    let publicKey: Uint8Array;
    try {
      publicKey = didKeyToPublicKey(payload.iss);
    } catch (error) {
      return { valid: false, reason: `Invalid issuer DID: ${error}` };
    }

    // Verify signature
    const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);
    const signature = base64urlToBytes(encodedSignature);

    const valid = await verify(signingInput, signature, publicKey);
    if (!valid) {
      return { valid: false, reason: 'Invalid signature' };
    }

    return { valid: true, payload };
  } catch (error) {
    return { valid: false, reason: `Verification error: ${error}` };
  }
}

/**
 * Decode a JWT without verifying (for inspection)
 */
export function decodeCredential(jwt: string): { header?: unknown; payload?: JWTPayload } | null {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload] = parts;
    const header = JSON.parse(Buffer.from(base64urlToBytes(encodedHeader)).toString());
    const payload = JSON.parse(Buffer.from(base64urlToBytes(encodedPayload)).toString());

    return { header, payload };
  } catch {
    return null;
  }
}
