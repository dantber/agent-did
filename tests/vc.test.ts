import {
  createOwnershipCredential,
  createCapabilityCredential,
  signCredential,
  verifyCredential,
  decodeCredential,
} from '../src/vc';
import { generateKeyPair } from '../src/crypto';
import { publicKeyToDidKey } from '../src/did';

describe('Verifiable Credentials', () => {
  let ownerKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array };
  let agentKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array };
  let ownerDid: string;
  let agentDid: string;

  beforeEach(async () => {
    ownerKeyPair = await generateKeyPair();
    agentKeyPair = await generateKeyPair();
    ownerDid = publicKeyToDidKey(ownerKeyPair.publicKey);
    agentDid = publicKeyToDidKey(agentKeyPair.publicKey);
  });

  describe('createOwnershipCredential', () => {
    it('should create a valid ownership credential', () => {
      const vc = createOwnershipCredential(ownerDid, agentDid, { name: 'Test Agent' });

      expect(vc.type).toContain('VerifiableCredential');
      expect(vc.type).toContain('AgentOwnershipCredential');
      expect(vc.issuer).toBe(ownerDid);
      expect(vc.credentialSubject.id).toBe(agentDid);
      expect(vc.credentialSubject.owner).toBe(ownerDid);
      expect(vc.credentialSubject.name).toBe('Test Agent');
      expect(vc.validFrom).toBeDefined();
    });
  });

  describe('createCapabilityCredential', () => {
    it('should create a valid capability credential', () => {
      const scopes = ['read', 'write'];
      const vc = createCapabilityCredential(ownerDid, agentDid, scopes, {
        audience: 'https://agent-did.xyz',
        expires: '2025-12-31T23:59:59Z',
      });

      expect(vc.type).toContain('VerifiableCredential');
      expect(vc.type).toContain('AgentCapabilityCredential');
      expect(vc.issuer).toBe(ownerDid);
      expect(vc.credentialSubject.id).toBe(agentDid);
      expect(vc.credentialSubject.scopes).toEqual(scopes);
      expect(vc.credentialSubject.audience).toBe('https://agent-did.xyz');
      expect(vc.validUntil).toBe('2025-12-31T23:59:59Z');
    });

    it('should create capability without optional fields', () => {
      const scopes = ['admin'];
      const vc = createCapabilityCredential(ownerDid, agentDid, scopes);

      expect(vc.credentialSubject.scopes).toEqual(scopes);
      expect(vc.credentialSubject.audience).toBeUndefined();
      expect(vc.validUntil).toBeUndefined();
    });
  });

  describe('signCredential and verifyCredential', () => {
    it('should sign and verify an ownership credential', async () => {
      const vc = createOwnershipCredential(ownerDid, agentDid);
      const jwt = await signCredential(vc, ownerKeyPair.privateKey, ownerKeyPair.publicKey);

      expect(jwt.split('.')).toHaveLength(3);

      const result = await verifyCredential(jwt);
      expect(result.valid).toBe(true);
      expect(result.payload?.iss).toBe(ownerDid);
      expect(result.payload?.sub).toBe(agentDid);
    });

    it('should sign and verify a capability credential', async () => {
      const vc = createCapabilityCredential(ownerDid, agentDid, ['read', 'write']);
      const jwt = await signCredential(vc, ownerKeyPair.privateKey, ownerKeyPair.publicKey);

      const result = await verifyCredential(jwt);
      expect(result.valid).toBe(true);
      expect(result.payload?.vc.credentialSubject.scopes).toEqual(['read', 'write']);
    });

    it('should reject tampered credentials', async () => {
      const vc = createOwnershipCredential(ownerDid, agentDid);
      const jwt = await signCredential(vc, ownerKeyPair.privateKey, ownerKeyPair.publicKey);

      // Tamper with the JWT (modify payload)
      const parts = jwt.split('.');
      parts[1] = parts[1].slice(0, -1) + (parts[1].endsWith('A') ? 'B' : 'A');
      const tamperedJwt = parts.join('.');

      const result = await verifyCredential(tamperedJwt);
      expect(result.valid).toBe(false);
      expect(result.reason).toMatch(/Invalid (signature|JWT payload)/);
    });

    it('should reject expired credentials', async () => {
      const pastDate = new Date();
      pastDate.setFullYear(pastDate.getFullYear() - 1);

      const vc = createCapabilityCredential(ownerDid, agentDid, ['read'], {
        expires: pastDate.toISOString(),
      });

      const jwt = await signCredential(vc, ownerKeyPair.privateKey, ownerKeyPair.publicKey);
      const result = await verifyCredential(jwt);

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Credential has expired');
    });

    it('should reject credentials with wrong algorithm', async () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature';
      const result = await verifyCredential(jwt);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Unsupported algorithm');
    });

    it('should reject malformed JWT', async () => {
      const result = await verifyCredential('not.a.valid.jwt');
      expect(result.valid).toBe(false);
    });

    it('should verify with allowed issuers', async () => {
      const vc = createOwnershipCredential(ownerDid, agentDid);
      const jwt = await signCredential(vc, ownerKeyPair.privateKey, ownerKeyPair.publicKey);

      const result = await verifyCredential(jwt, { allowedIssuers: [ownerDid] });
      expect(result.valid).toBe(true);

      const result2 = await verifyCredential(jwt, { allowedIssuers: ['did:key:other'] });
      expect(result2.valid).toBe(false);
      expect(result2.reason).toBe('Issuer not allowed');
    });

    it('should enforce subject and audience expectations', async () => {
      const vc = createCapabilityCredential(ownerDid, agentDid, ['read'], {
        audience: 'https://agent-did.xyz',
      });
      const jwt = await signCredential(vc, ownerKeyPair.privateKey, ownerKeyPair.publicKey);

      const ok = await verifyCredential(jwt, {
        expectedSubject: agentDid,
        expectedAudience: 'https://agent-did.xyz',
      });
      expect(ok.valid).toBe(true);

      const badSubject = await verifyCredential(jwt, { expectedSubject: 'did:key:other' });
      expect(badSubject.valid).toBe(false);
      expect(badSubject.reason).toBe('Subject mismatch');

      const badAudience = await verifyCredential(jwt, { expectedAudience: 'https://wrong.agent-did.xyz' });
      expect(badAudience.valid).toBe(false);
      expect(badAudience.reason).toBe('Audience mismatch');
    });
  });

  describe('decodeCredential', () => {
    it('should decode a JWT without verifying', async () => {
      const vc = createOwnershipCredential(ownerDid, agentDid);
      const jwt = await signCredential(vc, ownerKeyPair.privateKey, ownerKeyPair.publicKey);

      const decoded = decodeCredential(jwt);
      expect(decoded).toBeDefined();
      expect(decoded?.payload?.iss).toBe(ownerDid);
      expect(decoded?.payload?.vc.type).toContain('AgentOwnershipCredential');
    });

    it('should return null for invalid JWT', () => {
      const decoded = decodeCredential('invalid');
      expect(decoded).toBeNull();
    });
  });
});
