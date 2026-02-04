import {
  publicKeyToDidKey,
  didKeyToPublicKey,
  deriveDidDocument,
  getPublicKeyHex,
  isValidDidKey,
  getVerificationMethodId,
} from '../src/did';
import { generateKeyPair } from '../src/crypto';

describe('DID operations', () => {
  describe('publicKeyToDidKey', () => {
    it('should convert public key to did:key', async () => {
      const keyPair = await generateKeyPair();
      const did = publicKeyToDidKey(keyPair.publicKey);

      expect(did.startsWith('did:key:z')).toBe(true);
      expect(did.length).toBeGreaterThan(50);
    });

    it('should produce consistent results', async () => {
      const keyPair = await generateKeyPair();
      const did1 = publicKeyToDidKey(keyPair.publicKey);
      const did2 = publicKeyToDidKey(keyPair.publicKey);

      expect(did1).toBe(did2);
    });
  });

  describe('didKeyToPublicKey', () => {
    it('should extract public key from did:key', async () => {
      const keyPair = await generateKeyPair();
      const did = publicKeyToDidKey(keyPair.publicKey);
      const extractedPublicKey = didKeyToPublicKey(did);

      expect(Buffer.from(extractedPublicKey).toString('hex')).toBe(
        Buffer.from(keyPair.publicKey).toString('hex')
      );
    });

    it('should throw on invalid did:key', () => {
      expect(() => didKeyToPublicKey('invalid')).toThrow('Invalid DID format');
      expect(() => didKeyToPublicKey('did:key:')).toThrow(); // Will throw for empty key
      expect(() => didKeyToPublicKey('did:key:x')).toThrow('Invalid multibase');
    });
  });

  describe('deriveDidDocument', () => {
    it('should derive a valid DID Document', async () => {
      const keyPair = await generateKeyPair();
      const did = publicKeyToDidKey(keyPair.publicKey);
      const doc = deriveDidDocument(did);

      expect(doc.id).toBe(did);
      expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
      expect(doc.verificationMethod).toHaveLength(1);
      expect(doc.verificationMethod[0].controller).toBe(did);
      expect(doc.verificationMethod[0].type).toBe('Ed25519VerificationKey2020');
      expect(doc.authentication).toHaveLength(1);
      expect(doc.assertionMethod).toHaveLength(1);
    });
  });

  describe('getPublicKeyHex', () => {
    it('should return hex representation of public key', async () => {
      const keyPair = await generateKeyPair();
      const did = publicKeyToDidKey(keyPair.publicKey);
      const hex = getPublicKeyHex(did);

      expect(hex).toBe(Buffer.from(keyPair.publicKey).toString('hex'));
      expect(hex.length).toBe(64); // 32 bytes = 64 hex chars
    });
  });

  describe('isValidDidKey', () => {
    it('should validate correct did:key', async () => {
      const keyPair = await generateKeyPair();
      const did = publicKeyToDidKey(keyPair.publicKey);

      expect(isValidDidKey(did)).toBe(true);
    });

    it('should reject invalid did:key', () => {
      expect(isValidDidKey('')).toBe(false);
      expect(isValidDidKey('did:web:example.com')).toBe(false);
      expect(isValidDidKey('not-a-did')).toBe(false);
      expect(isValidDidKey(null as unknown as string)).toBe(false);
      expect(isValidDidKey(undefined as unknown as string)).toBe(false);
    });
  });

  describe('getVerificationMethodId', () => {
    it('should generate correct verification method ID', async () => {
      const keyPair = await generateKeyPair();
      const did = publicKeyToDidKey(keyPair.publicKey);
      const vmId = getVerificationMethodId(did);

      expect(vmId.startsWith(did)).toBe(true);
      expect(vmId.includes('#')).toBe(true);
    });
  });
});
