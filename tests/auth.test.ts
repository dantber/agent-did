import { createAuthPayload, signAuthChallenge, verifyAuthChallenge } from '../src/crypto/auth';
import { generateKeyPair } from '../src/crypto';
import { publicKeyToDidKey } from '../src/did';

describe('Auth signing', () => {
  let keyPair: { publicKey: Uint8Array; privateKey: Uint8Array };
  let did: string;

  beforeEach(async () => {
    keyPair = await generateKeyPair();
    did = publicKeyToDidKey(keyPair.publicKey);
  });

  describe('createAuthPayload', () => {
    it('should create a valid auth payload', () => {
      const payload = createAuthPayload(did, 'challenge-123');

      expect(payload.did).toBe(did);
      expect(payload.nonce).toBe('challenge-123');
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
      expect(payload.exp).toBeGreaterThan(payload.iat);
    });

    it('should include optional fields', () => {
      const payload = createAuthPayload(did, 'challenge-123', {
        audience: 'https://agent-did.xyz',
        domain: 'agent-did.xyz',
        expiresIn: 300,
      });

      expect(payload.aud).toBe('https://agent-did.xyz');
      expect(payload.domain).toBe('agent-did.xyz');
    });
  });

  describe('signAuthChallenge and verifyAuthChallenge', () => {
    it('should sign and verify a challenge', async () => {
      const result = await signAuthChallenge(did, keyPair.privateKey, keyPair.publicKey, 'test-challenge');

      expect(result.did).toBe(did);
      expect(result.alg).toBe('EdDSA');
      expect(result.signature).toBeDefined();
      expect(result.payloadEncoded).toBeDefined();

      const verifyResult = await verifyAuthChallenge(did, result.payloadEncoded, result.signature);
      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.payload?.nonce).toBe('test-challenge');
    });

    it('should verify with expected nonce', async () => {
      const result = await signAuthChallenge(did, keyPair.privateKey, keyPair.publicKey, 'specific-nonce');

      const verifyResult = await verifyAuthChallenge(did, result.payloadEncoded, result.signature, {
        expectedNonce: 'specific-nonce',
      });
      expect(verifyResult.valid).toBe(true);

      const verifyResult2 = await verifyAuthChallenge(
        did,
        result.payloadEncoded,
        result.signature,
        {
          expectedNonce: 'wrong-nonce',
        }
      );
      expect(verifyResult2.valid).toBe(false);
      expect(verifyResult2.reason).toBe('Nonce mismatch');
    });

    it('should verify with expected audience and domain', async () => {
      const result = await signAuthChallenge(did, keyPair.privateKey, keyPair.publicKey, 'challenge', {
        audience: 'agent-did.xyz',
        domain: 'agent-did.xyz',
      });

      const verifyResult = await verifyAuthChallenge(did, result.payloadEncoded, result.signature, {
        expectedAudience: 'agent-did.xyz',
        expectedDomain: 'agent-did.xyz',
      });
      expect(verifyResult.valid).toBe(true);

      const verifyResult2 = await verifyAuthChallenge(
        did,
        result.payloadEncoded,
        result.signature,
        {
          expectedAudience: 'wrong.com',
        }
      );
      expect(verifyResult2.valid).toBe(false);
      expect(verifyResult2.reason).toBe('Audience mismatch');
    });

    it('should reject expired signatures', async () => {
      const result = await signAuthChallenge(did, keyPair.privateKey, keyPair.publicKey, 'challenge', {
        expiresIn: 1, // 1 second
      });

      // Wait for expiration (add buffer for test stability)
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const verifyResult = await verifyAuthChallenge(did, result.payloadEncoded, result.signature);
      expect(verifyResult.valid).toBe(false);
    });

    it('should reject wrong DID', async () => {
      const otherKeyPair = await generateKeyPair();
      const otherDid = publicKeyToDidKey(otherKeyPair.publicKey);

      const result = await signAuthChallenge(did, keyPair.privateKey, keyPair.publicKey, 'challenge');

      const verifyResult = await verifyAuthChallenge(
        otherDid,
        result.payloadEncoded,
        result.signature
      );
      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.reason).toBe('DID mismatch in payload');
    });

    it('should reject invalid signatures', async () => {
      const result = await signAuthChallenge(did, keyPair.privateKey, keyPair.publicKey, 'challenge');

      // Modify signature in the middle to ensure it affects the decoded bytes
      // Changing a character in the middle guarantees the signature is invalidated
      const midPoint = Math.floor(result.signature.length / 2);
      const midChar = result.signature.charAt(midPoint);
      const newChar = midChar === 'A' ? 'B' : 'A';
      const modifiedSignature =
        result.signature.slice(0, midPoint) + newChar + result.signature.slice(midPoint + 1);

      const verifyResult = await verifyAuthChallenge(
        did,
        result.payloadEncoded,
        modifiedSignature
      );
      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.reason).toBe('Invalid signature');
    });

    it('should reject invalid payload encoding', async () => {
      const verifyResult = await verifyAuthChallenge(did, 'invalid-payload', 'signature');
      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.reason).toBe('Invalid payload encoding');
    });

    it('should produce different signatures for different nonces', async () => {
      const result1 = await signAuthChallenge(did, keyPair.privateKey, keyPair.publicKey, 'nonce-1');
      const result2 = await signAuthChallenge(did, keyPair.privateKey, keyPair.publicKey, 'nonce-2');

      expect(result1.signature).not.toBe(result2.signature);
      expect(result1.payload.nonce).toBe('nonce-1');
      expect(result2.payload.nonce).toBe('nonce-2');
    });
  });
});
