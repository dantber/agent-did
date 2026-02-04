import {
  generateKeyPair,
  sign,
  verify,
  bytesToBase64url,
  base64urlToBytes,
  bytesToHex,
  hexToBytes,
} from '../src/crypto';

describe('Crypto utilities', () => {
  describe('Key generation', () => {
    it('should generate a valid Ed25519 key pair', async () => {
      const keyPair = await generateKeyPair();

      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(32);
      expect(keyPair.privateKey.length).toBe(32);
    });

    it('should generate different keys each time', async () => {
      const keyPair1 = await generateKeyPair();
      const keyPair2 = await generateKeyPair();

      expect(Buffer.from(keyPair1.publicKey).toString('hex')).not.toBe(
        Buffer.from(keyPair2.publicKey).toString('hex')
      );
    });
  });

  describe('Signing and verification', () => {
    it('should sign and verify a message', async () => {
      const keyPair = await generateKeyPair();
      const message = Buffer.from('Hello, World!');

      const signature = await sign(message, keyPair.privateKey, keyPair.publicKey);
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64);

      const isValid = await verify(message, signature, keyPair.publicKey);
      expect(isValid).toBe(true);
    });

    it('should reject invalid signatures', async () => {
      const keyPair1 = await generateKeyPair();
      const keyPair2 = await generateKeyPair();
      const message = Buffer.from('Hello, World!');

      const signature = await sign(message, keyPair1.privateKey, keyPair1.publicKey);

      // Wrong public key
      const isValid = await verify(message, signature, keyPair2.publicKey);
      expect(isValid).toBe(false);
    });

    it('should reject tampered messages', async () => {
      const keyPair = await generateKeyPair();
      const message = Buffer.from('Hello, World!');
      const tamperedMessage = Buffer.from('Hello, World?');

      const signature = await sign(message, keyPair.privateKey, keyPair.publicKey);

      const isValid = await verify(tamperedMessage, signature, keyPair.publicKey);
      expect(isValid).toBe(false);
    });
  });

  describe('Encoding utilities', () => {
    it('should convert bytes to base64url and back', () => {
      const original = new Uint8Array([1, 2, 3, 255, 254, 253]);
      const encoded = bytesToBase64url(original);
      const decoded = base64urlToBytes(encoded);

      expect(Buffer.from(decoded).toString('hex')).toBe(Buffer.from(original).toString('hex'));
    });

    it('should convert bytes to hex and back', () => {
      const original = new Uint8Array([1, 2, 3, 255, 254, 253]);
      const encoded = bytesToHex(original);
      const decoded = hexToBytes(encoded);

      expect(Buffer.from(decoded).toString('hex')).toBe(Buffer.from(original).toString('hex'));
    });

    it('should handle base64url without padding', () => {
      // Test with a 1-byte input (needs padding in standard base64)
      const original = new Uint8Array([1]);
      const encoded = bytesToBase64url(original);
      expect(encoded).not.toContain('=');

      const decoded = base64urlToBytes(encoded);
      expect(decoded.length).toBe(1);
      expect(decoded[0]).toBe(1);
    });
  });
});
