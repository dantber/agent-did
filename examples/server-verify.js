#!/usr/bin/env node

/**
 * Simple example showing how a server verifies signed messages from agent-did CLI
 *
 * Prerequisites:
 *   npm install agent-did-server
 *
 * Usage:
 *   # 1. Client signs a challenge using agent-did CLI:
 *   agent-did auth sign --did <your-did> --challenge "test-nonce-123" --audience "my-api" --json > signed.json
 *
 *   # 2. Server verifies the signature:
 *   node examples/server-verify.js signed.json
 */

import { readFileSync } from 'fs';
import { didKeyToPublicKey, verifySignature, base64UrlDecode } from 'agent-did-server';

async function verifySignedChallenge(signedDataPath) {
  try {
    // Read the signed data from CLI output
    const signedData = JSON.parse(readFileSync(signedDataPath, 'utf-8'));
    const { did, payloadEncoded, signature } = signedData;

    console.log('📋 Verifying signed challenge...\n');
    console.log('DID:', did);
    console.log('Payload (base64url):', payloadEncoded.substring(0, 50) + '...');
    console.log('Signature (base64url):', signature.substring(0, 50) + '...\n');

    // Step 1: Extract public key from DID
    console.log('Step 1: Extracting public key from DID...');
    const publicKey = didKeyToPublicKey(did);
    console.log('✓ Public key extracted (32 bytes)\n');

    // Step 2: Decode the payload to verify its contents
    console.log('Step 2: Decoding payload...');
    const payloadBytes = base64UrlDecode(payloadEncoded);
    const payload = JSON.parse(Buffer.from(payloadBytes).toString('utf-8'));
    console.log('✓ Payload decoded:');
    console.log('  - Nonce:', payload.nonce);
    console.log('  - DID:', payload.did);
    console.log('  - Audience:', payload.aud);
    console.log('  - Domain:', payload.domain);
    console.log('  - Issued at:', new Date(payload.iat * 1000).toISOString());
    console.log('  - Expires at:', new Date(payload.exp * 1000).toISOString());
    console.log();

    // Step 3: Verify the Ed25519 signature
    console.log('Step 3: Verifying Ed25519 signature...');
    const signatureBytes = base64UrlDecode(signature);
    const isValid = await verifySignature(payloadBytes, signatureBytes, publicKey);

    if (isValid) {
      console.log('✅ Signature is VALID!\n');

      // Step 4: Additional checks you might want to do
      console.log('Additional checks:');

      // Check if payload hasn't expired
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        console.log('⚠️  WARNING: Payload has expired');
      } else {
        console.log('✓ Payload is not expired');
      }

      // Check if DID in payload matches the signing DID
      if (payload.did !== did) {
        console.log('⚠️  WARNING: DID mismatch in payload');
      } else {
        console.log('✓ DID in payload matches signing DID');
      }

      console.log('\n🎉 Authentication successful! You can now issue a JWT for this DID.');

    } else {
      console.log('❌ Signature is INVALID!\n');
      console.log('This could mean:');
      console.log('  - The payload was tampered with');
      console.log('  - The signature was corrupted');
      console.log('  - The wrong DID was provided');
      process.exit(1);
    }

  } catch (error) {
    console.error('❌ Verification failed:', error.message);
    process.exit(1);
  }
}

// Check command line arguments
const signedDataPath = process.argv[2];
if (!signedDataPath) {
  console.error('Usage: node server-verify.js <path-to-signed.json>');
  console.error('\nExample workflow:');
  console.error('  1. Sign a challenge with CLI:');
  console.error('     agent-did auth sign --did <your-did> --challenge "test-123" --audience "my-api" --json > signed.json');
  console.error('  2. Verify on server:');
  console.error('     node server-verify.js signed.json');
  process.exit(1);
}

verifySignedChallenge(signedDataPath);
