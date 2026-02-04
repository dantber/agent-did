import { Command } from 'commander';
import { signAuthChallenge } from '../../crypto/auth';
import { getExistingKeystore, outputJson } from '../utils';

export const authSignCommand = new Command('sign')
  .description('Sign an authentication challenge')
  .requiredOption('--did <did>', 'Agent DID to sign with')
  .requiredOption('--challenge <challenge>', 'Challenge string to sign')
  .option('--audience <audience>', 'Audience (server identifier)')
  .option('--domain <domain>', 'Domain (server domain)')
  .option('--expires-in <seconds>', 'Expiration time in seconds', '120')
  .option('-s, --store <path>', 'Keystore path')
  .option('--no-encryption', 'Use unencrypted keystore')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const keystore = await getExistingKeystore(options.store, options.noEncryption);

      // Validate identity
      const identity = await keystore.getIdentity(options.did);
      if (!identity) {
        throw new Error(`Identity not found: ${options.did}`);
      }

      // Get key pair
      const keyPair = await keystore.getKeyPair(options.did);

      // Sign the challenge
      const result = await signAuthChallenge(
        options.did,
        keyPair.privateKey,
        keyPair.publicKey,
        options.challenge,
        {
          audience: options.audience,
          domain: options.domain,
          expiresIn: parseInt(options.expiresIn, 10),
        }
      );

      if (options.json) {
        console.log(outputJson(result));
      } else {
        console.log('\n✓ Challenge signed successfully');
        console.log('\n=== Signature Result ===\n');
        console.log(`DID:         ${result.did}`);
        console.log(`Key ID:      ${result.kid}`);
        console.log(`Algorithm:   ${result.alg}`);
        console.log(`Created:     ${result.createdAt}`);
        console.log(`Expires:     ${result.expiresAt}`);
        console.log(`\n=== Payload (base64url) ===`);
        console.log(result.payloadEncoded);
        console.log(`\n=== Signature (base64url) ===`);
        console.log(result.signature);
        console.log(`\n=== Full Response (for server) ===\n`);
        console.log(outputJson(result));
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
