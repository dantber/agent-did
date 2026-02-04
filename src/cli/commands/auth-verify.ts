import { Command } from 'commander';
import { verifyAuthChallenge } from '../../crypto/auth';
import { outputJson } from '../utils';

export const authVerifyCommand = new Command('verify')
  .description('Verify an authentication signature')
  .requiredOption('--did <did>', 'DID that signed the challenge')
  .requiredOption('--payload <payload>', 'Base64url-encoded payload')
  .requiredOption('--signature <signature>', 'Base64url-encoded signature')
  .option('--nonce <nonce>', 'Expected nonce')
  .option('--audience <audience>', 'Expected audience')
  .option('--domain <domain>', 'Expected domain')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const result = await verifyAuthChallenge(options.did, options.payload, options.signature, {
        expectedNonce: options.nonce,
        expectedAudience: options.audience,
        expectedDomain: options.domain,
      });

      if (options.json) {
        console.log(outputJson(result));
        return;
      }

      if (result.valid) {
        console.log('\n✓ Signature is valid');
        if (result.payload) {
          console.log(`DID: ${result.payload.did}`);
          console.log(`Nonce: ${result.payload.nonce}`);
          if (result.payload.aud) console.log(`Audience: ${result.payload.aud}`);
          if (result.payload.domain) console.log(`Domain: ${result.payload.domain}`);
          console.log(`Issued: ${new Date(result.payload.iat * 1000).toISOString()}`);
          console.log(`Expires: ${new Date(result.payload.exp * 1000).toISOString()}`);
        }
      } else {
        console.log('\n✗ Signature is invalid');
        if (result.reason) console.log(`Reason: ${result.reason}`);
        process.exit(1);
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
