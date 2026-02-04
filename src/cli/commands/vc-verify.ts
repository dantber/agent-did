import { Command } from 'commander';
import { verifyCredential, decodeCredential } from '../../vc';
import { getStorePath, outputJson } from '../utils';
import * as fs from 'fs';

export const vcVerifyCommand = new Command('verify')
  .description('Verify a verifiable credential from a file')
  .requiredOption('-f, --file <path>', 'Path to credential file (JWT)')
  .option('--issuer <did>', 'Expected issuer DID')
  .option('--subject <did>', 'Expected subject DID')
  .option('--audience <audience>', 'Expected audience')
  .option('--domain <domain>', 'Expected domain')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      // Read credential from file
      const fileContent = await fs.promises.readFile(options.file, 'utf-8');

      // Try to parse as JSON first (in case it contains { credential: jwt })
      let jwt: string;
      try {
        const parsed = JSON.parse(fileContent);
        jwt = parsed.credential || parsed.jwt || fileContent.trim();
      } catch {
        jwt = fileContent.trim();
      }

      // Verify the credential
      const result = await verifyCredential(jwt, {
        allowedIssuers: options.issuer ? [options.issuer] : undefined,
        expectedSubject: options.subject,
        expectedAudience: options.audience,
        expectedDomain: options.domain,
      });

      if (result.valid && result.payload) {
        const decoded = decodeCredential(jwt);
        const credential = decoded?.payload?.vc;
        const issuer = decoded?.payload?.iss;

        const output = {
          valid: true,
          issuer: issuer || result.payload.iss,
          subject: result.payload.sub,
          issuedAt: new Date(result.payload.iat * 1000).toISOString(),
          ...(result.payload.exp && {
            expiresAt: new Date(result.payload.exp * 1000).toISOString(),
          }),
          credential,
        };

        if (options.json) {
          console.log(outputJson(output));
        } else {
          console.log('\n✓ Credential is valid');
          console.log(`\nIssuer: ${result.payload.iss}`);
          console.log(`Subject: ${result.payload.sub}`);
          console.log(`Issued: ${output.issuedAt}`);
          if (output.expiresAt) {
            console.log(`Expires: ${output.expiresAt}`);
          }
        }
      } else {
        const output = {
          valid: false,
          reason: result.reason,
        };

        if (options.json) {
          console.log(outputJson(output));
        } else {
          console.log('\n✗ Credential is invalid');
          console.log(`Reason: ${result.reason}`);
          process.exit(1);
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
