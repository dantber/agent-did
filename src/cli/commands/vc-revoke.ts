import { Command } from 'commander';
import { RevocationRegistry } from '../../revocation';
import { getExistingKeystore, getStorePath, outputJson } from '../utils';
import { decodeCredential } from '../../vc';
import * as fs from 'fs';

export const vcRevokeCommand = new Command('revoke')
  .description('Revoke a verifiable credential')
  .requiredOption('-f, --file <path>', 'Path to credential file to revoke')
  .option('--reason <reason>', 'Reason for revocation')
  .option('-s, --store <path>', 'Keystore path')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const keystore = await getExistingKeystore(options.store);
      const registry = new RevocationRegistry(storePath);
      await registry.init();

      // Read credential from file
      const fileContent = await fs.promises.readFile(options.file, 'utf-8');

      // Try to parse as JSON first
      let jwt: string;
      let credentialId: string;
      try {
        const parsed = JSON.parse(fileContent);
        jwt = parsed.credential || parsed.jwt || fileContent.trim();
        credentialId = parsed.credentialId || parsed.id;
      } catch {
        jwt = fileContent.trim();
        credentialId = '';
      }

      // Decode credential to get details
      const decoded = decodeCredential(jwt);
      if (!decoded || !decoded.payload) {
        throw new Error('Invalid credential format');
      }

      const issuerDid = decoded.payload.iss;
      const subjectDid = decoded.payload.sub;

      // Verify issuer has access
      const issuerIdentity = await keystore.getIdentity(issuerDid);
      if (!issuerIdentity) {
        throw new Error(`You don't have access to revoke credentials for issuer: ${issuerDid}`);
      }

      // Generate credential ID if not provided
      if (!credentialId) {
        credentialId = registry.generateStatusId(jwt);
      }

      // Revoke the credential
      await registry.revoke(credentialId, issuerDid, subjectDid, options.reason);

      const output = {
        credentialId,
        issuer: issuerDid,
        subject: subjectDid,
        revokedAt: new Date().toISOString(),
        reason: options.reason,
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log('\n✓ Credential revoked successfully');
        console.log(`Credential ID: ${credentialId}`);
        console.log(`Issuer: ${issuerDid}`);
        console.log(`Subject: ${subjectDid}`);
        if (options.reason) {
          console.log(`Reason: ${options.reason}`);
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

export const vcCheckRevocationCommand = new Command('check-revocation')
  .description('Check if a credential has been revoked')
  .requiredOption('-f, --file <path>', 'Path to credential file')
  .option('-s, --store <path>', 'Keystore path')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const registry = new RevocationRegistry(storePath);

      // Read credential
      const fileContent = await fs.promises.readFile(options.file, 'utf-8');
      let jwt: string;
      let credentialId: string;

      try {
        const parsed = JSON.parse(fileContent);
        jwt = parsed.credential || parsed.jwt || fileContent.trim();
        credentialId = parsed.credentialId || parsed.id;
      } catch {
        jwt = fileContent.trim();
        credentialId = '';
      }

      const decoded = decodeCredential(jwt);
      if (!decoded || !decoded.payload) {
        throw new Error('Invalid credential format');
      }

      const issuerDid = decoded.payload.iss;

      if (!credentialId) {
        credentialId = registry.generateStatusId(jwt);
      }

      const status = await registry.getStatus(credentialId, issuerDid);

      const output = {
        credentialId,
        issuer: issuerDid,
        revoked: status !== null,
        ...(status && {
          revokedAt: status.revokedAt,
          reason: status.reason,
        }),
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        if (status) {
          console.log('\n✗ Credential has been revoked');
          console.log(`Revoked at: ${status.revokedAt}`);
          if (status.reason) {
            console.log(`Reason: ${status.reason}`);
          }
        } else {
          console.log('\n✓ Credential is valid (not revoked)');
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
