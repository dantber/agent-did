import { Command } from 'commander';
import { createOwnershipCredential, createCapabilityCredential, createProfileCredential, signCredential } from '../../vc';
import {
  getExistingKeystore,
  getStorePath,
  mapInvalidPassphraseError,
  outputJson,
  resolveRolePassphrase,
} from '../utils';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const ownershipCommand = new Command('ownership')
  .description('Issue an ownership credential to an agent')
  .requiredOption('--issuer <did>', 'Owner DID (issuer)')
  .requiredOption('--subject <did>', 'Agent DID (subject)')
  .option('-o, --out <file>', 'Output file path')
  .option('-s, --store <path>', 'Keystore path')
  .option('--owner-passphrase <passphrase>', 'Passphrase for decrypting issuer owner key')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--no-store', 'Do not store credential in keystore')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const noEncryption = options.encryption === false;
      const ownerPassphrase = await resolveRolePassphrase({
        role: 'owner',
        purpose: 'decrypt',
        noEncryption,
        passphraseFlagValue: options.ownerPassphrase,
        passphraseFlagName: '--owner-passphrase',
      });
      const keystore = await getExistingKeystore(options.store, noEncryption, ownerPassphrase);

      // Validate issuer
      const issuer = await keystore.getIdentity(options.issuer);
      if (!issuer) {
        throw new Error(`Issuer not found: ${options.issuer}`);
      }
      if (issuer.type !== 'owner') {
        throw new Error(`Issuer must be an owner: ${options.issuer}`);
      }

      // Validate subject
      const subject = await keystore.getIdentity(options.subject);
      if (!subject) {
        throw new Error(`Subject not found: ${options.subject}`);
      }
      if (subject.type !== 'agent') {
        throw new Error(`Subject must be an agent: ${options.subject}`);
      }
      if (subject.ownerDid !== options.issuer) {
        throw new Error(`Subject is not owned by issuer: ${options.issuer}`);
      }

      // Get issuer's key pair
      const issuerKeyPair = await keystore.getKeyPair(options.issuer).catch((error) => {
        throw mapInvalidPassphraseError(error, 'owner', '--owner-passphrase');
      });

      // Create and sign credential
      const credential = createOwnershipCredential(options.issuer, options.subject, {
        name: subject.name,
      });

      const jwt = await signCredential(credential, issuerKeyPair.privateKey, issuerKeyPair.publicKey);

      // Store credential with secure random ID (unless --no-store)
      let credId: string | undefined;
      if (options.store !== false) {
        credId = `ownership-${crypto.randomUUID()}`;
        await keystore.storeCredential(credId, { jwt, credential });
      }

      const output = {
        credential: jwt,
        stored: credId !== undefined,
        credentialId: credId,
      };

      if (options.out) {
        await fs.promises.writeFile(options.out, JSON.stringify(output, null, 2));
        console.log(`Credential written to: ${options.out}`);
      }

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log('\n✓ Ownership credential issued successfully');
        if (credId) {
          const credPath = path.join(storePath, 'credentials', `${credId}.json`);
          console.log(`✓ Stored in keystore: ${credPath}`);
        }
        console.log(`\nIssuer:  ${issuer.name} (${options.issuer})`);
        console.log(`Subject: ${subject.name} (${options.subject})`);
        if (credId) {
          console.log(`\nView with: agent-did vc list`);
        }

        if (!options.out) {
          console.log(`\nCredential (JWT):\n${jwt}`);
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

const capabilityCommand = new Command('capability')
  .description('Issue a capability credential to an agent')
  .requiredOption('--issuer <did>', 'Owner DID (issuer)')
  .requiredOption('--subject <did>', 'Agent DID (subject)')
  .requiredOption('--scopes <scopes>', 'Comma-separated list of scopes (e.g., read,write)')
  .option('--audience <audience>', 'Audience for this credential')
  .option('--expires <date>', 'Expiration date (ISO 8601)')
  .option('-o, --out <file>', 'Output file path')
  .option('-s, --store <path>', 'Keystore path')
  .option('--owner-passphrase <passphrase>', 'Passphrase for decrypting issuer owner key')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--no-store', 'Do not store credential in keystore')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const noEncryption = options.encryption === false;
      const ownerPassphrase = await resolveRolePassphrase({
        role: 'owner',
        purpose: 'decrypt',
        noEncryption,
        passphraseFlagValue: options.ownerPassphrase,
        passphraseFlagName: '--owner-passphrase',
      });
      const keystore = await getExistingKeystore(options.store, noEncryption, ownerPassphrase);

      // Validate issuer
      const issuer = await keystore.getIdentity(options.issuer);
      if (!issuer) {
        throw new Error(`Issuer not found: ${options.issuer}`);
      }
      if (issuer.type !== 'owner') {
        throw new Error(`Issuer must be an owner: ${options.issuer}`);
      }

      // Validate subject
      const subject = await keystore.getIdentity(options.subject);
      if (!subject) {
        throw new Error(`Subject not found: ${options.subject}`);
      }
      if (subject.type !== 'agent') {
        throw new Error(`Subject must be an agent: ${options.subject}`);
      }
      if (subject.ownerDid !== options.issuer) {
        throw new Error(`Subject is not owned by issuer: ${options.issuer}`);
      }

      // Parse scopes
      const scopes = options.scopes
        .split(',')
        .map((s: string) => s.trim())
        .filter((s: string) => s.length > 0);
      if (scopes.length === 0) {
        throw new Error('At least one scope is required');
      }

      // Get issuer's key pair
      const issuerKeyPair = await keystore.getKeyPair(options.issuer).catch((error) => {
        throw mapInvalidPassphraseError(error, 'owner', '--owner-passphrase');
      });

      // Create and sign credential
      const credential = createCapabilityCredential(options.issuer, options.subject, scopes, {
        audience: options.audience,
        expires: options.expires,
      });

      const jwt = await signCredential(credential, issuerKeyPair.privateKey, issuerKeyPair.publicKey);

      // Store credential with secure random ID (unless --no-store)
      let credId: string | undefined;
      if (options.store !== false) {
        credId = `capability-${crypto.randomUUID()}`;
        await keystore.storeCredential(credId, { jwt, credential });
      }

      const output = {
        credential: jwt,
        stored: credId !== undefined,
        credentialId: credId,
      };

      if (options.out) {
        await fs.promises.writeFile(options.out, JSON.stringify(output, null, 2));
        console.log(`Credential written to: ${options.out}`);
      }

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log('\n✓ Capability credential issued successfully');
        if (credId) {
          const credPath = path.join(storePath, 'credentials', `${credId}.json`);
          console.log(`✓ Stored in keystore: ${credPath}`);
        }
        console.log(`\nIssuer:  ${issuer.name} (${options.issuer})`);
        console.log(`Subject: ${subject.name} (${options.subject})`);
        console.log(`Scopes:  ${scopes.join(', ')}`);
        if (options.expires) {
          console.log(`Expires: ${options.expires}`);
        }
        if (credId) {
          console.log(`\nView with: agent-did vc list`);
        }

        if (!options.out) {
          console.log(`\nCredential (JWT):\n${jwt}`);
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

const profileCommand = new Command('profile')
  .description('Issue a profile credential (self-issued by agent)')
  .requiredOption('--did <did>', 'Agent DID (issuer and subject)')
  .option('--name <name>', 'Display name for the agent')
  .option('--description <description>', 'Description of the agent')
  .option('--categories <categories>', 'Comma-separated list of categories (e.g., ai,assistant,support)')
  .option('-o, --out <file>', 'Output file path')
  .option('-s, --store <path>', 'Keystore path')
  .option('--agent-passphrase <passphrase>', 'Passphrase for decrypting agent key')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--no-store', 'Do not store credential in keystore')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const noEncryption = options.encryption === false;
      const agentPassphrase = await resolveRolePassphrase({
        role: 'agent',
        purpose: 'decrypt',
        noEncryption,
        passphraseFlagValue: options.agentPassphrase,
        passphraseFlagName: '--agent-passphrase',
      });
      const keystore = await getExistingKeystore(options.store, noEncryption, agentPassphrase);

      // Validate agent
      const agent = await keystore.getIdentity(options.did);
      if (!agent) {
        throw new Error(`Agent not found: ${options.did}`);
      }
      if (agent.type !== 'agent') {
        throw new Error(`Identity must be an agent: ${options.did}`);
      }

      // Parse categories
      let categories: string[] | undefined;
      if (options.categories) {
        categories = options.categories
          .split(',')
          .map((s: string) => s.trim())
          .filter((s: string) => s.length > 0);
      }

      // Get agent's key pair
      const agentKeyPair = await keystore.getKeyPair(options.did).catch((error) => {
        throw mapInvalidPassphraseError(error, 'agent', '--agent-passphrase');
      });

      // Create and sign credential
      const credential = createProfileCredential(options.did, {
        displayName: options.name || agent.name,
        description: options.description,
        categories,
      });

      const jwt = await signCredential(credential, agentKeyPair.privateKey, agentKeyPair.publicKey);

      // Store credential with secure random ID (unless --no-store)
      let credId: string | undefined;
      if (options.store !== false) {
        credId = `profile-${crypto.randomUUID()}`;
        await keystore.storeCredential(credId, { jwt, credential });
      }

      const output = {
        credential: jwt,
        stored: credId !== undefined,
        credentialId: credId,
      };

      if (options.out) {
        await fs.promises.writeFile(options.out, JSON.stringify(output, null, 2));
        console.log(`Credential written to: ${options.out}`);
      }

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log('\n✓ Profile credential issued successfully');
        if (credId) {
          const credPath = path.join(storePath, 'credentials', `${credId}.json`);
          console.log(`✓ Stored in keystore: ${credPath}`);
        }
        console.log(`\nAgent:       ${agent.name} (${options.did})`);
        if (options.name) console.log(`Display Name: ${options.name}`);
        if (options.description) console.log(`Description:  ${options.description}`);
        if (categories && categories.length > 0) {
          console.log(`Categories:   ${categories.join(', ')}`);
        }
        if (credId) {
          console.log(`\nView with: agent-did vc list`);
        }

        if (!options.out) {
          console.log(`\nCredential (JWT):\n${jwt}`);
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

export const vcIssueCommand = new Command('issue')
  .description('Issue a verifiable credential')
  .addCommand(ownershipCommand)
  .addCommand(capabilityCommand)
  .addCommand(profileCommand);
