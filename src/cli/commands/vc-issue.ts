import { Command } from 'commander';
import {
  createOwnershipCredential,
  createCapabilityCredential,
  createProfileCredential,
  signCredential,
  VerifiableCredential,
} from '../../vc';
import {
  getExistingKeystore,
  getStorePath,
  mapInvalidPassphraseError,
  outputJson,
  resolveCliPath,
  resolveRolePassphrase,
} from '../utils';
import { getCanonicalVcDir, storeJwtInCanonicalVcDir } from '../vc-files';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

type PersistResult = {
  credentialId?: string;
  keystoreRecordPath?: string;
  outputFilePath?: string;
  canonicalVcPath?: string;
};

const ownershipCommand = new Command('ownership')
  .description('Issue an ownership credential to an agent')
  .requiredOption('--issuer <did>', 'Owner DID (issuer)')
  .requiredOption('--subject <did>', 'Agent DID (subject)')
  .option(
    '-o, --out <file>',
    'Write JWT to this file (default: ~/.agent-did/vc/<auto>.jwt)'
  )
  .option('-s, --store <path>', 'Keystore path')
  .option('--owner-passphrase <passphrase>', 'Passphrase for decrypting issuer owner key')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--no-store', 'Do not store in keystore metadata or default VC directory')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storeOptionPath = resolveStoreOptionPath(options.store);
      const storePath = getStorePath(storeOptionPath);
      const shouldStore = shouldPersistCredential(options.store);
      const noEncryption = options.encryption === false;
      const ownerPassphrase = await resolveRolePassphrase({
        role: 'owner',
        purpose: 'decrypt',
        noEncryption,
        passphraseFlagValue: options.ownerPassphrase,
        passphraseFlagName: '--owner-passphrase',
      });
      const keystore = await getExistingKeystore(storeOptionPath, noEncryption, ownerPassphrase);

      const issuer = await keystore.getIdentity(options.issuer);
      if (!issuer) {
        throw new Error(`Issuer not found: ${options.issuer}`);
      }
      if (issuer.type !== 'owner') {
        throw new Error(`Issuer must be an owner: ${options.issuer}`);
      }

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

      const issuerKeyPair = await keystore.getKeyPair(options.issuer).catch((error) => {
        throw mapInvalidPassphraseError(error, 'owner', '--owner-passphrase');
      });

      const credential = createOwnershipCredential(options.issuer, options.subject, {
        name: subject.name,
      });
      const jwt = await signCredential(
        credential,
        issuerKeyPair.privateKey,
        issuerKeyPair.publicKey
      );

      const persisted = await persistIssuedCredential({
        storePath,
        shouldStore,
        outPath: options.out,
        credential,
        jwt,
        prefix: 'ownership',
        saveMetadata: async (id) => keystore.storeCredential(id, { jwt, credential }),
      });

      const output = {
        credential: jwt,
        stored: persisted.credentialId !== undefined,
        credentialId: persisted.credentialId,
        outputFile: persisted.outputFilePath,
        vcFile: persisted.canonicalVcPath,
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log('\n✓ Ownership credential issued successfully');
        printStorageSummary(persisted);
        console.log(`\nIssuer:  ${issuer.name} (${options.issuer})`);
        console.log(`Subject: ${subject.name} (${options.subject})`);
        if (persisted.credentialId) {
          console.log('\nView with: agent-did vc list');
        }
        if (!persisted.outputFilePath) {
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
  .option(
    '-o, --out <file>',
    'Write JWT to this file (default: ~/.agent-did/vc/<auto>.jwt)'
  )
  .option('-s, --store <path>', 'Keystore path')
  .option('--owner-passphrase <passphrase>', 'Passphrase for decrypting issuer owner key')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--no-store', 'Do not store in keystore metadata or default VC directory')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storeOptionPath = resolveStoreOptionPath(options.store);
      const storePath = getStorePath(storeOptionPath);
      const shouldStore = shouldPersistCredential(options.store);
      const noEncryption = options.encryption === false;
      const ownerPassphrase = await resolveRolePassphrase({
        role: 'owner',
        purpose: 'decrypt',
        noEncryption,
        passphraseFlagValue: options.ownerPassphrase,
        passphraseFlagName: '--owner-passphrase',
      });
      const keystore = await getExistingKeystore(storeOptionPath, noEncryption, ownerPassphrase);

      const issuer = await keystore.getIdentity(options.issuer);
      if (!issuer) {
        throw new Error(`Issuer not found: ${options.issuer}`);
      }
      if (issuer.type !== 'owner') {
        throw new Error(`Issuer must be an owner: ${options.issuer}`);
      }

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

      const scopes = options.scopes
        .split(',')
        .map((scope: string) => scope.trim())
        .filter((scope: string) => scope.length > 0);
      if (scopes.length === 0) {
        throw new Error('At least one scope is required');
      }

      const issuerKeyPair = await keystore.getKeyPair(options.issuer).catch((error) => {
        throw mapInvalidPassphraseError(error, 'owner', '--owner-passphrase');
      });

      const credential = createCapabilityCredential(options.issuer, options.subject, scopes, {
        audience: options.audience,
        expires: options.expires,
      });
      const jwt = await signCredential(
        credential,
        issuerKeyPair.privateKey,
        issuerKeyPair.publicKey
      );

      const persisted = await persistIssuedCredential({
        storePath,
        shouldStore,
        outPath: options.out,
        credential,
        jwt,
        prefix: 'capability',
        saveMetadata: async (id) => keystore.storeCredential(id, { jwt, credential }),
      });

      const output = {
        credential: jwt,
        stored: persisted.credentialId !== undefined,
        credentialId: persisted.credentialId,
        outputFile: persisted.outputFilePath,
        vcFile: persisted.canonicalVcPath,
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log('\n✓ Capability credential issued successfully');
        printStorageSummary(persisted);
        console.log(`\nIssuer:  ${issuer.name} (${options.issuer})`);
        console.log(`Subject: ${subject.name} (${options.subject})`);
        console.log(`Scopes:  ${scopes.join(', ')}`);
        if (options.expires) {
          console.log(`Expires: ${options.expires}`);
        }
        if (persisted.credentialId) {
          console.log('\nView with: agent-did vc list');
        }
        if (!persisted.outputFilePath) {
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
  .option(
    '--categories <categories>',
    'Comma-separated list of categories (e.g., ai,assistant,support)'
  )
  .option(
    '-o, --out <file>',
    'Write JWT to this file (default: ~/.agent-did/vc/<auto>.jwt)'
  )
  .option('-s, --store <path>', 'Keystore path')
  .option('--agent-passphrase <passphrase>', 'Passphrase for decrypting agent key')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--no-store', 'Do not store in keystore metadata or default VC directory')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storeOptionPath = resolveStoreOptionPath(options.store);
      const storePath = getStorePath(storeOptionPath);
      const shouldStore = shouldPersistCredential(options.store);
      const noEncryption = options.encryption === false;
      const agentPassphrase = await resolveRolePassphrase({
        role: 'agent',
        purpose: 'decrypt',
        noEncryption,
        passphraseFlagValue: options.agentPassphrase,
        passphraseFlagName: '--agent-passphrase',
      });
      const keystore = await getExistingKeystore(storeOptionPath, noEncryption, agentPassphrase);

      const agent = await keystore.getIdentity(options.did);
      if (!agent) {
        throw new Error(`Agent not found: ${options.did}`);
      }
      if (agent.type !== 'agent') {
        throw new Error(`Identity must be an agent: ${options.did}`);
      }

      let categories: string[] | undefined;
      if (options.categories) {
        categories = options.categories
          .split(',')
          .map((category: string) => category.trim())
          .filter((category: string) => category.length > 0);
      }

      const agentKeyPair = await keystore.getKeyPair(options.did).catch((error) => {
        throw mapInvalidPassphraseError(error, 'agent', '--agent-passphrase');
      });

      const credential = createProfileCredential(options.did, {
        displayName: options.name || agent.name,
        description: options.description,
        categories,
      });
      const jwt = await signCredential(
        credential,
        agentKeyPair.privateKey,
        agentKeyPair.publicKey
      );

      const persisted = await persistIssuedCredential({
        storePath,
        shouldStore,
        outPath: options.out,
        credential,
        jwt,
        prefix: 'profile',
        saveMetadata: async (id) => keystore.storeCredential(id, { jwt, credential }),
      });

      const output = {
        credential: jwt,
        stored: persisted.credentialId !== undefined,
        credentialId: persisted.credentialId,
        outputFile: persisted.outputFilePath,
        vcFile: persisted.canonicalVcPath,
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log('\n✓ Profile credential issued successfully');
        printStorageSummary(persisted);
        console.log(`\nAgent:       ${agent.name} (${options.did})`);
        if (options.name) console.log(`Display Name: ${options.name}`);
        if (options.description) console.log(`Description:  ${options.description}`);
        if (categories && categories.length > 0) {
          console.log(`Categories:   ${categories.join(', ')}`);
        }
        if (persisted.credentialId) {
          console.log('\nView with: agent-did vc list');
        }
        if (!persisted.outputFilePath) {
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

export async function persistIssuedCredential(params: {
  storePath: string;
  shouldStore: boolean;
  outPath?: string;
  credential: VerifiableCredential;
  jwt: string;
  prefix: string;
  saveMetadata: (credentialId: string) => Promise<void>;
}): Promise<PersistResult> {
  const result: PersistResult = {};
  const canonicalVcDir = getCanonicalVcDir(params.storePath);

  if (params.shouldStore) {
    result.credentialId = `${params.prefix}-${crypto.randomUUID()}`;
    await params.saveMetadata(result.credentialId);
    result.keystoreRecordPath = path.join(
      params.storePath,
      'credentials',
      `${result.credentialId}.json`
    );
  }

  if (params.outPath) {
    result.outputFilePath = await writeJwtFile(resolveCliPath(params.outPath), params.jwt);
  }

  if (params.shouldStore) {
    if (
      result.outputFilePath &&
      pathIsWithinDirectory(result.outputFilePath, canonicalVcDir)
    ) {
      result.canonicalVcPath = result.outputFilePath;
    } else {
      result.canonicalVcPath = await storeJwtInCanonicalVcDir(
        params.storePath,
        params.jwt,
        params.credential.type,
        params.credential.credentialSubject.id
      );
    }
  }

  if (!result.outputFilePath && result.canonicalVcPath) {
    result.outputFilePath = result.canonicalVcPath;
  }

  return result;
}

async function writeJwtFile(filePath: string, jwt: string): Promise<string> {
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  await fs.promises.writeFile(filePath, `${jwt.trim()}\n`, 'utf-8');
  try {
    await fs.promises.chmod(filePath, 0o600);
  } catch {
    // Ignore permission errors on platforms that do not support chmod semantics.
  }
  return filePath;
}

function resolveStoreOptionPath(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function shouldPersistCredential(value: unknown): boolean {
  return value !== false;
}

function pathIsWithinDirectory(candidatePath: string, parentPath: string): boolean {
  const relative = path.relative(parentPath, candidatePath);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function printStorageSummary(result: PersistResult): void {
  if (result.keystoreRecordPath) {
    console.log(`✓ Stored metadata in keystore: ${result.keystoreRecordPath}`);
  }
  if (result.outputFilePath) {
    console.log(`✓ JWT file: ${result.outputFilePath}`);
  }
  if (
    result.canonicalVcPath &&
    result.outputFilePath &&
    result.canonicalVcPath !== result.outputFilePath
  ) {
    console.log(`✓ Also stored in default VC directory: ${result.canonicalVcPath}`);
  }
}
