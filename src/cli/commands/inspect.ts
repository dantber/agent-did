import { Command } from 'commander';
import { deriveDidDocument, getPublicKeyHex } from '../../did';
import { getExistingKeystore, outputJson, formatDate } from '../utils';

export const inspectCommand = new Command('inspect')
  .description('Inspect an identity by DID')
  .requiredOption('--did <did>', 'DID to inspect')
  .option('-s, --store <path>', 'Keystore path (default: ~/.agent-did)')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const keystore = await getExistingKeystore(options.store, options.encryption === false);
      const identity = await keystore.getIdentity(options.did);

      if (!identity) {
        throw new Error(`Identity not found: ${options.did}`);
      }

      const didDocument = deriveDidDocument(identity.did);
      const publicKeyHex = getPublicKeyHex(identity.did);

      const output = {
        did: identity.did,
        type: identity.type,
        name: identity.name,
        createdAt: identity.createdAt,
        ...(identity.ownerDid && { ownerDid: identity.ownerDid }),
        publicKeyHex,
        didDocument,
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log('\n=== Identity ===\n');
        console.log(`DID:       ${identity.did}`);
        console.log(`Type:      ${identity.type}`);
        console.log(`Name:      ${identity.name}`);
        console.log(`Created:   ${formatDate(identity.createdAt)}`);
        if (identity.ownerDid) {
          console.log(`Owner DID: ${identity.ownerDid}`);
        }
        console.log(`\nPublic Key (hex): ${publicKeyHex}`);
        console.log('\n=== DID Document ===\n');
        console.log(outputJson(didDocument));
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
