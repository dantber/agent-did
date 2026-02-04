import { Command } from 'commander';
import { generateKeyPair } from '../../crypto';
import { publicKeyToDidKey } from '../../did';
import { getExistingKeystore, getStorePath, outputJson, outputTable } from '../utils';

export const createAgentCommand = new Command('agent')
  .description('Create a new agent identity linked to an owner')
  .requiredOption('-n, --name <name>', 'Name for the agent identity')
  .requiredOption('--owner <did>', 'Owner DID')
  .option('-s, --store <path>', 'Keystore path (default: ~/.agent-did)')
  .option('--no-encryption', 'Store keys unencrypted (NOT RECOMMENDED)')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);

      // Use existing keystore (owner should already exist)
      const keystore = await getExistingKeystore(options.store, options.encryption === false);
      await keystore.init();

      // Validate owner exists
      const ownerIdentity = await keystore.getIdentity(options.owner);
      if (!ownerIdentity) {
        throw new Error(`Owner identity not found: ${options.owner}`);
      }

      if (ownerIdentity.type !== 'owner') {
        throw new Error(`Specified DID is not an owner: ${options.owner}`);
      }

      // Generate key pair
      const keyPair = await generateKeyPair();
      const did = publicKeyToDidKey(keyPair.publicKey);

      // Create metadata
      const metadata = {
        did,
        type: 'agent' as const,
        name: options.name,
        ownerDid: options.owner,
        createdAt: new Date().toISOString(),
      };

      // Store identity
      await keystore.storeIdentity(metadata, keyPair);

      const output = {
        did,
        kid: `${did}#${did.split(':')[2]}`,
        name: options.name,
        type: 'agent',
        ownerDid: options.owner,
        ownerName: ownerIdentity.name,
        store: storePath,
        createdAt: metadata.createdAt,
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log(outputTable(output));
        console.log('\n✓ Agent identity created successfully');
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
