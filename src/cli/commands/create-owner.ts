import { Command } from 'commander';
import { generateKeyPair, KeyPair } from '../../crypto';
import { publicKeyToDidKey } from '../../did';
import { getNewKeystore, getStorePath, outputJson, outputTable } from '../utils';

export const createOwnerCommand = new Command('owner')
  .description('Create a new owner identity')
  .requiredOption('-n, --name <name>', 'Name for the owner identity')
  .option('-s, --store <path>', 'Keystore path (default: ~/.agent-did)')
  .option('--no-encryption', 'Store keys unencrypted (NOT RECOMMENDED)')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);

      // Will validate passphrase strength for new keystore
      const keystore = await getNewKeystore(options.store, options.encryption === false);
      await keystore.init();

      // Generate key pair
      const keyPair = await generateKeyPair();
      const did = publicKeyToDidKey(keyPair.publicKey);

      // Create metadata
      const metadata = {
        did,
        type: 'owner' as const,
        name: options.name,
        createdAt: new Date().toISOString(),
      };

      // Store identity
      await keystore.storeIdentity(metadata, keyPair);

      const output = {
        did,
        kid: `${did}#${did.split(':')[2]}`,
        name: options.name,
        type: 'owner',
        store: storePath,
        createdAt: metadata.createdAt,
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log(outputTable(output));
        console.log('\n✓ Owner identity created successfully');
        if (options.encryption !== false) {
          console.log(`\nIMPORTANT: Store your passphrase securely. It cannot be recovered.`);
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
