import { Command } from 'commander';
import { getExistingKeystore, outputJson } from '../utils';

export const deleteIdentityCommand = new Command('delete')
  .description('Delete an identity and its key material')
  .requiredOption('--did <did>', 'DID to delete')
  .option('-s, --store <path>', 'Keystore path (default: ~/.agent-did)')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--yes', 'Confirm deletion without prompt')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      if (!options.yes) {
        throw new Error('Deletion requires --yes to confirm');
      }

      const keystore = await getExistingKeystore(options.store, options.encryption === false);
      const deleted = await keystore.deleteIdentity(options.did);

      const output = { deleted, did: options.did };
      if (options.json) {
        console.log(outputJson(output));
      } else {
        if (deleted) {
          console.log('\n✓ Identity deleted successfully');
        } else {
          console.log('\n✗ Identity not found');
          process.exit(1);
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
