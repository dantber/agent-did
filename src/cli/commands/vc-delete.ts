import { Command } from 'commander';
import { getExistingKeystore, outputJson } from '../utils';

export const vcDeleteCommand = new Command('delete')
  .description('Delete a stored credential by ID')
  .requiredOption('--id <id>', 'Credential ID to delete')
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
      const deleted = await keystore.deleteCredential(options.id);

      const output = { deleted, id: options.id };
      if (options.json) {
        console.log(outputJson(output));
      } else {
        if (deleted) {
          console.log('\n✓ Credential deleted successfully');
        } else {
          console.log('\n✗ Credential not found');
          process.exit(1);
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
