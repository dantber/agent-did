import { Command } from 'commander';
import { IdentityMetadata } from '../../keystore';
import { getExistingKeystore, outputJson, formatDid, formatDate } from '../utils';

export const listCommand = new Command('list')
  .description('List all identities in the keystore')
  .option('-s, --store <path>', 'Keystore path (default: ~/.agent-did)')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const keystore = await getExistingKeystore(options.store, options.encryption === false);

      // Check if keystore exists
      const exists = await keystore.exists();
      if (!exists) {
        console.log('No identities found. Keystore does not exist.');
        console.log(`Run 'agent-did create owner --name <name>' to create your first identity.`);
        return;
      }

      const identities = await keystore.listIdentities();

      if (identities.length === 0) {
        console.log('No identities found.');
        return;
      }

      if (options.json) {
        console.log(outputJson(identities));
      } else {
        // Group by type
        const owners = identities.filter((i) => i.type === 'owner');
        const agents = identities.filter((i) => i.type === 'agent');

        console.log('\n=== Owners ===\n');
        if (owners.length === 0) {
          console.log('No owners found.');
        } else {
          owners.forEach((owner) => printIdentity(owner));
        }

        console.log('\n=== Agents ===\n');
        if (agents.length === 0) {
          console.log('No agents found.');
        } else {
          agents.forEach((agent) => printIdentity(agent));
        }

        console.log(`\nTotal: ${identities.length} identity(s)`);
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

function printIdentity(identity: IdentityMetadata) {
  console.log(`  Name: ${identity.name}`);
  console.log(`  DID:  ${formatDid(identity.did)}`);
  console.log(`  Type: ${identity.type}`);
  if (identity.ownerDid) {
    console.log(`  Owner: ${formatDid(identity.ownerDid)}`);
  }
  console.log(`  Created: ${formatDate(identity.createdAt)}`);
  console.log('');
}
