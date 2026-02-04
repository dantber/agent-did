import { Command } from 'commander';
import { BitstringStatusListManager } from '../../status-list';
import { getExistingKeystore, getStorePath, outputJson } from '../utils';

export const createStatusListCommand = new Command('create-status-list')
  .description('Create a Bitstring Status List credential for an issuer')
  .requiredOption('--issuer <did>', 'Issuer DID')
  .option('--purpose <purpose>', 'Purpose: revocation or suspension', 'revocation')
  .option('--size <number>', 'Number of entries (default: 131072)', parseInt)
  .option('-s, --store <path>', 'Keystore path')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const keystore = await getExistingKeystore(options.store);
      const manager = new BitstringStatusListManager(storePath);
      await manager.init();

      // Verify issuer exists
      const issuer = await keystore.getIdentity(options.issuer);
      if (!issuer) {
        throw new Error(`Issuer not found: ${options.issuer}`);
      }

      const purpose = options.purpose as 'revocation' | 'suspension';
      if (purpose !== 'revocation' && purpose !== 'suspension') {
        throw new Error('Purpose must be "revocation" or "suspension"');
      }

      const statusList = await manager.createStatusList(options.issuer, purpose, options.size);

      const credential = statusList.toCredential();

      if (options.json) {
        console.log(outputJson(credential));
      } else {
        console.log('\n✓ Status List created successfully');
        console.log(`ID: ${credential.id}`);
        console.log(`Purpose: ${purpose}`);
        console.log(`Capacity: ${options.size || 131072} entries`);
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

export const statusListStatsCommand = new Command('status-list-stats')
  .description('Get statistics about a status list')
  .requiredOption('--issuer <did>', 'Issuer DID')
  .option('--purpose <purpose>', 'Purpose: revocation or suspension', 'revocation')
  .option('-s, --store <path>', 'Keystore path')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const manager = new BitstringStatusListManager(storePath);

      const purpose = options.purpose as 'revocation' | 'suspension';
      const stats = await manager.getStats(options.issuer, purpose);

      if (options.json) {
        console.log(outputJson(stats));
      } else {
        console.log(`\n=== Status List Statistics ===\n`);
        console.log(`Purpose:      ${purpose}`);
        console.log(`Total:        ${stats.total} entries`);
        console.log(`Used:         ${stats.set} entries`);
        console.log(`Available:    ${stats.available} entries`);
        console.log(`Utilization:  ${(stats.utilization * 100).toFixed(2)}%`);
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
