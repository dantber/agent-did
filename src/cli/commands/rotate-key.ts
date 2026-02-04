import { Command } from 'commander';
import { KeyRotationManager } from '../../rotation';
import { AuditLog } from '../../audit';
import { getExistingKeystore, getStorePath, outputJson } from '../utils';

export const rotateKeyCommand = new Command('rotate-key')
  .description('Rotate the key for an identity while maintaining continuity')
  .requiredOption('--did <did>', 'DID to rotate')
  .option('--reason <reason>', 'Reason for rotation')
  .option('-s, --store <path>', 'Keystore path')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const keystore = await getExistingKeystore(options.store);
      const auditLog = new AuditLog(storePath);
      const rotationManager = new KeyRotationManager(storePath, keystore, auditLog);

      // Verify identity exists
      const identity = await keystore.getIdentity(options.did);
      if (!identity) {
        throw new Error(`Identity not found: ${options.did}`);
      }

      console.log(`\nRotating key for: ${identity.name} (${identity.type})`);
      if (options.reason) {
        console.log(`Reason: ${options.reason}`);
      }
      console.log('\nGenerating new key...');

      // Perform rotation
      const { newDid, record } = await rotationManager.rotateKey(options.did, options.reason);

      const output = {
        oldDid: options.did,
        newDid,
        rotatedAt: record.rotatedAt,
        reason: options.reason,
        status: 'completed',
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log('\n✓ Key rotation completed successfully');
        console.log(`\nOld DID: ${options.did}`);
        console.log(`New DID: ${newDid}`);
        console.log(`\nIMPORTANT:`);
        console.log(`1. Update all references to use the new DID`);
        console.log(`2. Re-issue credentials using the new DID`);
        console.log(`3. Notify relying parties of the key rotation`);
        console.log(`4. The old key is now deprecated but still accessible`);
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

export const rotationHistoryCommand = new Command('rotation-history')
  .description('View key rotation history')
  .option('--did <did>', 'Filter by DID')
  .option('-s, --store <path>', 'Keystore path')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const keystore = await getExistingKeystore(options.store);
      const rotationManager = new KeyRotationManager(storePath, keystore);

      const rotations = options.did
        ? await rotationManager.getRotationHistory(options.did)
        : await rotationManager.listRotations();

      if (options.json) {
        console.log(outputJson(rotations));
        return;
      }

      if (rotations.length === 0) {
        console.log('\nNo key rotations found.');
        return;
      }

      console.log(`\n=== Key Rotation History ===\n`);
      for (const rotation of rotations) {
        console.log(`Rotated at: ${rotation.rotatedAt}`);
        console.log(`Old DID:    ${rotation.oldDid}`);
        console.log(`New DID:    ${rotation.newDid}`);
        if (rotation.reason) {
          console.log(`Reason:     ${rotation.reason}`);
        }
        console.log(`Status:     ${rotation.status}`);
        console.log('---');
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
