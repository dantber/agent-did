import { Command } from 'commander';
import { BackupManager } from '../../backup';
import { getStorePath, getPassphrase, outputJson } from '../utils';

export const backupCommand = new Command('backup')
  .description('Create a backup of the keystore')
  .requiredOption('-o, --out <file>', 'Output backup file path')
  .option('-s, --store <path>', 'Keystore path')
  .option('--encrypt', 'Encrypt the backup')
  .option('--backup-password <password>', 'Password for encrypted backup')
  .option('--no-credentials', 'Exclude credentials from backup')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const backupManager = new BackupManager(storePath);

      let backupPassword: string | undefined;
      if (options.encrypt) {
        backupPassword = options.backupPassword || process.env.AGENT_DID_BACKUP_PASSWORD;
        if (!backupPassword) {
          throw new Error(
            'Backup password required for encryption. ' +
              'Use --backup-password or set AGENT_DID_BACKUP_PASSWORD'
          );
        }
      }

      const metadata = await backupManager.backup(options.out, {
        encrypt: options.encrypt,
        password: backupPassword,
        includeCredentials: options.credentials !== false,
      });

      if (options.json) {
        console.log(outputJson(metadata));
      } else {
        console.log('\n✓ Backup created successfully');
        console.log(`File: ${options.out}`);
        console.log(`Identities: ${metadata.identityCount}`);
        console.log(`Credentials: ${metadata.credentialCount}`);
        console.log(`Encrypted: ${metadata.encrypted ? 'Yes' : 'No'}`);
        console.log(`Created: ${metadata.createdAt}`);
        console.log('\nIMPORTANT: Store your backup in a secure location.');
        if (metadata.encrypted) {
          console.log('Keep your backup password safe - it cannot be recovered.');
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

export const restoreCommand = new Command('restore')
  .description('Restore keystore from a backup')
  .requiredOption('-f, --file <path>', 'Backup file path')
  .option('-s, --store <path>', 'Target keystore path')
  .option('--backup-password <password>', 'Password for encrypted backup')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const backupManager = new BackupManager(storePath);

      const backupPassword = options.backupPassword || process.env.AGENT_DID_BACKUP_PASSWORD;

      const metadata = await backupManager.restore(options.file, {
        password: backupPassword,
        targetPath: storePath,
      });

      if (options.json) {
        console.log(outputJson(metadata));
      } else {
        console.log('\n✓ Backup restored successfully');
        console.log(`Identities: ${metadata.identityCount}`);
        console.log(`Credentials: ${metadata.credentialCount}`);
        console.log(`Original backup created: ${metadata.createdAt}`);
        console.log(`Restored to: ${storePath}`);
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
