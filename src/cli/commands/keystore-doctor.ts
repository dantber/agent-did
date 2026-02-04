import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { getStorePath, outputJson, getPassphrase } from '../utils';
import { Keystore } from '../../keystore';

type DoctorProblem = {
  type: string;
  message: string;
  path?: string;
};

export const keystoreDoctorCommand = new Command('doctor')
  .description('Check keystore consistency and report problems')
  .option('-s, --store <path>', 'Keystore path (default: ~/.agent-did)')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--fix', 'Attempt to fix common issues (destructive)')
  .option('--yes', 'Confirm fixes without prompt')
  .option('--check-decrypt', 'Verify that keys can be decrypted with passphrase')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      if (options.fix && !options.yes) {
        throw new Error('Fixing requires --yes to confirm');
      }

      const storePath = getStorePath(options.store);
      const problems: DoctorProblem[] = [];
      const fixes: string[] = [];

      const exists = await pathExists(storePath);
      if (!exists) {
        problems.push({ type: 'missing-store', message: 'Keystore does not exist', path: storePath });
        return output(options, { storePath, problems });
      }

      const indexPath = path.join(storePath, 'identities.json');
      let identities: Array<{ did: string }> = [];
      let indexInvalid = false;
      if (!(await pathExists(indexPath))) {
        problems.push({ type: 'missing-index', message: 'identities.json not found', path: indexPath });
        if (options.fix) {
          await fs.promises.writeFile(indexPath, JSON.stringify({ identities: [] }, null, 2));
          fixes.push('created identities.json');
        }
      } else {
        try {
          const content = await fs.promises.readFile(indexPath, 'utf-8');
          const parsed = JSON.parse(content);
          identities = Array.isArray(parsed.identities) ? parsed.identities : [];
          if (!Array.isArray(parsed.identities)) {
            problems.push({
              type: 'invalid-index',
              message: 'identities.json does not contain an identities array',
              path: indexPath,
            });
            indexInvalid = true;
          }
        } catch (error) {
          problems.push({
            type: 'invalid-index',
            message: `Failed to parse identities.json: ${String(error)}`,
            path: indexPath,
          });
          indexInvalid = true;
        }
      }

      if (options.fix && indexInvalid) {
        const backupPath = `${indexPath}.bak-${Date.now()}`;
        try {
          await fs.promises.rename(indexPath, backupPath);
          fixes.push(`backed up identities.json to ${backupPath}`);
        } catch {
          // Ignore backup failures
        }
        await fs.promises.writeFile(indexPath, JSON.stringify({ identities: [] }, null, 2));
        fixes.push('reset identities.json');
        identities = [];
      }

      const keysDir = path.join(storePath, 'keys');
      if (options.fix) {
        await fs.promises.mkdir(keysDir, { recursive: true });
      }
      const keyFiles = await listJsonFiles(keysDir);
      const keyFileSet = new Set(keyFiles);
      const expectedKeyFiles = new Set(
        identities.map((identity) => `${sanitizeDid(identity.did)}.json`)
      );

      for (const expected of expectedKeyFiles) {
        if (!keyFileSet.has(expected)) {
          problems.push({
            type: 'missing-key',
            message: `Key file missing for identity: ${expected}`,
            path: path.join(keysDir, expected),
          });
        }
      }

      for (const file of keyFileSet) {
        if (!expectedKeyFiles.has(file)) {
          problems.push({
            type: 'orphan-key',
            message: `Key file has no matching identity: ${file}`,
            path: path.join(keysDir, file),
          });
          if (options.fix) {
            await fs.promises.unlink(path.join(keysDir, file));
            fixes.push(`removed orphan key: ${file}`);
          }
        }
      }

      const credentialsDir = path.join(storePath, 'credentials');
      if (options.fix) {
        await fs.promises.mkdir(credentialsDir, { recursive: true });
      }
      const credentialFiles = await listJsonFiles(credentialsDir);
      for (const file of credentialFiles) {
        const fullPath = path.join(credentialsDir, file);
        try {
          const content = await fs.promises.readFile(fullPath, 'utf-8');
          JSON.parse(content);
        } catch (error) {
          problems.push({
            type: 'invalid-credential',
            message: `Failed to parse credential: ${file}: ${String(error)}`,
            path: fullPath,
          });
          if (options.fix) {
            const invalidPath = `${fullPath}.invalid-${Date.now()}`;
            await fs.promises.rename(fullPath, invalidPath);
            fixes.push(`moved invalid credential: ${file}`);
          }
        }
      }

      // Check decryption if requested
      if (options.checkDecrypt && identities.length > 0) {
        try {
          const passphrase = await getPassphrase(options.encryption === false);
          const keystore = new Keystore(storePath, passphrase, true); // Skip validation for existing keystore

          // Try to decrypt one key as a sanity check
          const testIdentity = identities[0];
          try {
            await keystore.getKeyPair(testIdentity.did);
            // Success - passphrase works
          } catch (error) {
            problems.push({
              type: 'decryption-failed',
              message: `Failed to decrypt keys: ${String(error)}`,
              path: keysDir,
            });
          }
        } catch (error) {
          problems.push({
            type: 'passphrase-missing',
            message: 'Cannot check decryption: Passphrase not available',
          });
        }
      }

      return output(options, {
        storePath,
        identitiesCount: identities.length,
        keysCount: keyFiles.length,
        credentialsCount: credentialFiles.length,
        problems,
        fixes,
      });
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

function sanitizeDid(did: string): string {
  return did.replace(/[^a-zA-Z0-9]/g, '_');
}

async function pathExists(target: string): Promise<boolean> {
  try {
    await fs.promises.access(target);
    return true;
  } catch {
    return false;
  }
}

async function listJsonFiles(dirPath: string): Promise<string[]> {
  try {
    const entries = await fs.promises.readdir(dirPath);
    return entries.filter((name) => name.endsWith('.json'));
  } catch {
    return [];
  }
}

function output(options: { json?: boolean }, report: unknown) {
  if (options.json) {
    console.log(outputJson(report));
  } else {
    const r = report as {
      storePath: string;
      identitiesCount?: number;
      keysCount?: number;
      credentialsCount?: number;
      problems: DoctorProblem[];
      fixes?: string[];
    };

    console.log(`Keystore: ${r.storePath}`);
    if (typeof r.identitiesCount === 'number') {
      console.log(`Identities: ${r.identitiesCount}`);
    }
    if (typeof r.keysCount === 'number') {
      console.log(`Keys: ${r.keysCount}`);
    }
    if (typeof r.credentialsCount === 'number') {
      console.log(`Credentials: ${r.credentialsCount}`);
    }

    if (r.problems.length === 0) {
      console.log('\n✓ No problems found');
      return;
    }

    console.log('\nProblems:');
    r.problems.forEach((problem) => {
      console.log(`- ${problem.type}: ${problem.message}`);
      if (problem.path) {
        console.log(`  Path: ${problem.path}`);
      }
    });

    if (r.fixes && r.fixes.length > 0) {
      console.log('\nFixes applied:');
      r.fixes.forEach((fix) => console.log(`- ${fix}`));
    }
    process.exit(1);
  }
}
