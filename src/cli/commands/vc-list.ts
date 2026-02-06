import { Command } from 'commander';
import { verifyCredential } from '../../vc';
import {
  CredentialFileSummary,
  discoverCredentialFiles,
  readJwtFromCredentialFile,
} from '../vc-files';
import { formatDate, getStorePath, outputJson } from '../utils';

type VerificationSummary = {
  valid: boolean;
  reason?: string;
};

type ListEntry = CredentialFileSummary & {
  verification?: VerificationSummary;
};

export const vcListCommand = new Command('list')
  .description('List credential JWT files from the local keystore')
  .option('-s, --store <path>', 'Keystore path (default: ~/.agent-did)')
  .option('--no-encryption', 'Legacy flag (not required for file-based VC listing)')
  .option('--verify', 'Verify signature for each listed credential')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const discovery = await discoverCredentialFiles(storePath);

      if (discovery.errors.length > 0) {
        throw new Error(
          discovery.errors
            .map((problem) => `${problem.type}: ${problem.message}${problem.path ? ` (${problem.path})` : ''}`)
            .join('; ')
        );
      }

      let credentials: ListEntry[] = discovery.credentials.map((item) => ({ ...item }));
      if (options.verify) {
        credentials = await addVerification(credentials);
      }

      credentials.sort((a, b) => {
        const aTime = timestampForSort(a);
        const bTime = timestampForSort(b);
        return bTime - aTime;
      });

      if (options.json) {
        console.log(
          outputJson({
            storePath,
            directories: {
              canonical: discovery.canonicalDir,
              legacy: discovery.legacyDir,
            },
            count: credentials.length,
            legacyJwtFiles: discovery.legacyJwtFiles,
            credentials,
            warnings: discovery.warnings,
          })
        );
        return;
      }

      if (credentials.length === 0) {
        console.log('No credentials found.');
        console.log(`Scanned: ${discovery.canonicalDir}`);
        console.log(`Scanned (legacy): ${discovery.legacyDir}`);
        if (discovery.warnings.length > 0) {
          console.log('\nWarnings:');
          for (const warning of discovery.warnings) {
            console.log(`- ${warning.type}: ${warning.message}${warning.path ? ` (${warning.path})` : ''}`);
          }
        }
        if (discovery.legacyJwtFiles > 0) {
          console.log(
            `\nLegacy JWT files detected in ${discovery.legacyDir}. Run 'agent-did keystore doctor --migrate-vc --yes' to copy them into ${discovery.canonicalDir}.`
          );
        }
        return;
      }

      console.log(`Found ${credentials.length} credential(s):\n`);

      for (const item of credentials) {
        console.log(`- File: ${item.filename}${item.source === 'legacy' ? ' (legacy)' : ''}`);
        console.log(`  Types: ${item.types.length > 0 ? item.types.join(', ') : '(unknown)'}`);
        console.log(`  Issuer: ${item.issuer || '(missing)'}`);
        console.log(`  Subject: ${item.subject || '(missing)'}`);

        const issuedAt = item.issuedAt || item.validFrom;
        if (issuedAt) {
          console.log(`  Issued: ${formatDate(issuedAt)}`);
        }
        if (item.expiresAt) {
          console.log(`  Expires: ${formatDate(item.expiresAt)}`);
        }
        if (item.verification) {
          const validText = item.verification.valid ? 'valid' : 'invalid';
          const reason = item.verification.reason ? ` (${item.verification.reason})` : '';
          console.log(`  Verification: ${validText}${reason}`);
        }
        console.log('');
      }

      if (discovery.warnings.length > 0) {
        console.log('Warnings:');
        for (const warning of discovery.warnings) {
          console.log(`- ${warning.type}: ${warning.message}${warning.path ? ` (${warning.path})` : ''}`);
        }
        console.log('');
      }

      if (discovery.legacyJwtFiles > 0) {
        console.log(
          `Legacy JWT files detected in ${discovery.legacyDir}. Run 'agent-did keystore doctor --migrate-vc --yes' to copy them into ${discovery.canonicalDir}.`
        );
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

async function addVerification(credentials: ListEntry[]): Promise<ListEntry[]> {
  const output: ListEntry[] = [];
  for (const item of credentials) {
    try {
      const jwt = await readJwtFromCredentialFile(item.path);
      const result = await verifyCredential(jwt);
      output.push({
        ...item,
        verification: {
          valid: result.valid,
          reason: result.reason,
        },
      });
    } catch (error) {
      output.push({
        ...item,
        verification: {
          valid: false,
          reason: error instanceof Error ? error.message : String(error),
        },
      });
    }
  }
  return output;
}

function timestampForSort(item: CredentialFileSummary): number {
  const candidate = item.issuedAt || item.validFrom;
  if (!candidate) return 0;
  const value = Date.parse(candidate);
  return Number.isFinite(value) ? value : 0;
}
