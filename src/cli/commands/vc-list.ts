import { Command } from 'commander';
import { decodeCredential } from '../../vc';
import { getExistingKeystore, outputJson, formatDate } from '../utils';

export const vcListCommand = new Command('list')
  .description('List stored credentials in the keystore')
  .option('-s, --store <path>', 'Keystore path (default: ~/.agent-did)')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const keystore = await getExistingKeystore(options.store, options.encryption === false);
      const exists = await keystore.exists();
      if (!exists) {
        console.log('No credentials found. Keystore does not exist.');
        return;
      }

      const stored = await keystore.listCredentials();
      if (stored.length === 0) {
        console.log('No credentials found.');
        return;
      }

      if (options.json) {
        console.log(outputJson(stored));
        return;
      }

      stored.forEach((item) => {
        const jwt = extractJwt(item.data);
        const summary = jwt ? summarizeCredential(jwt) : {};
        console.log(`  ID: ${item.id}`);
        if (summary.issuer) console.log(`  Issuer: ${summary.issuer}`);
        if (summary.subject) console.log(`  Subject: ${summary.subject}`);
        if (summary.type) console.log(`  Type: ${summary.type}`);
        if (summary.issuedAt) console.log(`  Issued: ${formatDate(summary.issuedAt)}`);
        if (summary.expiresAt) console.log(`  Expires: ${formatDate(summary.expiresAt)}`);
        console.log('');
      });
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

export function summarizeCredential(jwt: string): {
  issuer?: string;
  subject?: string;
  type?: string;
  issuedAt?: string;
  expiresAt?: string;
} {
  const decoded = decodeCredential(jwt);
  if (!decoded?.payload) return {};

  const payload = decoded.payload;
  const type = Array.isArray(payload.vc?.type) ? payload.vc.type.join(', ') : undefined;
  const issuedAt = payload.iat ? new Date(payload.iat * 1000).toISOString() : undefined;
  const expiresAt = payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined;

  return {
    issuer: payload.iss,
    subject: payload.sub,
    type,
    issuedAt,
    expiresAt,
  };
}

function extractJwt(data: unknown): string | null {
  if (!data) return null;
  if (typeof data === 'string') return data;
  if (typeof data === 'object') {
    const maybe = data as { credential?: string; jwt?: string };
    return maybe.credential || maybe.jwt || null;
  }
  return null;
}
