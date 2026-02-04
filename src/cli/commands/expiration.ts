import { Command } from 'commander';
import { ExpirationManager } from '../../expiration';
import { getStorePath, outputJson } from '../utils';
import * as fs from 'fs';

export const checkExpiringCommand = new Command('check-expiring')
  .description('Check for credentials that are expiring soon')
  .option('--days <number>', 'Days threshold for expiring (default: 30)', '30')
  .option('-s, --store <path>', 'Keystore path')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const manager = new ExpirationManager(storePath);

      const daysThreshold = parseInt(options.days, 10);
      const expiring = await manager.checkExpiring(daysThreshold);

      if (options.json) {
        console.log(outputJson(expiring));
        return;
      }

      if (expiring.length === 0) {
        console.log(`\n✓ No credentials expiring in the next ${daysThreshold} days.`);
        return;
      }

      console.log(`\n⚠️  Found ${expiring.length} credential(s) expiring soon:\n`);

      for (const cred of expiring) {
        if (cred.expired) {
          console.log(`❌ EXPIRED: ${cred.id}`);
          console.log(`   Expired: ${Math.abs(cred.daysUntilExpiry)} day(s) ago`);
        } else if (cred.daysUntilExpiry <= 7) {
          console.log(`🔴 URGENT: ${cred.id}`);
          console.log(`   Expires: ${cred.daysUntilExpiry} day(s)`);
        } else if (cred.daysUntilExpiry <= 14) {
          console.log(`🟡 WARNING: ${cred.id}`);
          console.log(`   Expires: ${cred.daysUntilExpiry} day(s)`);
        } else {
          console.log(`🟢 NOTICE: ${cred.id}`);
          console.log(`   Expires: ${cred.daysUntilExpiry} day(s)`);
        }
        console.log(`   Issuer:  ${cred.issuer}`);
        console.log(`   Subject: ${cred.subject}`);
        console.log(`   Date:    ${cred.expiresAt}`);
        console.log('');
      }

      console.log(`Recommendation: Renew credentials marked as URGENT or EXPIRED.`);
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

export const expirationSummaryCommand = new Command('expiration-summary')
  .description('Get a summary of credential expiration status')
  .option('-s, --store <path>', 'Keystore path')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const manager = new ExpirationManager(storePath);

      const summary = await manager.getSummary();

      if (options.json) {
        console.log(outputJson(summary));
        return;
      }

      console.log(`\n=== Credential Expiration Summary ===\n`);
      console.log(`Total credentials:     ${summary.total}`);
      console.log(`Expired:               ${summary.expired}`);
      console.log(`Expiring soon (30d):   ${summary.expiringSoon}`);
      console.log(`Healthy:               ${summary.healthy}`);

      if (summary.expired > 0) {
        console.log(`\n⚠️  You have ${summary.expired} expired credential(s)!`);
      }
      if (summary.expiringSoon > 0) {
        console.log(`\n⚠️  You have ${summary.expiringSoon} credential(s) expiring soon!`);
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

export const checkCredentialExpiryCommand = new Command('check-credential-expiry')
  .description('Check expiration status of a specific credential')
  .requiredOption('-f, --file <path>', 'Path to credential file')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const fileContent = await fs.promises.readFile(options.file, 'utf-8');

      let jwt: string;
      try {
        const parsed = JSON.parse(fileContent);
        jwt = parsed.credential || parsed.jwt || fileContent.trim();
      } catch {
        jwt = fileContent.trim();
      }

      const manager = new ExpirationManager(''); // Don't need basePath for single check
      const status = await manager.checkCredentialExpiry(jwt);

      if (options.json) {
        console.log(outputJson(status));
        return;
      }

      if (!status.expiresAt) {
        console.log('\n✓ This credential does not expire.');
        return;
      }

      if (status.expired) {
        console.log('\n❌ This credential has EXPIRED');
        console.log(`Expired: ${Math.abs(status.daysUntilExpiry!)} day(s) ago`);
        console.log(`Date: ${status.expiresAt}`);
      } else {
        console.log('\n✓ This credential is still valid');
        console.log(`Expires: ${status.daysUntilExpiry} day(s) from now`);
        console.log(`Date: ${status.expiresAt}`);

        if (status.daysUntilExpiry! <= 30) {
          console.log(`\n⚠️  This credential will expire soon! Consider renewing.`);
        }
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
