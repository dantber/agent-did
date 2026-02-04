import { Command } from 'commander';
import { decodeCredential } from '../../vc';
import { outputJson } from '../utils';
import * as fs from 'fs';

export const vcInspectCommand = new Command('inspect')
  .description('Decode a verifiable credential without verifying')
  .requiredOption('-f, --file <path>', 'Path to credential file (JWT)')
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

      const decoded = decodeCredential(jwt);
      if (!decoded) {
        throw new Error('Invalid JWT');
      }

      if (options.json) {
        console.log(outputJson(decoded));
      } else {
        console.log('\n=== Header ===\n');
        console.log(outputJson(decoded.header || {}));
        console.log('\n=== Payload ===\n');
        console.log(outputJson(decoded.payload || {}));
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
