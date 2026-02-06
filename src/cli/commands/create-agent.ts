import { Command } from 'commander';
import { generateKeyPair } from '../../crypto';
import { publicKeyToDidKey } from '../../did';
import {
  getExistingKeystore,
  getNewKeystore,
  getStorePath,
  outputJson,
  outputTable,
  resolveRolePassphrase,
} from '../utils';

export const createAgentCommand = new Command('agent')
  .description('Create a new agent identity linked to an owner')
  .requiredOption('-n, --name <name>', 'Name for the agent identity')
  .requiredOption('--owner <did>', 'Owner DID')
  .option('-s, --store <path>', 'Keystore path (default: ~/.agent-did)')
  .option('--agent-passphrase <passphrase>', 'Passphrase for encrypting the agent key')
  .option('--owner-passphrase <passphrase>', 'Owner passphrase (with --reuse-owner-passphrase)')
  .option(
    '--reuse-owner-passphrase',
    'Reuse owner passphrase to encrypt the agent key (opt-in)'
  )
  .option('--no-encryption', 'Store keys unencrypted (NOT RECOMMENDED)')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const storePath = getStorePath(options.store);
      const noEncryption = options.encryption === false;

      if (options.reuseOwnerPassphrase && options.agentPassphrase !== undefined) {
        throw new Error(
          'Cannot combine --agent-passphrase with --reuse-owner-passphrase. Choose one source.'
        );
      }

      if (!options.reuseOwnerPassphrase && options.ownerPassphrase !== undefined) {
        throw new Error(
          '--owner-passphrase requires --reuse-owner-passphrase when creating an agent.'
        );
      }

      const agentPassphrase = options.reuseOwnerPassphrase
        ? await resolveRolePassphrase({
            role: 'owner',
            purpose: 'encrypt',
            noEncryption,
            passphraseFlagValue: options.ownerPassphrase,
            passphraseFlagName: '--owner-passphrase',
            promptText: 'Enter owner passphrase to encrypt AGENT DID key: ',
          })
        : await resolveRolePassphrase({
            role: 'agent',
            purpose: 'encrypt',
            noEncryption,
            passphraseFlagValue: options.agentPassphrase,
            passphraseFlagName: '--agent-passphrase',
          });

      // Owner metadata lookup does not require decrypting keys.
      const metadataKeystore = await getExistingKeystore(options.store, true, null);
      await metadataKeystore.init();

      // Validate owner exists
      const ownerIdentity = await metadataKeystore.getIdentity(options.owner);
      if (!ownerIdentity) {
        throw new Error(`Owner identity not found: ${options.owner}`);
      }

      if (ownerIdentity.type !== 'owner') {
        throw new Error(`Specified DID is not an owner: ${options.owner}`);
      }

      // Generate key pair
      const keyPair = await generateKeyPair();
      const did = publicKeyToDidKey(keyPair.publicKey);

      // Create metadata
      const metadata = {
        did,
        type: 'agent' as const,
        name: options.name,
        ownerDid: options.owner,
        createdAt: new Date().toISOString(),
      };

      // Store identity
      const writeKeystore = await getNewKeystore(options.store, noEncryption, agentPassphrase);
      await writeKeystore.storeIdentity(metadata, keyPair);

      const output = {
        did,
        kid: `${did}#${did.split(':')[2]}`,
        name: options.name,
        type: 'agent',
        ownerDid: options.owner,
        ownerName: ownerIdentity.name,
        store: storePath,
        createdAt: metadata.createdAt,
      };

      if (options.json) {
        console.log(outputJson(output));
      } else {
        console.log(outputTable(output));
        console.log('\n✓ Agent identity created successfully');
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
