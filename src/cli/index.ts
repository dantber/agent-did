#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync } from 'fs';
import { join } from 'path';
import { createOwnerCommand } from './commands/create-owner';
import { createAgentCommand } from './commands/create-agent';
import { listCommand } from './commands/list';
import { inspectCommand } from './commands/inspect';
import { deleteIdentityCommand } from './commands/delete-identity';
import { vcIssueCommand } from './commands/vc-issue';
import { vcVerifyCommand } from './commands/vc-verify';
import { authSignCommand } from './commands/auth-sign';
import { authVerifyCommand } from './commands/auth-verify';
import { vcInspectCommand } from './commands/vc-inspect';
import { vcListCommand } from './commands/vc-list';
import { vcDeleteCommand } from './commands/vc-delete';
import { vcRevokeCommand, vcCheckRevocationCommand } from './commands/vc-revoke';
import { keystoreDoctorCommand } from './commands/keystore-doctor';
import { backupCommand, restoreCommand } from './commands/backup';
import { rotateKeyCommand, rotationHistoryCommand } from './commands/rotate-key';
import { createStatusListCommand, statusListStatsCommand } from './commands/status-list';
import {
  checkExpiringCommand,
  expirationSummaryCommand,
  checkCredentialExpiryCommand,
} from './commands/expiration';

// Read version from package.json
const packageJson = JSON.parse(
  readFileSync(join(__dirname, '../../package.json'), 'utf-8')
);

const program = new Command();

program
  .name('agent-did')
  .description('CLI for managing AI agent identities using DIDs and Verifiable Credentials')
  .version(packageJson.version);

program
  .command('create')
  .description('Create a new identity')
  .addCommand(createOwnerCommand)
  .addCommand(createAgentCommand);

program.addCommand(listCommand);
program.addCommand(inspectCommand);
program.addCommand(deleteIdentityCommand);
program.addCommand(rotateKeyCommand);
program.addCommand(rotationHistoryCommand);

program
  .command('vc')
  .description('Verifiable Credential operations')
  .addCommand(vcIssueCommand)
  .addCommand(vcVerifyCommand)
  .addCommand(vcInspectCommand)
  .addCommand(vcListCommand)
  .addCommand(vcDeleteCommand)
  .addCommand(vcRevokeCommand)
  .addCommand(vcCheckRevocationCommand)
  .addCommand(createStatusListCommand)
  .addCommand(statusListStatsCommand)
  .addCommand(checkExpiringCommand)
  .addCommand(expirationSummaryCommand)
  .addCommand(checkCredentialExpiryCommand);

program
  .command('auth')
  .description('Authentication operations')
  .addCommand(authSignCommand)
  .addCommand(authVerifyCommand);

program
  .command('keystore')
  .description('Keystore utilities')
  .addCommand(keystoreDoctorCommand)
  .addCommand(backupCommand)
  .addCommand(restoreCommand);

program.parse();
