import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { getStorePath, outputJson, getPassphrase } from '../utils';
import {
  CredentialFileProblem,
  discoverCredentialFiles,
  getBackupsDir,
  getCanonicalVcDir,
  getLegacyCredentialsDir,
  migrateLegacyJwtFiles,
} from '../vc-files';
import { Keystore } from '../../keystore';
import { STORAGE } from '../../constants';

type Severity = 'error' | 'warning';

type DoctorProblem = {
  severity: Severity;
  type: string;
  message: string;
  path?: string;
};

type DirectoryStatus = {
  path: string;
  exists: boolean;
  writable: boolean;
  securePermissions?: boolean;
};

type DoctorReport = {
  homePath: string;
  homePathSource: 'store-option' | 'env' | 'default';
  directories: {
    keys: DirectoryStatus;
    vc: DirectoryStatus;
    backups: DirectoryStatus;
  };
  identitiesCount: number;
  keyFilesCount: number;
  vcFilesCount: number;
  canonicalVcFilesCount: number;
  legacyVcFilesCount: number;
  migratedLegacyVcFiles?: {
    copied: number;
    moved: number;
    skipped: number;
  };
  fixesApplied: string[];
  warnings: DoctorProblem[];
  errors: DoctorProblem[];
};

export const keystoreDoctorCommand = new Command('doctor')
  .description('Check keystore health, directories, and credential file integrity')
  .option('-s, --store <path>', 'Keystore path (default: AGENT_DID_HOME or ~/.agent-did)')
  .option('--no-encryption', 'Keys are stored unencrypted')
  .option('--check-decrypt', 'Verify that a key can be decrypted with the configured passphrase')
  .option('--fix', 'Create missing directories and repair simple structural issues')
  .option('--migrate-vc', 'Copy legacy credential JWT files from credentials/ to vc/')
  .option('--move', 'When used with --migrate-vc, move files instead of copying')
  .option('--yes', 'Confirm changes for --fix and migration actions')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      if ((options.fix || options.migrateVc || options.move) && !options.yes) {
        throw new Error('Use --yes to confirm --fix, --migrate-vc, or --move actions');
      }
      if (options.move && !options.migrateVc) {
        throw new Error('--move requires --migrate-vc');
      }

      const report = await runDoctor(options);
      if (options.json) {
        console.log(outputJson(report));
      } else {
        printReport(report, options);
      }

      if (report.errors.length > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

export async function runDoctor(options: {
  store?: string | boolean;
  encryption?: boolean;
  checkDecrypt?: boolean;
  fix?: boolean;
  migrateVc?: boolean;
  move?: boolean;
}): Promise<DoctorReport> {
  const customStorePath = typeof options.store === 'string' ? options.store : undefined;
  const homePathSource = resolveHomePathSource(customStorePath);
  const homePath = getStorePath(customStorePath);

  const fixesApplied: string[] = [];
  const warnings: DoctorProblem[] = [];
  const errors: DoctorProblem[] = [];

  if (!(await pathExists(homePath))) {
    if (options.fix) {
      await fs.promises.mkdir(homePath, { recursive: true });
      fixesApplied.push(`created keystore home: ${homePath}`);
    } else {
      errors.push({
        severity: 'error',
        type: 'missing-home',
        message: 'Keystore home directory does not exist',
        path: homePath,
      });
    }
  }

  const keysDir = path.join(homePath, STORAGE.KEYS_DIR);
  const vcDir = getCanonicalVcDir(homePath);
  const backupsDir = getBackupsDir(homePath);
  const legacyDir = getLegacyCredentialsDir(homePath);

  const keysStatus = await inspectDirectory(keysDir, options.fix === true, fixesApplied, errors);
  const vcStatus = await inspectDirectory(vcDir, options.fix === true, fixesApplied, errors);
  const backupsStatus = await inspectDirectory(
    backupsDir,
    options.fix === true,
    fixesApplied,
    errors
  );

  const { identities, keyFilesCount } = await inspectIdentitiesAndKeys(
    homePath,
    keysDir,
    options.fix === true,
    fixesApplied,
    warnings,
    errors
  );

  const discovery = await discoverCredentialFiles(homePath);
  appendProblems(
    warnings,
    discovery.warnings.map((problem) => toDoctorProblem(problem, 'warning'))
  );
  appendProblems(
    errors,
    discovery.errors.map((problem) => toDoctorProblem(problem, 'error'))
  );

  let migratedLegacyVcFiles: DoctorReport['migratedLegacyVcFiles'];
  if (options.migrateVc) {
    const migration = await migrateLegacyJwtFiles(homePath, {
      move: options.move,
    });
    migratedLegacyVcFiles = {
      copied: migration.copied,
      moved: migration.moved,
      skipped: migration.skipped,
    };
    if (migration.copied > 0) {
      fixesApplied.push(
        options.move
          ? `migrated ${migration.copied} legacy JWT file(s) from ${legacyDir} to ${vcDir} (moved)`
          : `copied ${migration.copied} legacy JWT file(s) from ${legacyDir} to ${vcDir}`
      );
    }
    if (migration.skipped > 0) {
      warnings.push({
        severity: 'warning',
        type: 'legacy-migration-skipped',
        message: `${migration.skipped} legacy JWT file(s) were skipped because target files already exist`,
        path: vcDir,
      });
    }
    appendProblems(
      errors,
      migration.failures.map((problem) => toDoctorProblem(problem, 'error'))
    );
  } else if (discovery.legacyJwtFiles > 0) {
    warnings.push({
      severity: 'warning',
      type: 'legacy-vc-files-detected',
      message: `${discovery.legacyJwtFiles} legacy JWT file(s) found in ${legacyDir}. Run with --migrate-vc --yes to copy them into ${vcDir}.`,
      path: legacyDir,
    });
  }

  if (options.checkDecrypt && identities.length > 0 && errors.length === 0) {
    try {
      const passphrase = await getPassphrase(options.encryption === false);
      const keystore = new Keystore(homePath, passphrase, true);
      await keystore.getKeyPair(identities[0].did);
    } catch (error) {
      errors.push({
        severity: 'error',
        type: 'decryption-check-failed',
        message: error instanceof Error ? error.message : String(error),
        path: keysDir,
      });
    }
  }

  return {
    homePath,
    homePathSource,
    directories: {
      keys: keysStatus,
      vc: vcStatus,
      backups: backupsStatus,
    },
    identitiesCount: identities.length,
    keyFilesCount,
    vcFilesCount: discovery.credentials.length,
    canonicalVcFilesCount: discovery.canonicalJwtFiles,
    legacyVcFilesCount: discovery.legacyJwtFiles,
    migratedLegacyVcFiles,
    fixesApplied,
    warnings,
    errors,
  };
}

async function inspectDirectory(
  dirPath: string,
  fix: boolean,
  fixesApplied: string[],
  errors: DoctorProblem[]
): Promise<DirectoryStatus> {
  if (!(await pathExists(dirPath))) {
    if (fix) {
      await fs.promises.mkdir(dirPath, { recursive: true });
      fixesApplied.push(`created directory: ${dirPath}`);
    } else {
      errors.push({
        severity: 'error',
        type: 'missing-directory',
        message: 'Required directory is missing',
        path: dirPath,
      });
      return {
        path: dirPath,
        exists: false,
        writable: false,
      };
    }
  }

  const stat = await fs.promises.stat(dirPath);
  if (!stat.isDirectory()) {
    errors.push({
      severity: 'error',
      type: 'invalid-directory',
      message: 'Path exists but is not a directory',
      path: dirPath,
    });
    return {
      path: dirPath,
      exists: true,
      writable: false,
    };
  }

  const writable = await isWritable(dirPath);
  if (!writable) {
    errors.push({
      severity: 'error',
      type: 'directory-not-writable',
      message: 'Directory is not writable',
      path: dirPath,
    });
  }

  const securePermissions = checkSecurePermissions(stat.mode);
  if (securePermissions === false) {
    errors.push({
      severity: 'error',
      type: 'weak-directory-permissions',
      message: 'Directory permissions allow group/other write access',
      path: dirPath,
    });
  }

  return {
    path: dirPath,
    exists: true,
    writable,
    securePermissions: securePermissions === undefined ? undefined : securePermissions,
  };
}

async function inspectIdentitiesAndKeys(
  homePath: string,
  keysDir: string,
  fix: boolean,
  fixesApplied: string[],
  warnings: DoctorProblem[],
  errors: DoctorProblem[]
): Promise<{ identities: Array<{ did: string }>; keyFilesCount: number }> {
  const indexPath = path.join(homePath, STORAGE.INDEX_FILE);
  let identities: Array<{ did: string }> = [];

  if (!(await pathExists(indexPath))) {
    if (fix) {
      await fs.promises.writeFile(indexPath, JSON.stringify({ identities: [] }, null, 2));
      fixesApplied.push(`created index file: ${indexPath}`);
    } else {
      errors.push({
        severity: 'error',
        type: 'missing-index',
        message: 'identities.json is missing',
        path: indexPath,
      });
      return { identities, keyFilesCount: 0 };
    }
  }

  try {
    const content = await fs.promises.readFile(indexPath, 'utf-8');
    const parsed = JSON.parse(content) as { identities?: Array<{ did: string }> };
    if (!Array.isArray(parsed.identities)) {
      throw new Error('identities.json does not contain an identities array');
    }
    identities = parsed.identities;
  } catch (error) {
    errors.push({
      severity: 'error',
      type: 'invalid-index',
      message: error instanceof Error ? error.message : String(error),
      path: indexPath,
    });
    if (fix) {
      const backupPath = `${indexPath}.bak-${Date.now()}`;
      try {
        await fs.promises.rename(indexPath, backupPath);
        fixesApplied.push(`backed up invalid identities.json: ${backupPath}`);
      } catch {
        // Best effort backup only.
      }
      await fs.promises.writeFile(indexPath, JSON.stringify({ identities: [] }, null, 2));
      fixesApplied.push(`reset invalid index: ${indexPath}`);
      identities = [];
    }
  }

  let keyFilesCount = 0;
  const keyFiles = await listFilesWithExtension(keysDir, '.json');
  keyFilesCount = keyFiles.length;

  const expected = new Set(identities.map((identity) => `${sanitizeDid(identity.did)}.json`));
  const found = new Set(keyFiles);

  for (const keyFile of keyFiles) {
    const keyPath = path.join(keysDir, keyFile);
    try {
      const content = await fs.promises.readFile(keyPath, 'utf-8');
      JSON.parse(content);
      const stat = await fs.promises.stat(keyPath);
      const secure = checkSecurePermissions(stat.mode);
      if (secure === false) {
        warnings.push({
          severity: 'warning',
          type: 'weak-key-permissions',
          message: 'Key file permissions are too open',
          path: keyPath,
        });
      }
    } catch (error) {
      errors.push({
        severity: 'error',
        type: 'invalid-key-file',
        message: error instanceof Error ? error.message : String(error),
        path: keyPath,
      });
    }
  }

  for (const expectedKeyFile of expected) {
    if (!found.has(expectedKeyFile)) {
      warnings.push({
        severity: 'warning',
        type: 'missing-key-file',
        message: `Missing key file for identity (${expectedKeyFile})`,
        path: path.join(keysDir, expectedKeyFile),
      });
    }
  }

  for (const keyFile of found) {
    if (!expected.has(keyFile)) {
      warnings.push({
        severity: 'warning',
        type: 'orphan-key-file',
        message: `Key file has no matching identity (${keyFile})`,
        path: path.join(keysDir, keyFile),
      });
    }
  }

  return {
    identities,
    keyFilesCount,
  };
}

function resolveHomePathSource(customStorePath?: string): 'store-option' | 'env' | 'default' {
  if (customStorePath) {
    return 'store-option';
  }
  if (process.env.AGENT_DID_HOME) {
    return 'env';
  }
  return 'default';
}

function printReport(
  report: DoctorReport,
  options: { fix?: boolean; migrateVc?: boolean; move?: boolean }
): void {
  console.log('Keystore Doctor');
  console.log(`Home: ${report.homePath}`);
  console.log(`Home source: ${report.homePathSource}`);
  console.log('');

  console.log('Directories:');
  printDirectoryLine('keys', report.directories.keys);
  printDirectoryLine('vc', report.directories.vc);
  printDirectoryLine('backups', report.directories.backups);
  console.log('');

  console.log('Counts:');
  console.log(`- Identities: ${report.identitiesCount}`);
  console.log(`- Key files: ${report.keyFilesCount}`);
  console.log(
    `- VC files: ${report.vcFilesCount} (canonical: ${report.canonicalVcFilesCount}, legacy: ${report.legacyVcFilesCount})`
  );
  if (report.migratedLegacyVcFiles) {
    console.log(
      `- Legacy migration: copied ${report.migratedLegacyVcFiles.copied}, moved ${report.migratedLegacyVcFiles.moved}, skipped ${report.migratedLegacyVcFiles.skipped}`
    );
  }
  console.log('');

  if (report.fixesApplied.length > 0) {
    console.log('Fixes applied:');
    for (const fix of report.fixesApplied) {
      console.log(`- ${fix}`);
    }
    console.log('');
  } else if (options.fix || options.migrateVc || options.move) {
    console.log('No fixes were needed.');
    console.log('');
  }

  if (report.errors.length === 0 && report.warnings.length === 0) {
    console.log('✓ Healthy keystore');
    return;
  }

  if (report.errors.length > 0) {
    console.log('Errors:');
    for (const problem of report.errors) {
      printProblem(problem);
    }
    console.log('');
  }

  if (report.warnings.length > 0) {
    console.log('Warnings:');
    for (const problem of report.warnings) {
      printProblem(problem);
    }
    console.log('');
  }

  if (report.errors.length > 0) {
    console.log('✗ Keystore health check failed');
  } else {
    console.log('⚠ Keystore is usable but has warnings');
  }
}

function printDirectoryLine(name: string, status: DirectoryStatus): void {
  const existsLabel = status.exists ? 'exists' : 'missing';
  const writableLabel = status.writable ? 'writable' : 'not writable';
  let permissionLabel = '';
  if (status.securePermissions === true) {
    permissionLabel = ', permissions OK';
  } else if (status.securePermissions === false) {
    permissionLabel = ', permissions too open';
  }
  console.log(`- ${name}: ${existsLabel}, ${writableLabel}${permissionLabel} (${status.path})`);
}

function printProblem(problem: DoctorProblem): void {
  const location = problem.path ? ` (${problem.path})` : '';
  console.log(`- [${problem.severity}] ${problem.type}: ${problem.message}${location}`);
}

function toDoctorProblem(problem: CredentialFileProblem, severity: Severity): DoctorProblem {
  return {
    severity,
    type: problem.type,
    message: problem.message,
    path: problem.path,
  };
}

function appendProblems(target: DoctorProblem[], items: DoctorProblem[]): void {
  for (const item of items) {
    target.push(item);
  }
}

function sanitizeDid(did: string): string {
  return did.replace(/[^a-zA-Z0-9]/g, '_');
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.promises.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function isWritable(targetPath: string): Promise<boolean> {
  try {
    await fs.promises.access(targetPath, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

async function listFilesWithExtension(dirPath: string, extension: string): Promise<string[]> {
  try {
    const entries = await fs.promises.readdir(dirPath);
    return entries.filter((entry) => entry.toLowerCase().endsWith(extension)).sort();
  } catch {
    return [];
  }
}

function checkSecurePermissions(mode: number): boolean | undefined {
  if (process.platform === 'win32') {
    return undefined;
  }
  const writableByGroupOrOther = (mode & 0o022) !== 0;
  return !writableByGroupOrOther;
}
