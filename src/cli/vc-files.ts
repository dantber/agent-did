import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { STORAGE } from '../constants';
import { decodeCredential } from '../vc';

export type CredentialFileSource = 'vc' | 'legacy';

export interface CredentialFileSummary {
  filename: string;
  path: string;
  source: CredentialFileSource;
  issuer?: string;
  subject?: string;
  types: string[];
  issuedAt?: string;
  validFrom?: string;
  expiresAt?: string;
}

export interface CredentialFileProblem {
  type: string;
  message: string;
  path?: string;
}

export interface CredentialDiscoveryResult {
  canonicalDir: string;
  legacyDir: string;
  canonicalJwtFiles: number;
  legacyJwtFiles: number;
  credentials: CredentialFileSummary[];
  warnings: CredentialFileProblem[];
  errors: CredentialFileProblem[];
}

export interface LegacyMigrationResult {
  copied: number;
  moved: number;
  skipped: number;
  failures: CredentialFileProblem[];
}

interface ParsedCredentialFile {
  jwt: string;
  summary: CredentialFileSummary;
}

export function getCanonicalVcDir(storePath: string): string {
  return path.join(storePath, STORAGE.VC_DIR);
}

export function getLegacyCredentialsDir(storePath: string): string {
  return path.join(storePath, STORAGE.CREDENTIALS_DIR);
}

export function getBackupsDir(storePath: string): string {
  return path.join(storePath, STORAGE.BACKUPS_DIR);
}

export async function discoverCredentialFiles(storePath: string): Promise<CredentialDiscoveryResult> {
  const canonicalDir = getCanonicalVcDir(storePath);
  const legacyDir = getLegacyCredentialsDir(storePath);

  const warnings: CredentialFileProblem[] = [];
  const errors: CredentialFileProblem[] = [];
  const credentials: CredentialFileSummary[] = [];

  const canonical = await scanJwtDirectory(canonicalDir, 'vc', warnings, errors);
  const legacy = await scanJwtDirectory(legacyDir, 'legacy', warnings, errors);

  for (const entry of canonical.parsed) {
    credentials.push(entry.summary);
  }
  for (const entry of legacy.parsed) {
    credentials.push(entry.summary);
  }

  return {
    canonicalDir,
    legacyDir,
    canonicalJwtFiles: canonical.jwtFileCount,
    legacyJwtFiles: legacy.jwtFileCount,
    credentials,
    warnings,
    errors,
  };
}

export async function readJwtFromCredentialFile(filePath: string): Promise<string> {
  const fileContent = await fs.promises.readFile(filePath, 'utf-8');
  const jwt = extractJwtFromFile(fileContent);
  if (!jwt) {
    throw new Error(`File does not contain a valid JWT: ${filePath}`);
  }
  return jwt;
}

export function buildCredentialJwtFilename(types: string[] | undefined, subjectDid: string): string {
  const typePart = toKebabCase(pickPrimaryType(types) || 'credential');
  const subjectPart = toKebabCase(shortDidFragment(subjectDid));
  const timestamp = new Date()
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d{3}Z$/, 'Z');
  const entropy = crypto.randomBytes(3).toString('hex');
  return `${typePart}-${subjectPart}-${timestamp}-${entropy}.jwt`;
}

export async function storeJwtInCanonicalVcDir(
  storePath: string,
  jwt: string,
  types: string[] | undefined,
  subjectDid: string
): Promise<string> {
  const vcDir = getCanonicalVcDir(storePath);
  await fs.promises.mkdir(vcDir, { recursive: true });

  const filename = buildCredentialJwtFilename(types, subjectDid);
  const outputPath = await getUniquePath(path.join(vcDir, filename));

  await fs.promises.writeFile(outputPath, `${jwt.trim()}\n`, 'utf-8');
  try {
    await fs.promises.chmod(outputPath, STORAGE.FILE_PERMISSIONS);
  } catch {
    // Ignore permission errors on platforms that do not support chmod semantics.
  }

  return outputPath;
}

export async function migrateLegacyJwtFiles(
  storePath: string,
  options: { move?: boolean } = {}
): Promise<LegacyMigrationResult> {
  const canonicalDir = getCanonicalVcDir(storePath);
  const legacyDir = getLegacyCredentialsDir(storePath);
  const result: LegacyMigrationResult = {
    copied: 0,
    moved: 0,
    skipped: 0,
    failures: [],
  };

  const legacyEntries = await listJwtEntries(legacyDir);
  if (!legacyEntries.exists) {
    return result;
  }
  if (!legacyEntries.directory) {
    result.failures.push({
      type: 'invalid-legacy-dir',
      message: 'Legacy credentials path exists but is not a directory',
      path: legacyDir,
    });
    return result;
  }

  await fs.promises.mkdir(canonicalDir, { recursive: true });

  for (const file of legacyEntries.files) {
    const sourcePath = path.join(legacyDir, file);
    const targetPath = path.join(canonicalDir, file);
    try {
      const targetExists = await exists(targetPath);
      if (targetExists) {
        result.skipped += 1;
        continue;
      }

      await fs.promises.copyFile(sourcePath, targetPath);
      result.copied += 1;

      try {
        await fs.promises.chmod(targetPath, STORAGE.FILE_PERMISSIONS);
      } catch {
        // Ignore permission errors on platforms that do not support chmod semantics.
      }

      if (options.move) {
        await fs.promises.unlink(sourcePath);
        result.moved += 1;
      }
    } catch (error) {
      result.failures.push({
        type: 'legacy-migrate-failed',
        message: `Failed to migrate ${file}: ${error instanceof Error ? error.message : String(error)}`,
        path: sourcePath,
      });
    }
  }

  return result;
}

async function scanJwtDirectory(
  dirPath: string,
  source: CredentialFileSource,
  warnings: CredentialFileProblem[],
  errors: CredentialFileProblem[]
): Promise<{ parsed: ParsedCredentialFile[]; jwtFileCount: number }> {
  const entries = await listJwtEntries(dirPath);
  if (!entries.exists) {
    return { parsed: [], jwtFileCount: 0 };
  }

  if (!entries.directory) {
    errors.push({
      type: 'invalid-dir',
      message: `Expected a directory but found a non-directory path`,
      path: dirPath,
    });
    return { parsed: [], jwtFileCount: 0 };
  }

  if (entries.error) {
    errors.push({
      type: 'directory-read-failed',
      message: entries.error,
      path: dirPath,
    });
    return { parsed: [], jwtFileCount: 0 };
  }

  const parsed: ParsedCredentialFile[] = [];
  for (const file of entries.files) {
    const filePath = path.join(dirPath, file);
    const parsedFile = await parseCredentialFile(filePath, file, source);
    if (!parsedFile.error && parsedFile.parsed) {
      parsed.push(parsedFile.parsed);
      continue;
    }
    warnings.push({
      type: 'invalid-credential-file',
      message: parsedFile.error || `Unable to parse credential file: ${file}`,
      path: filePath,
    });
  }

  return {
    parsed,
    jwtFileCount: entries.files.length,
  };
}

async function parseCredentialFile(
  filePath: string,
  filename: string,
  source: CredentialFileSource
): Promise<{ parsed?: ParsedCredentialFile; error?: string }> {
  try {
    const fileContent = await fs.promises.readFile(filePath, 'utf-8');
    const jwt = extractJwtFromFile(fileContent);
    if (!jwt) {
      return { error: 'File does not contain a valid JWT' };
    }

    const decoded = decodeCredential(jwt);
    if (!decoded?.payload) {
      return { error: 'Credential JWT is malformed or corrupted' };
    }

    const payload = decoded.payload;
    const vc = payload.vc;
    const types = normalizeTypes(vc?.type);

    const summary: CredentialFileSummary = {
      filename,
      path: filePath,
      source,
      issuer: payload.iss || vc?.issuer,
      subject: payload.sub || vc?.credentialSubject?.id,
      types,
      issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : undefined,
      validFrom: vc?.validFrom,
      expiresAt: payload.exp
        ? new Date(payload.exp * 1000).toISOString()
        : vc?.validUntil,
    };

    return {
      parsed: {
        jwt,
        summary,
      },
    };
  } catch (error) {
    return {
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function listJwtEntries(
  dirPath: string
): Promise<{ exists: boolean; directory: boolean; files: string[]; error?: string }> {
  try {
    const stat = await fs.promises.stat(dirPath);
    if (!stat.isDirectory()) {
      return { exists: true, directory: false, files: [] };
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return { exists: false, directory: false, files: [] };
    }
    return {
      exists: true,
      directory: true,
      files: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }

  try {
    const entries = await fs.promises.readdir(dirPath);
    return {
      exists: true,
      directory: true,
      files: entries.filter((name) => name.toLowerCase().endsWith('.jwt')).sort(),
    };
  } catch (error) {
    return {
      exists: true,
      directory: true,
      files: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function extractJwtFromFile(content: string): string | null {
  const trimmed = content.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed) as { credential?: unknown; jwt?: unknown };
      const credential = typeof parsed.credential === 'string' ? parsed.credential : null;
      const jwt = typeof parsed.jwt === 'string' ? parsed.jwt : null;
      return credential || jwt || null;
    } catch {
      return null;
    }
  }

  return trimmed;
}

function normalizeTypes(typeValue: unknown): string[] {
  if (Array.isArray(typeValue)) {
    return typeValue.map((value) => String(value));
  }
  if (typeof typeValue === 'string') {
    return [typeValue];
  }
  return [];
}

function pickPrimaryType(types: string[] | undefined): string | undefined {
  if (!types || types.length === 0) {
    return undefined;
  }
  return types.find((type) => type !== 'VerifiableCredential') || types[0];
}

function shortDidFragment(did: string): string {
  const base = did.split(':').pop() || did;
  return base.slice(0, 14);
}

function toKebabCase(input: string): string {
  return input
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();
}

async function getUniquePath(targetPath: string): Promise<string> {
  if (!(await exists(targetPath))) {
    return targetPath;
  }

  const parsed = path.parse(targetPath);
  for (let index = 2; index < 10000; index += 1) {
    const candidate = path.join(parsed.dir, `${parsed.name}-${index}${parsed.ext}`);
    if (!(await exists(candidate))) {
      return candidate;
    }
  }

  throw new Error(`Unable to find unique path for ${targetPath}`);
}

async function exists(targetPath: string): Promise<boolean> {
  try {
    await fs.promises.access(targetPath);
    return true;
  } catch {
    return false;
  }
}
