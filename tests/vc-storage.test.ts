import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Keystore } from '../src/keystore';
import { generateKeyPair } from '../src/crypto';
import { publicKeyToDidKey } from '../src/did';
import { createOwnershipCredential, signCredential } from '../src/vc';
import { persistIssuedCredential } from '../src/cli/commands/vc-issue';
import { discoverCredentialFiles } from '../src/cli/vc-files';
import { runDoctor } from '../src/cli/commands/keystore-doctor';

describe('VC storage and discovery', () => {
  let tempDir: string;
  let keystore: Keystore;
  const passphrase = 'test-passphrase-with-16-chars-minimum';

  beforeEach(async () => {
    tempDir = path.join(os.tmpdir(), `agent-did-vc-storage-test-${Date.now()}-${Math.random()}`);
    keystore = new Keystore(tempDir, passphrase, true);
    await keystore.init();
  });

  afterEach(async () => {
    try {
      await fs.promises.rm(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  it('issuing a VC without --out stores a JWT file in the default vc directory', async () => {
    const fixtures = await createOwnerAndAgent(keystore);
    const credential = createOwnershipCredential(fixtures.ownerDid, fixtures.agentDid);
    const jwt = await signCredential(
      credential,
      fixtures.ownerKeyPair.privateKey,
      fixtures.ownerKeyPair.publicKey
    );

    const persisted = await persistIssuedCredential({
      storePath: tempDir,
      shouldStore: true,
      credential,
      jwt,
      prefix: 'ownership',
      saveMetadata: async () => undefined,
    });

    expect(persisted.outputFilePath).toBeDefined();
    expect(persisted.canonicalVcPath).toBeDefined();
    expect(persisted.outputFilePath).toBe(persisted.canonicalVcPath);
    expect(persisted.outputFilePath).toContain(path.join(tempDir, 'vc'));

    const fileContent = await fs.promises.readFile(persisted.outputFilePath as string, 'utf-8');
    expect(fileContent.trim()).toBe(jwt);
  });

  it('vc list discovery returns issued credentials from the vc directory', async () => {
    const fixtures = await createOwnerAndAgent(keystore);
    const credential = createOwnershipCredential(fixtures.ownerDid, fixtures.agentDid, {
      name: 'Support Bot',
    });
    const jwt = await signCredential(
      credential,
      fixtures.ownerKeyPair.privateKey,
      fixtures.ownerKeyPair.publicKey
    );

    await persistIssuedCredential({
      storePath: tempDir,
      shouldStore: true,
      credential,
      jwt,
      prefix: 'ownership',
      saveMetadata: async () => undefined,
    });

    const discovery = await discoverCredentialFiles(tempDir);
    expect(discovery.errors).toHaveLength(0);
    expect(discovery.credentials).toHaveLength(1);
    expect(discovery.credentials[0].source).toBe('vc');
    expect(discovery.credentials[0].issuer).toBe(fixtures.ownerDid);
    expect(discovery.credentials[0].subject).toBe(fixtures.agentDid);
    expect(discovery.credentials[0].types).toContain('AgentOwnershipCredential');
    expect(discovery.credentials[0].issuedAt || discovery.credentials[0].validFrom).toBeDefined();
  });

  it('vc list discovery finds legacy credentials directory JWT files', async () => {
    const fixtures = await createOwnerAndAgent(keystore);
    const credential = createOwnershipCredential(fixtures.ownerDid, fixtures.agentDid);
    const jwt = await signCredential(
      credential,
      fixtures.ownerKeyPair.privateKey,
      fixtures.ownerKeyPair.publicKey
    );

    const legacyFile = path.join(tempDir, 'credentials', 'legacy-ownership.jwt');
    await fs.promises.mkdir(path.dirname(legacyFile), { recursive: true });
    await fs.promises.writeFile(legacyFile, `${jwt}\n`, 'utf-8');

    const discovery = await discoverCredentialFiles(tempDir);
    expect(discovery.errors).toHaveLength(0);
    expect(discovery.legacyJwtFiles).toBe(1);
    expect(discovery.credentials).toHaveLength(1);
    expect(discovery.credentials[0].source).toBe('legacy');
    expect(discovery.credentials[0].filename).toBe('legacy-ownership.jwt');
  });

  it('keystore doctor reports a healthy state for a valid temp home', async () => {
    const fixtures = await createOwnerAndAgent(keystore);
    const credential = createOwnershipCredential(fixtures.ownerDid, fixtures.agentDid);
    const jwt = await signCredential(
      credential,
      fixtures.ownerKeyPair.privateKey,
      fixtures.ownerKeyPair.publicKey
    );

    await persistIssuedCredential({
      storePath: tempDir,
      shouldStore: true,
      credential,
      jwt,
      prefix: 'ownership',
      saveMetadata: async () => undefined,
    });

    const report = await runDoctor({ store: tempDir });
    expect(report.errors).toHaveLength(0);
    expect(report.identitiesCount).toBe(2);
    expect(report.keyFilesCount).toBe(2);
    expect(report.vcFilesCount).toBe(1);
    expect(report.directories.keys.exists).toBe(true);
    expect(report.directories.vc.exists).toBe(true);
    expect(report.directories.backups.exists).toBe(true);
    expect(report.directories.keys.writable).toBe(true);
    expect(report.directories.vc.writable).toBe(true);
    expect(report.directories.backups.writable).toBe(true);
  });
});

async function createOwnerAndAgent(keystore: Keystore): Promise<{
  ownerDid: string;
  agentDid: string;
  ownerKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array };
  agentKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array };
}> {
  const ownerKeyPair = await generateKeyPair();
  const agentKeyPair = await generateKeyPair();
  const ownerDid = publicKeyToDidKey(ownerKeyPair.publicKey);
  const agentDid = publicKeyToDidKey(agentKeyPair.publicKey);

  await keystore.storeIdentity(
    {
      did: ownerDid,
      type: 'owner',
      name: 'Owner',
      createdAt: new Date().toISOString(),
    },
    ownerKeyPair
  );
  await keystore.storeIdentity(
    {
      did: agentDid,
      type: 'agent',
      name: 'Agent',
      ownerDid,
      createdAt: new Date().toISOString(),
    },
    agentKeyPair
  );

  return {
    ownerDid,
    agentDid,
    ownerKeyPair,
    agentKeyPair,
  };
}
