import * as os from 'os';
import * as path from 'path';
import {
  getStorePath,
  mapInvalidPassphraseError,
  resolveCliPath,
  resolveRolePassphrase,
} from '../src/cli/utils';

describe('role-based passphrase resolution', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.OWNER_DID_PASSPHRASE;
    delete process.env.AGENT_DID_OWNER_PASSPHRASE;
    delete process.env.AGENT_DID_PASSPHRASE;
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
  });

  it('prefers CLI flag over env for agent passphrase', async () => {
    process.env.AGENT_DID_PASSPHRASE = 'agent-env-passphrase';

    const passphrase = await resolveRolePassphrase({
      role: 'agent',
      purpose: 'decrypt',
      passphraseFlagValue: 'agent-flag-passphrase',
      passphraseFlagName: '--agent-passphrase',
    });

    expect(passphrase).toBe('agent-flag-passphrase');
  });

  it('uses OWNER_DID_PASSPHRASE for owner passphrase', async () => {
    process.env.OWNER_DID_PASSPHRASE = 'owner-passphrase';
    process.env.AGENT_DID_PASSPHRASE = 'legacy-passphrase';

    const passphrase = await resolveRolePassphrase({
      role: 'owner',
      purpose: 'decrypt',
      passphraseFlagName: '--owner-passphrase',
    });

    expect(passphrase).toBe('owner-passphrase');
  });

  it('falls back to legacy AGENT_DID_PASSPHRASE for owner and warns', async () => {
    process.env.AGENT_DID_PASSPHRASE = 'legacy-passphrase';
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    const passphrase = await resolveRolePassphrase({
      role: 'owner',
      purpose: 'decrypt',
      passphraseFlagName: '--owner-passphrase',
    });

    expect(passphrase).toBe('legacy-passphrase');
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('AGENT_DID_PASSPHRASE is a legacy fallback')
    );
  });

  it('throws explicit missing-passphrase error for agent key decryption', async () => {
    await expect(
      resolveRolePassphrase({
        role: 'agent',
        purpose: 'decrypt',
        passphraseFlagName: '--agent-passphrase',
      })
    ).rejects.toThrow(
      'Passphrase required to decrypt AGENT DID key. Set AGENT_DID_PASSPHRASE or use --agent-passphrase.'
    );
  });
});

describe('invalid passphrase error mapping', () => {
  it('maps authentication failure to owner-specific message', () => {
    const mapped = mapInvalidPassphraseError(
      new Error('Authentication failed'),
      'owner',
      '--owner-passphrase'
    );

    expect(mapped.message).toContain('Invalid passphrase for ISSUER/OWNER DID key.');
    expect(mapped.message).toContain('OWNER_DID_PASSPHRASE');
    expect(mapped.message).toContain('--owner-passphrase');
  });

  it('returns original error when it is not an authentication failure', () => {
    const original = new Error('Some other failure');
    const mapped = mapInvalidPassphraseError(original, 'agent', '--agent-passphrase');
    expect(mapped).toBe(original);
  });
});

describe('path resolution', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.AGENT_DID_HOME;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('expands AGENT_DID_HOME values containing ~', () => {
    process.env.AGENT_DID_HOME = '~/.agent-did-custom-home';
    expect(getStorePath()).toBe(path.join(os.homedir(), '.agent-did-custom-home'));
  });

  it('expands custom --store paths containing ~', () => {
    expect(getStorePath('~/custom-store')).toBe(path.join(os.homedir(), 'custom-store'));
  });

  it('resolves CLI output paths containing ~', () => {
    expect(resolveCliPath('~/custom-output.jwt')).toBe(
      path.join(os.homedir(), 'custom-output.jwt')
    );
  });
});
