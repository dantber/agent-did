#!/usr/bin/env node

/**
 * Smoke test script for agent-did
 * Tests the full workflow: create owner, create agent, issue VC, verify VC, sign auth
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';

const TEST_STORE = path.join(os.tmpdir(), `agent-did-smoke-test-${Date.now()}`);
const PASSPHRASE = 'test-passphrase-for-smoke-test';

function run(cmd) {
  const env = { ...process.env, AGENT_DID_PASSPHRASE: PASSPHRASE };
  const result = execSync(cmd, {
    encoding: 'utf-8',
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  return result;
}

function cleanup() {
  try {
    fs.rmSync(TEST_STORE, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
}

console.log('=== Agent DID Smoke Test ===\n');
console.log(`Test store: ${TEST_STORE}\n`);

try {
  // Clean up any previous test store
  cleanup();

  // 1. Create owner
  console.log('1. Creating owner identity...');
  const ownerOutput = run(
    `node dist/cli/index.js create owner --name "Test Owner" --store "${TEST_STORE}" --json`
  );
  const ownerResult = JSON.parse(ownerOutput);
  const ownerDid = ownerResult.did;
  console.log(`   ✓ Owner created: ${ownerDid.slice(0, 40)}...`);

  // 2. Create agent
  console.log('2. Creating agent identity...');
  const agentOutput = run(
    `node dist/cli/index.js create agent --name "Test Agent" --owner "${ownerDid}" --store "${TEST_STORE}" --json`
  );
  const agentResult = JSON.parse(agentOutput);
  const agentDid = agentResult.did;
  console.log(`   ✓ Agent created: ${agentDid.slice(0, 40)}...`);

  // 3. List identities
  console.log('3. Listing identities...');
  const listOutput = run(`node dist/cli/index.js list --store "${TEST_STORE}" --json`);
  const identities = JSON.parse(listOutput);
  console.log(`   ✓ Found ${identities.length} identity(s)`);

  // 4. Inspect owner
  console.log('4. Inspecting owner identity...');
  const inspectOutput = run(
    `node dist/cli/index.js inspect --did "${ownerDid}" --store "${TEST_STORE}" --json`
  );
  const inspection = JSON.parse(inspectOutput);
  console.log(`   ✓ Owner type: ${inspection.type}`);
  console.log(`   ✓ Public key: ${inspection.publicKeyHex.slice(0, 20)}...`);

  // 5. Issue ownership VC
  console.log('5. Issuing ownership VC...');
  const vcFile = path.join(TEST_STORE, 'ownership-vc.json');
  run(
    `node dist/cli/index.js vc issue ownership --issuer "${ownerDid}" --subject "${agentDid}" --out "${vcFile}" --store "${TEST_STORE}"`
  );
  const vcContent = JSON.parse(fs.readFileSync(vcFile, 'utf-8'));
  console.log(`   ✓ VC issued and saved`);
  console.log(`   ✓ VC ID: ${vcContent.credentialId}`);

  // 6. Verify ownership VC
  console.log('6. Verifying ownership VC...');
  const verifyOutput = run(
    `node dist/cli/index.js vc verify --file "${vcFile}" --json`
  );
  const verifyResult = JSON.parse(verifyOutput);
  if (!verifyResult.valid) {
    throw new Error(`VC verification failed: ${verifyResult.reason}`);
  }
  console.log(`   ✓ VC verified successfully`);
  console.log(`   ✓ Issuer: ${verifyResult.issuer.slice(0, 40)}...`);

  // 7. Issue capability VC
  console.log('7. Issuing capability VC...');
  const capVcFile = path.join(TEST_STORE, 'capability-vc.json');
  run(
    `node dist/cli/index.js vc issue capability --issuer "${ownerDid}" --subject "${agentDid}" --scopes "read,write,admin" --out "${capVcFile}" --store "${TEST_STORE}"`
  );
  console.log(`   ✓ Capability VC issued`);

  // 8. Verify capability VC
  console.log('8. Verifying capability VC...');
  const capVerifyOutput = run(
    `node dist/cli/index.js vc verify --file "${capVcFile}" --json`
  );
  const capVerifyResult = JSON.parse(capVerifyOutput);
  if (!capVerifyResult.valid) {
    throw new Error(`Capability VC verification failed: ${capVerifyResult.reason}`);
  }
  console.log(`   ✓ Capability VC verified`);

  // 9. Sign auth challenge
  console.log('9. Signing auth challenge...');
  const authOutput = run(
    `node dist/cli/index.js auth sign --did "${agentDid}" --challenge "test-challenge-123" --audience "test-api" --store "${TEST_STORE}" --json`
  );
  const authResult = JSON.parse(authOutput);
  console.log(`   ✓ Challenge signed`);
  console.log(`   ✓ Algorithm: ${authResult.alg}`);
  console.log(`   ✓ Key ID: ${authResult.kid.slice(0, 40)}...`);

  // Summary
  console.log('\n=== Smoke Test Summary ===');
  console.log('✓ All tests passed!');
  console.log(`\nTest artifacts location: ${TEST_STORE}`);
  console.log('\nCommands tested:');
  console.log('  - create owner');
  console.log('  - create agent');
  console.log('  - list');
  console.log('  - inspect');
  console.log('  - vc issue ownership');
  console.log('  - vc issue capability');
  console.log('  - vc verify');
  console.log('  - auth sign');

} catch (error) {
  console.error('\n✗ Smoke test failed:');
  console.error(error.message);
  if (error.stderr) {
    console.error('Stderr:', error.stderr.toString());
  }
  if (error.stdout) {
    console.error('Stdout:', error.stdout.toString());
  }
  cleanup();
  process.exit(1);
}

cleanup();
console.log('\n✓ Cleanup complete');
