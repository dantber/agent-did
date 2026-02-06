#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI=(node "$ROOT_DIR/dist/cli/index.js")

if [[ ! -f "${CLI[1]}" ]]; then
  echo "Missing compiled CLI at ${CLI[1]}. Run npm run build first."
  exit 1
fi

STORE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-did-passphrase-XXXXXX")"
trap 'rm -rf "$STORE_DIR"' EXIT

OWNER_PASS="OwnerPassphrase-1234!"
AGENT_PASS="AgentPassphrase-5678!"

echo "1) Create owner DID encrypted with passphrase A..."
OWNER_JSON="$("${CLI[@]}" create owner --name "Owner A" --store "$STORE_DIR" --owner-passphrase "$OWNER_PASS" --json)"
OWNER_DID="$(node -e 'const data = JSON.parse(process.argv[1]); process.stdout.write(data.did);' "$OWNER_JSON")"

echo "2) Create agent DID encrypted with passphrase B..."
AGENT_JSON="$("${CLI[@]}" create agent --name "Agent B" --owner "$OWNER_DID" --store "$STORE_DIR" --agent-passphrase "$AGENT_PASS" --json)"
AGENT_DID="$(node -e 'const data = JSON.parse(process.argv[1]); process.stdout.write(data.did);' "$AGENT_JSON")"

echo "3) Ownership VC issuance succeeds with only owner passphrase..."
OWNERSHIP_JSON="$(
  env -u AGENT_DID_PASSPHRASE OWNER_DID_PASSPHRASE="$OWNER_PASS" \
    "${CLI[@]}" vc issue ownership --issuer "$OWNER_DID" --subject "$AGENT_DID" --store "$STORE_DIR" --json
)"
node -e 'const data = JSON.parse(process.argv[1]); if (!data.credential) process.exit(1);' "$OWNERSHIP_JSON"

echo "4) Auth sign succeeds with only agent passphrase..."
AUTH_JSON="$(
  env -u OWNER_DID_PASSPHRASE -u AGENT_DID_OWNER_PASSPHRASE AGENT_DID_PASSPHRASE="$AGENT_PASS" \
    "${CLI[@]}" auth sign --did "$AGENT_DID" --challenge "nonce-123" --audience "agent-did.xyz" --domain "agent-did.xyz" --store "$STORE_DIR" --json
)"
node -e 'const data = JSON.parse(process.argv[1]); if (!data.signature) process.exit(1);' "$AUTH_JSON"

echo "5) Wrong or missing passphrase returns role-specific errors..."
set +e
WRONG_AGENT_OUTPUT="$(
  env -u OWNER_DID_PASSPHRASE -u AGENT_DID_OWNER_PASSPHRASE AGENT_DID_PASSPHRASE="wrong-passphrase" \
    "${CLI[@]}" auth sign --did "$AGENT_DID" --challenge "nonce-456" --audience "agent-did.xyz" --domain "agent-did.xyz" --store "$STORE_DIR" --json 2>&1
)"
WRONG_AGENT_EXIT=$?
set -e

if [[ $WRONG_AGENT_EXIT -eq 0 ]]; then
  echo "Expected auth sign to fail with wrong agent passphrase."
  exit 1
fi

if [[ "$WRONG_AGENT_OUTPUT" != *"Invalid passphrase for AGENT DID key"* ]]; then
  echo "Expected agent invalid-passphrase error message."
  echo "$WRONG_AGENT_OUTPUT"
  exit 1
fi

set +e
MISSING_OWNER_OUTPUT="$(
  env -u OWNER_DID_PASSPHRASE -u AGENT_DID_OWNER_PASSPHRASE -u AGENT_DID_PASSPHRASE \
    "${CLI[@]}" vc issue ownership --issuer "$OWNER_DID" --subject "$AGENT_DID" --store "$STORE_DIR" --json 2>&1
)"
MISSING_OWNER_EXIT=$?
set -e

if [[ $MISSING_OWNER_EXIT -eq 0 ]]; then
  echo "Expected ownership issuance to fail with missing owner passphrase."
  exit 1
fi

if [[ "$MISSING_OWNER_OUTPUT" != *"Passphrase required to decrypt ISSUER/OWNER DID key"* ]]; then
  echo "Expected owner missing-passphrase error message."
  echo "$MISSING_OWNER_OUTPUT"
  exit 1
fi

echo "✅ Acceptance checks passed."
echo "Owner DID: $OWNER_DID"
echo "Agent DID: $AGENT_DID"
