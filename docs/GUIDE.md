# agent-did Complete Guide

Comprehensive guide to using agent-did for AI agent identity management.

**[← Back to README](../README.md)** · **[Why this matters](VISION.md)** · **[Website](https://agent-did.xyz)**

---

## Table of Contents

- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Getting Started](#getting-started)
- [Command Reference](#command-reference)
- [Integration Patterns](#integration-patterns)
- [Advanced Features](#advanced-features)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Production Deployment](#production-deployment)

---

## Installation

### Prerequisites

- **Node.js 20+** (for native fetch support)
- **npm 9+** or **yarn 1.22+**
- **Unix-like OS** (macOS, Linux) or Windows with WSL2

### Install Globally

```bash
npm install -g agent-did

# Verify installation
agent-did --version
```

### Install Locally (Project Dependency)

```bash
npm install agent-did

# Use via npx
npx agent-did --version
```

### From Source

```bash
git clone https://github.com/dantber/agent-did.git
cd agent-did
npm install
npm run build
npm link

# Verify
agent-did --version
```

---

## Core Concepts

### DIDs (Decentralized Identifiers)

A DID is a globally unique identifier you control.

**Format:**
```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
│    │   └─ Base58btc-encoded Ed25519 public key
│    └───── Method (did:key)
└────────── Scheme
```

**Properties:**
- Self-sovereign (you control it, no registry)
- Cryptographically verifiable
- Resolvable to a DID Document
- Platform-agnostic

**DID Document Example:**
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:key:z6MkhaXg...",
  "verificationMethod": [{
    "id": "did:key:z6MkhaXg...#z6MkhaXg...",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6MkhaXg...",
    "publicKeyMultibase": "z6MkhaXg..."
  }],
  "authentication": ["did:key:z6MkhaXg...#z6MkhaXg..."],
  "assertionMethod": ["did:key:z6MkhaXg...#z6MkhaXg..."]
}
```

### Verifiable Credentials (VCs)

Cryptographically signed claims about a subject.

**Structure:**
```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "AgentCapabilityCredential"],
  "issuer": "did:key:z6Mk...",
  "validFrom": "2024-01-15T10:30:00Z",
  "validUntil": "2025-12-31T23:59:59Z",
  "credentialSubject": {
    "id": "did:key:z6Mk...",
    "scopes": ["read", "write", "refund:under:$1000"]
  }
}
```

**Properties:**
- Tamper-evident (any modification breaks signature)
- Verifiable offline (no API call needed)
- Portable (works across platforms)
- Privacy-preserving (selective disclosure possible)

### Credential Types

#### 1. Ownership Credentials

Prove that you own an agent.

```bash
agent-did vc issue ownership \
  --issuer did:key:z6Mk... \
  --subject did:key:z6Mk... \
  --out ownership.jwt
```

**Use cases:**
- Prove agent ownership to third parties
- Establish identity lineage
- Audit trails

#### 2. Capability Credentials

Grant specific permissions to an agent.

```bash
agent-did vc issue capability \
  --issuer did:key:z6Mk... \
  --subject did:key:z6Mk... \
  --scopes "read,write,admin" \
  --audience "https://agent-did.xyz" \
  --expires "2025-12-31T23:59:59Z" \
  --out capability.jwt
```

**Use cases:**
- Delegate API access
- Time-bound permissions
- Scoped authorization

---

## Getting Started

### Step-by-Step Tutorial

#### 1. Set Up Environment

**Choose one of three passphrase modes:**

**A. Role-specific environment variables** (Recommended for automation/CI-CD)
```bash
# Create secure passphrases (16+ characters)
export OWNER_DID_PASSPHRASE="owner-very-secure-passphrase"
export AGENT_DID_PASSPHRASE="agent-very-secure-passphrase"

# Optional: Set custom keystore location
export AGENT_DID_HOME="$HOME/.my-agents"
```

`AGENT_DID_OWNER_PASSPHRASE` is also accepted for owner/issuer operations. Legacy owner fallback from `AGENT_DID_PASSPHRASE` still works with a warning.

**B. Interactive Prompt** (Best for manual terminal use)
```bash
# No setup needed - you'll be prompted when running commands
agent-did create owner --name "Acme Corp"
# Enter passphrase to encrypt ISSUER/OWNER DID key: ********

agent-did create agent --name "Support Bot" --owner did:key:z6Mk...
# Enter passphrase to encrypt AGENT DID key: ********
```

**C. No Encryption** (Development/testing only - NOT for production)
```bash
# Keys stored in plaintext - use --no-encryption flag
agent-did create owner --name "Test" --no-encryption
# ⚠️  WARNING: Keys will be stored UNENCRYPTED on disk!
```

**Passphrase requirements (for encrypted modes):**
- Minimum 16 characters
- High entropy (mix of letters, numbers, symbols)
- Store in password manager (1Password, LastPass, etc.)
- Cannot be recovered if lost

**Mode comparison:**

| Mode                 | Security         | Use Case                  | Automation |
|----------------------|------------------|---------------------------|------------|
| Environment Variable | ✅ Encrypted      | Production, CI/CD         | ✅ Yes      |
| Interactive Prompt   | ✅ Encrypted      | Manual use, one-off tasks | ❌ No       |
| No Encryption        | ⚠️ **Plaintext** | Testing, development ONLY | ✅ Yes      |

#### 2. Create Owner Identity

```bash
agent-did create owner --name "Acme Corporation"
```

**Output:**
```
✓ Identity created successfully

DID         : did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
kid         : did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
name        : Acme Corporation
type        : owner
store       : /Users/you/.agent-did
createdAt   : 2024-01-15T10:30:00.000Z
```

**Save this DID** - you'll use it to create agents and issue credentials.

#### 3. Create Agent Identity

```bash
agent-did create agent \
  --name "Customer Support Bot" \
  --owner did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
# prompts for AGENT DID passphrase by default
```

**Output:**
```
✓ Identity created successfully

DID         : did:key:z6Mkj7yHGXW9TvRMu8HfkzZnT8sKN9mpPNTSFWAZSDzxe6V5
kid         : did:key:z6Mkj7yHGXW9TvRMu8HfkzZnT8sKN9mpPNTSFWAZSDzxe6V5#z6Mkj7yHGXW9TvRMu8HfkzZnT8sKN9mpPNTSFWAZSDzxe6V5
name        : Customer Support Bot
type        : agent
owner       : did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
store       : /Users/you/.agent-did
createdAt   : 2024-01-15T10:35:00.000Z
```

#### 4. List Identities

```bash
agent-did list
```

**Output:**
```
=== Identities ===

1. Acme Corporation (owner)
   DID: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
   Created: 2024-01-15T10:30:00.000Z

2. Customer Support Bot (agent)
   DID: did:key:z6Mkj7yHGXW9TvRMu8HfkzZnT8sKN9mpPNTSFWAZSDzxe6V5
   Owner: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
   Created: 2024-01-15T10:35:00.000Z
```

#### 5. Issue Ownership Credential

```bash
OWNER_DID_PASSPHRASE="$OWNER_PASS" agent-did vc issue ownership \
  --issuer did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK \
  --subject did:key:z6Mkj7yHGXW9TvRMu8HfkzZnT8sKN9mpPNTSFWAZSDzxe6V5 \
  --out ownership.jwt
```

**What you get:**
- A JWT file (`ownership.jwt`)
- Cryptographically signed proof of ownership
- Verifiable by anyone offline

#### 6. Issue Capability Credential

```bash
agent-did vc issue capability \
  --issuer did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK \
  --subject did:key:z6Mkj7yHGXW9TvRMu8HfkzZnT8sKN9mpPNTSFWAZSDzxe6V5 \
  --scopes "support:read,support:write,refund:under:$100" \
  --audience "https://api.acme.com" \
  --expires "2025-12-31T23:59:59Z" \
  --out capability.jwt
```

**Scopes explained:**
- `support:read` - Read support tickets
- `support:write` - Respond to tickets
- `refund:under:$100` - Process refunds under $100

#### 7. Verify Credential

```bash
agent-did vc verify --file capability.jwt
```

**Output:**
```
✓ Credential is valid

Issuer:     did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
Subject:    did:key:z6Mkj7yHGXW9TvRMu8HfkzZnT8sKN9mpPNTSFWAZSDzxe6V5
Issued:     2024-01-15T10:30:00.000Z
Expires:    2025-12-31T23:59:59Z
Type:       AgentCapabilityCredential
```

---

## Command Reference

### Identity Commands

#### create owner

Create a new owner identity.

```bash
agent-did create owner --name <name> [options]
```

**Options:**
- `--name <name>` - Name for this identity (required)
- `--store <path>` - Custom keystore location (default: `~/.agent-did`)
- `--owner-passphrase <passphrase>` - Passphrase for owner key encryption
- `--no-encryption` - Store key unencrypted (testing only)
- `--json` - Output as JSON

**Examples:**

```bash
# Basic usage
agent-did create owner --name "My Company"

# Non-interactive passphrase
agent-did create owner --name "My Company" --owner-passphrase "$OWNER_DID_PASSPHRASE"

# Custom keystore
agent-did create owner --name "My Company" --store ./keystore

# JSON output (for scripts)
agent-did create owner --name "My Company" --json
```

---

#### create agent

Create a new agent identity.

```bash
agent-did create agent --name <name> --owner <did> [options]
```

**Options:**
- `--name <name>` - Name for this agent (required)
- `--owner <did>` - Owner's DID (required)
- `--store <path>` - Custom keystore location
- `--agent-passphrase <passphrase>` - Passphrase for agent key encryption
- `--reuse-owner-passphrase` - Explicitly reuse owner passphrase for agent key
- `--owner-passphrase <passphrase>` - Owner passphrase (only with `--reuse-owner-passphrase`)
- `--no-encryption` - Store key unencrypted (testing only)
- `--json` - Output as JSON

**Examples:**

```bash
# Basic usage
agent-did create agent \
  --name "Support Bot" \
  --owner did:key:z6Mk...

# Explicit agent passphrase
agent-did create agent \
  --name "Support Bot" \
  --owner did:key:z6Mk... \
  --agent-passphrase "$AGENT_DID_PASSPHRASE"

# Explicitly reuse owner passphrase (opt-in)
agent-did create agent \
  --name "Support Bot" \
  --owner did:key:z6Mk... \
  --reuse-owner-passphrase \
  --owner-passphrase "$OWNER_DID_PASSPHRASE"

# Multiple agents for different purposes
agent-did create agent --name "Research Agent" --owner did:key:z6Mk...
agent-did create agent --name "Writing Agent" --owner did:key:z6Mk...
agent-did create agent --name "Coding Agent" --owner did:key:z6Mk...
```

---

#### list

List all identities in the keystore.

```bash
agent-did list [options]
```

**Options:**
- `--store <path>` - Custom keystore location
- `--json` - Output as JSON

**Examples:**

```bash
# Human-readable list
agent-did list

# JSON for scripting
agent-did list --json | jq '.[] | {name, did, type}'
```

---

#### inspect

Inspect an identity and view its DID Document.

```bash
agent-did inspect --did <did> [options]
```

**Options:**
- `--did <did>` - DID to inspect (required)
- `--store <path>` - Custom keystore location
- `--json` - Output as JSON

**Examples:**

```bash
# Inspect owner
agent-did inspect --did did:key:z6Mk...

# Get public key hex
agent-did inspect --did did:key:z6Mk... --json | jq -r '.publicKeyHex'

# View DID Document
agent-did inspect --did did:key:z6Mk... --json | jq '.didDocument'
```

---

#### delete

Permanently delete an identity.

```bash
agent-did delete --did <did> --yes [options]
```

**Options:**
- `--did <did>` - DID to delete (required)
- `--yes` - Confirm deletion (required for safety)
- `--store <path>` - Custom keystore location
- `--json` - Output as JSON

**⚠️ Warning:** This action is irreversible. All credentials signed by this DID become unverifiable.

**Examples:**

```bash
# Delete agent (with confirmation)
agent-did delete --did did:key:z6Mk... --yes

# Script usage
if confirm "Really delete?"; then
  agent-did delete --did "$AGENT_DID" --yes
fi
```

---

### Verifiable Credential Commands

#### vc issue ownership

Issue an ownership credential. **Automatically stored in keystore** (`~/.agent-did/credentials/`).

```bash
agent-did vc issue ownership \
  --issuer <did> \
  --subject <did> \
  [options]
```

**Options:**
- `--issuer <did>` - Owner's DID (required)
- `--subject <did>` - Agent's DID (required)
- `--owner-passphrase <passphrase>` - Passphrase for issuer owner key decryption
- `--out <file>` - Also save to file (optional)
- `--no-store` - Skip keystore storage (for immediate API use)
- `--store <path>` - Custom keystore location
- `--json` - Output as JSON

**Examples:**

```bash
# Basic ownership credential (auto-stored)
OWNER_DID_PASSPHRASE="$OWNER_PASS" agent-did vc issue ownership \
  --issuer did:key:z6Mk... \
  --subject did:key:z6Mk...
# ✓ Stored in keystore: ~/.agent-did/credentials/ownership-391f062c...json
# View with: agent-did vc list

# Also save to file
agent-did vc issue ownership \
  --issuer did:key:z6Mk... \
  --subject did:key:z6Mk... \
  --owner-passphrase "$OWNER_DID_PASSPHRASE" \
  --out ownership.jwt

# Skip storage (for immediate API use)
agent-did vc issue ownership \
  --issuer did:key:z6Mk... \
  --subject did:key:z6Mk... \
  --no-store | curl -X POST https://agent-did.xyz/credentials
```

---

#### vc issue capability

Issue a capability credential. **Automatically stored in keystore** (`~/.agent-did/credentials/`).

```bash
agent-did vc issue capability \
  --issuer <did> \
  --subject <did> \
  --scopes <scopes> \
  [options]
```

**Options:**
- `--issuer <did>` - Owner's DID (required)
- `--subject <did>` - Agent's DID (required)
- `--scopes <scopes>` - Comma-separated permissions (required)
- `--owner-passphrase <passphrase>` - Passphrase for issuer owner key decryption
- `--audience <aud>` - Service this credential is for
- `--expires <iso-date>` - Expiration date (ISO 8601)
- `--out <file>` - Also save to file (optional)
- `--no-store` - Skip keystore storage (for immediate API use)
- `--store <path>` - Custom keystore location
- `--json` - Output as JSON

**Scope Patterns:**

```bash
# Resource:action format
--scopes "tickets:read,tickets:write"

# With constraints
--scopes "refund:under:$100,approve:under:$500"

# Hierarchical
--scopes "api:read,api:admin,database:read"

# Wildcards (app-specific)
--scopes "support:*,billing:read"
```

**Examples:**

```bash
# Time-bound API access
agent-did vc issue capability \
  --issuer did:key:z6Mk... \
  --subject did:key:z6Mk... \
  --scopes "api:read,api:write" \
  --audience "https://agent-did.xyz" \
  --expires "2024-12-31T23:59:59Z" \
  --out capability.jwt

# Daily refresh pattern
agent-did vc issue capability \
  --issuer did:key:z6Mk... \
  --subject did:key:z6Mk... \
  --scopes "trading:execute" \
  --expires "$(date -u -d '+1 day' '+%Y-%m-%dT%H:%M:%SZ')" \
  --out daily-capability.jwt
```

---

#### vc verify

Verify a credential.

```bash
agent-did vc verify --file <path> [options]
```

**Options:**
- `--file <path>` - Path to JWT file (required)
- `--issuer <did>` - Expected issuer (optional, adds check)
- `--subject <did>` - Expected subject (optional, adds check)
- `--audience <aud>` - Expected audience (optional, adds check)
- `--domain <domain>` - Expected domain (optional, adds check)
- `--json` - Output as JSON

**Verification checks:**
1. Signature validity (Ed25519)
2. Expiration (if present)
3. Issuer DID format
4. Optional: issuer, subject, audience match

**Examples:**

```bash
# Basic verification
agent-did vc verify --file capability.jwt

# Strict verification (all constraints)
agent-did vc verify \
  --file capability.jwt \
  --issuer did:key:z6Mk... \
  --subject did:key:z6Mk... \
  --audience "https://agent-did.xyz"

# Automated check
if agent-did vc verify --file capability.jwt --json | jq -e '.valid'; then
  echo "Credential is valid"
else
  echo "Credential verification failed"
  exit 1
fi
```

---

### Authentication Commands

#### auth sign

Sign an authentication challenge.

```bash
agent-did auth sign \
  --did <did> \
  --challenge <nonce> \
  [options]
```

**Options:**
- `--did <did>` - Agent's DID (required)
- `--challenge <nonce>` - Server-provided nonce (required)
- `--agent-passphrase <passphrase>` - Passphrase for agent key decryption
- `--audience <aud>` - Service identifier
- `--domain <domain>` - Service domain
- `--expires-in <seconds>` - Expiration in seconds (default: 120)
- `--store <path>` - Custom keystore location
- `--json` - Output as JSON

**Examples:**

```bash
# Sign authentication challenge
AGENT_DID_PASSPHRASE="$AGENT_PASS" agent-did auth sign \
  --did did:key:z6Mk... \
  --challenge "abc123xyz" \
  --audience "agent-did.xyz" \
  --json > auth-response.json

# With custom expiration (5 minutes)
agent-did auth sign \
  --did did:key:z6Mk... \
  --challenge "$SERVER_NONCE" \
  --expires-in 300 \
  --json
```

---

## Integration Patterns

### Pattern 1: Agent Marketplace

**Scenario:** Agents bought/sold on a marketplace need portable identity.

```bash
# Marketplace creates agent
agent-did create agent --name "Trading Bot" --owner $SELLER_DID

# Seller issues capability credential
agent-did vc issue capability \
  --issuer $SELLER_DID \
  --subject $AGENT_DID \
  --scopes "trade:stocks,trade:crypto" \
  --expires "2024-12-31T23:59:59Z" \
  --out agent-capability.jwt

# Buyer receives agent DID + capability credential
# Buyer can verify ownership and capabilities
agent-did vc verify --file agent-capability.jwt

# When buyer wants to transfer
# 1. Seller revokes old credential
agent-did vc revoke --file agent-capability.jwt --reason "Transferred to buyer"

# 2. Buyer creates new ownership
agent-did vc issue ownership \
  --issuer $BUYER_DID \
  --subject $AGENT_DID \
  --out new-ownership.jwt
```

---

### Pattern 2: Multi-Agent Orchestration

**Scenario:** Multiple specialized agents collaborate on tasks.

```bash
# Create team of agents
OWNER_DID=$(agent-did create owner --name "AI Team" --json | jq -r '.did')

RESEARCHER=$(agent-did create agent --name "Researcher" --owner $OWNER_DID --json | jq -r '.did')
WRITER=$(agent-did create agent --name "Writer" --owner $OWNER_DID --json | jq -r '.did')
REVIEWER=$(agent-did create agent --name "Reviewer" --owner $OWNER_DID --json | jq -r '.did')

# Issue hierarchical capabilities
# Researcher: Full access
agent-did vc issue capability \
  --issuer $OWNER_DID \
  --subject $RESEARCHER \
  --scopes "research:*,data:read,data:write" \
  --out researcher-cred.jwt

# Writer: Read research, write articles
agent-did vc issue capability \
  --issuer $RESEARCHER \  # Delegated by researcher
  --subject $WRITER \
  --scopes "research:read,articles:write" \
  --out writer-cred.jwt

# Reviewer: Read-only
agent-did vc issue capability \
  --issuer $OWNER_DID \
  --subject $REVIEWER \
  --scopes "articles:read,articles:approve" \
  --out reviewer-cred.jwt
```

---

### Pattern 3: API Authentication

**Complete flow with Node.js backend.**

**Server (generate challenge):**
```javascript
// server.js
import express from 'express';
import crypto from 'crypto';

const app = express();
const challenges = new Map();

app.post('/auth/challenge', (req, res) => {
  const challenge = crypto.randomUUID();
  challenges.set(challenge, {
    created: Date.now(),
    used: false
  });

  // Clean up old challenges (5 minutes)
  setTimeout(() => challenges.delete(challenge), 5 * 60 * 1000);

  res.json({ challenge, expiresIn: 120 });
});
```

**Client (sign challenge):**
```bash
# Get challenge
CHALLENGE=$(curl -X POST https://agent-did.xyz/auth/challenge | jq -r '.challenge')

# Sign it
agent-did auth sign \
  --did $AGENT_DID \
  --challenge "$CHALLENGE" \
  --audience "agent-did.xyz" \
  --json > auth.json

# Send to server
curl -X POST https://agent-did.xyz/auth/verify \
  -H "Content-Type: application/json" \
  -d @auth.json
```

**Server (verify signature):**
```javascript
import { didKeyToPublicKey } from 'agent-did/did';
import { verify } from 'agent-did/crypto';

app.post('/auth/verify', async (req, res) => {
  const { did, payloadEncoded, signature } = req.body;

  // 1. Decode payload
  const payload = JSON.parse(
    Buffer.from(payloadEncoded, 'base64url').toString()
  );

  // 2. Check challenge exists and not used
  const challengeData = challenges.get(payload.nonce);
  if (!challengeData || challengeData.used) {
    return res.status(401).json({ error: 'Invalid challenge' });
  }

  // 3. Check expiration
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    return res.status(401).json({ error: 'Signature expired' });
  }

  // 4. Verify audience
  if (payload.aud !== 'agent-did.xyz') {
    return res.status(401).json({ error: 'Invalid audience' });
  }

  // 5. Extract public key from DID
  const publicKey = didKeyToPublicKey(did);

  // 6. Verify Ed25519 signature
  const isValid = await verify(
    Buffer.from(payloadEncoded),
    Buffer.from(signature, 'base64url'),
    publicKey
  );

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // 7. Mark challenge as used
  challengeData.used = true;

  // 8. Create session
  const token = createJWT({ did, sub: did });
  res.json({ success: true, token });
});
```

---

## Advanced Features

### Key Rotation

Rotate keys when compromised or as security hygiene.

```bash
# Rotate key
agent-did rotate-key \
  --did did:key:z6Mk... \
  --reason "Quarterly security rotation"
```

**Output:**
```
Rotating key for: My Organization (owner)
Reason: Quarterly security rotation

Generating new key...

✓ Key rotation completed successfully

Old DID: did:key:z6MkhaXg...
New DID: did:key:z6Mkj7yH...

IMPORTANT:
1. Update all references to use the new DID
2. Re-issue credentials using the new DID
3. Notify relying parties of the key rotation
4. The old key is now deprecated but still accessible
```

**Post-rotation checklist:**
- [ ] Update DID references in your systems
- [ ] Re-issue all credentials
- [ ] Notify services using old DID
- [ ] Update documentation
- [ ] Revoke old credentials

**View history:**
```bash
agent-did rotation-history
```

---

### Credential Revocation

**Simple revocation:**
```bash
agent-did vc revoke \
  --file capability.jwt \
  --reason "Agent misbehaved"
```

**Check if revoked:**
```bash
agent-did vc check-revocation --file capability.jwt
```

**Bitstring Status List (W3C):**

```bash
# 1. Create status list
agent-did vc create-status-list --issuer $OWNER_DID

# 2. View stats
agent-did vc status-list-stats --issuer $OWNER_DID

# Output:
# === Status List Statistics ===
# Purpose:      revocation
# Total:        131,072 entries
# Used:         45 entries
# Available:    131,027 entries
# Utilization:  0.03%
```

---

### Expiration Management

**Check expiring credentials:**
```bash
agent-did vc check-expiring --days 30
```

**Output:**
```
⚠️  Found 3 credential(s) expiring soon:

🔴 URGENT: capability-abc123
   Expires: 5 day(s)
   Issuer:  did:key:z6Mk...
   Subject: did:key:z6Mk...
   Date:    2024-01-20T10:30:00.000Z
```

**Get summary:**
```bash
agent-did vc expiration-summary
```

**Automated renewal script:**
```bash
#!/bin/bash
# renew-credentials.sh

# Check for expiring credentials (7 days)
EXPIRING=$(agent-did vc check-expiring --days 7 --json)

# Renew each
echo "$EXPIRING" | jq -r '.[] | .id' | while read ID; do
  echo "Renewing credential: $ID"

  # Re-issue with new expiration
  agent-did vc issue capability \
    --issuer $OWNER_DID \
    --subject $AGENT_DID \
    --scopes "$(get-scopes $ID)" \
    --expires "$(date -d '+1 year' -I)" \
    --out "renewed-${ID}.jwt"
done
```

---

### Backup & Restore

**Backup keystore:**
```bash
# Encrypted backup
agent-did keystore backup \
  --out backup-$(date +%Y%m%d).json \
  --encrypt
```

**Restore from backup:**
```bash
agent-did keystore restore --file backup-20240115.json
```

**Best practices:**
- Backup weekly (automated cron job)
- Store encrypted backups off-site (S3, encrypted volume)
- Test restore process quarterly
- Keep multiple versions (don't overwrite)

---

## Security Best Practices

### Passphrase Management

**Three Modes:**

1. **Environment Variable** (Production/CI-CD)
   ```bash
   export AGENT_DID_PASSPHRASE="$(openssl rand -base64 32)"
   ```
   - ✅ Works in automation
   - ✅ No interactive input needed
   - ⚠️ Visible in process list/shell history

2. **Interactive Prompt** (Manual Use)
   ```bash
   # No env var set - you'll be prompted
   agent-did create owner --name "Production"
   ```
   - ✅ Not stored in environment
   - ✅ Not visible in shell history
   - ❌ Requires interactive terminal

3. **No Encryption** (Testing Only)
   ```bash
   agent-did create owner --name "Test" --no-encryption
   ```
   - ⚠️ **NEVER use in production**
   - ✅ Fast for testing/development
   - ⚠️ Keys stored as plaintext

**Strong passphrase checklist (for encrypted modes):**
- [ ] Minimum 16 characters
- [ ] Mix of uppercase, lowercase, numbers, symbols
- [ ] Not based on dictionary words
- [ ] Not reused from other services
- [ ] Stored in password manager

**Generate strong passphrase:**
```bash
# macOS/Linux
openssl rand -base64 32

# Or use password manager generator
```

**Best practices by environment:**

| Environment | Recommended Mode | Notes |
|-------------|-----------------|-------|
| Production | Environment Variable | Use secrets manager (AWS Secrets, Vault) |
| CI/CD | Environment Variable | Set in pipeline secrets |
| Development | Interactive Prompt or No Encryption | Interactive for shared machines, no-encryption for local dev |
| Testing | No Encryption | Fast, no passphrase management needed |

### Key Storage

**File permissions:**
```bash
# Verify keystore permissions
ls -la ~/.agent-did/keys/

# Should show: -rw------- (0o600)
# If not, fix:
chmod 600 ~/.agent-did/keys/*
```

**Keystore doctor:**
```bash
# Check for issues
agent-did keystore doctor
```

### Credential Lifecycle

**1. Always set expiration:**
```bash
# ✅ Good: Time-bound
agent-did vc issue capability \
  --scopes "api:read" \
  --expires "2025-12-31T23:59:59Z"

# ❌ Bad: No expiration
agent-did vc issue capability --scopes "api:read"
```

**2. Use shortest reasonable expiration:**
```bash
# High-risk operations: 1 day
--expires "$(date -d '+1 day' -I)"

# Regular operations: 90 days
--expires "$(date -d '+90 days' -I)"

# Low-risk, stable: 1 year
--expires "$(date -d '+1 year' -I)"
```

**3. Monitor and renew:**
```bash
# Daily cron job
0 0 * * * /path/to/renew-credentials.sh
```

### Audit Logging

**Audit log location:**
```
~/.agent-did/audit-log.jsonl
```

**Review audit trail:**
```bash
# View recent actions
tail -f ~/.agent-did/audit-log.jsonl | jq .

# Filter by event type
jq 'select(.eventType == "CREDENTIAL_ISSUED")' ~/.agent-did/audit-log.jsonl

# Find credential revocations
jq 'select(.eventType == "CREDENTIAL_REVOKED")' ~/.agent-did/audit-log.jsonl
```

---

## Troubleshooting

### Common Issues

#### "Passphrase required but not available" error

**Cause:** No passphrase provided and not running in interactive terminal.

**Solution:**
```bash
# Option 1: Set environment variable
export AGENT_DID_PASSPHRASE="your-passphrase"

# Option 2: Run in interactive terminal (will prompt)
agent-did list

# Option 3: Use no encryption (testing only)
agent-did list --no-encryption
```

#### "Authentication failed" error

**Cause:** Wrong passphrase or corrupted keystore.

**Solution:**
```bash
# 1. Verify passphrase is set
echo $AGENT_DID_PASSPHRASE

# 2. Try with explicit passphrase
AGENT_DID_PASSPHRASE="your-passphrase" agent-did list

# 3. If keys were created with --no-encryption
agent-did list --no-encryption

# 4. Check keystore integrity
agent-did keystore doctor --check-decrypt
```

#### Mixed encrypted/unencrypted keystores

**Symptom:** Some commands work, others fail with authentication errors.

**Cause:** Some keys were created with `--no-encryption`, others with passphrase.

**Solution:**
```bash
# Check which keys are encrypted
agent-did keystore doctor

# For encrypted keys, use passphrase
export AGENT_DID_PASSPHRASE="your-passphrase"
agent-did list

# For unencrypted keys, use flag
agent-did list --no-encryption
```

#### "DID not found" error

**Cause:** DID doesn't exist in keystore.

**Solution:**
```bash
# List all DIDs
agent-did list

# Verify DID format
echo "did:key:z6Mk..." | grep -E '^did:key:z[A-Za-z0-9]+$'

# Check if in different keystore
agent-did list --store /path/to/other/keystore
```

#### "Credential has expired" error

**Cause:** Credential's `validUntil` date has passed.

**Solution:**
```bash
# Check expiration
agent-did vc inspect --file credential.jwt | jq '.payload.exp'

# Re-issue with new expiration
agent-did vc issue capability \
  --issuer $ISSUER_DID \
  --subject $SUBJECT_DID \
  --scopes "..." \
  --expires "2025-12-31T23:59:59Z" \
  --out renewed.jwt
```

#### Build/installation issues

```bash
# Clear npm cache
npm cache clean --force

# Reinstall
npm uninstall -g agent-did
npm install -g agent-did

# Verify Node.js version
node --version  # Should be 20+
```

---

## Production Deployment

### Passphrase Management in Production

**⚠️ CRITICAL: Always use encrypted keystores in production**

**Recommended approaches:**

1. **Secrets Manager** (Best)
   ```bash
   # AWS Secrets Manager
   export AGENT_DID_PASSPHRASE=$(aws secretsmanager get-secret-value \
     --secret-id agent-did-passphrase \
     --query SecretString \
     --output text)

   # HashiCorp Vault
   export AGENT_DID_PASSPHRASE=$(vault kv get -field=passphrase secret/agent-did)
   ```

2. **Kubernetes Secrets**
   - See Kubernetes section below for configuration

3. **Environment Variables** (Acceptable)
   ```bash
   # .env file (never commit!)
   AGENT_DID_PASSPHRASE=<strong-passphrase>
   AGENT_DID_HOME=/var/lib/agent-did
   ```

**❌ NEVER use `--no-encryption` in production** - Keys would be stored as plaintext on disk.

### Environment Setup

```bash
# .env file (never commit!)
AGENT_DID_PASSPHRASE=<strong-passphrase>
AGENT_DID_HOME=/var/lib/agent-did
```

### Docker Deployment

**Dockerfile:**
```dockerfile
FROM node:20-alpine

RUN npm install -g agent-did

# Create keystore directory
RUN mkdir -p /keystore && chmod 700 /keystore

WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD agent-did list --json || exit 1

ENTRYPOINT ["agent-did"]
```

**Usage:**
```bash
docker build -t agent-did .

docker run -it \
  -e AGENT_DID_PASSPHRASE="$PASSPHRASE" \
  -v ./keystore:/keystore \
  agent-did list
```

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: agent-did-passphrase
type: Opaque
stringData:
  passphrase: <strong-passphrase>

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: agent-did-keystore
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-did
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agent-did
  template:
    metadata:
      labels:
        app: agent-did
    spec:
      containers:
      - name: agent-did
        image: agent-did:latest
        env:
        - name: AGENT_DID_PASSPHRASE
          valueFrom:
            secretKeyRef:
              name: agent-did-passphrase
              key: passphrase
        - name: AGENT_DID_HOME
          value: /keystore
        volumeMounts:
        - name: keystore
          mountPath: /keystore
      volumes:
      - name: keystore
        persistentVolumeClaim:
          claimName: agent-did-keystore
```

### Monitoring

**Metrics to track:**
- Credential issuance rate
- Verification success/failure rate
- Expired credentials
- Key rotation events
- Failed authentication attempts

**Example monitoring script:**
```bash
#!/bin/bash
# monitor.sh

# Count expiring credentials
EXPIRING=$(agent-did vc check-expiring --days 7 --json | jq length)

# Alert if > threshold
if [ $EXPIRING -gt 10 ]; then
  send-alert "Warning: $EXPIRING credentials expiring soon"
fi

# Log metrics
echo "$(date),expiring=$EXPIRING" >> metrics.log
```

---

## Additional Resources

- **[README](../README.md)** - Quick start guide
- **[VISION](VISION.md)** - Why decentralized identity matters
- **[W3C_COMPLIANCE](W3C_COMPLIANCE.md)** - Standards compliance details
- **[MIGRATION_V2](MIGRATION_V2.md)** - VC Data Model v1.1 to v2.0
- **[Website](https://agent-did.xyz)** - Documentation and examples

---

**Need help?** [Open an issue](https://github.com/dantber/agent-did/issues) or check the [discussions](https://github.com/dantber/agent-did/discussions).
