# agent-did

[![npm version](https://badge.fury.io/js/agent-did.svg)](https://www.npmjs.com/package/agent-did)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**W3C-compliant DID and Verifiable Credential toolkit for AI agents.**

Give your AI agents cryptographic identity. Issue ownership credentials, delegate capabilities with expiration, and prove authenticity using W3C standards.

```bash
npm install -g agent-did
```

**[Website](https://agent-did.xyz)** · **[Why this matters](docs/VISION.md)**

---

## Features

- **Create DIDs** - `did:key` method with Ed25519 cryptography
- **Issue Verifiable Credentials** - Ownership and capability credentials (JWT with EdDSA)
- **Verify credentials** - Cryptographic signature verification
- **Key rotation** - Maintain identity continuity
- **Privacy-preserving revocation** - W3C Bitstring Status List
- **Expiration warnings** - Monitor credential lifecycle
- **Encrypted storage** - AES-256-GCM with PBKDF2 (600k iterations)

**Standards:**
- [W3C DID Core 1.0](https://www.w3.org/TR/did-1.0/)
- [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/)

---

## Quick Start

### 1. Install

```bash
npm install -g agent-did

# Or use without installing
npx agent-did --help
```

### 2. Set Passphrase (Choose One)

**Option A: Environment Variable** (Recommended for automation)
```bash
export AGENT_DID_PASSPHRASE="your-secure-passphrase-here"
```

**Option B: Interactive Prompt** (Best for manual use)
```bash
# Just run commands - you'll be prompted for passphrase
agent-did create owner --name "Acme Corp"
# Enter passphrase to encrypt keys: ********
```

**Option C: No Encryption** (Development/testing only)
```bash
agent-did create owner --name "Test" --no-encryption
```

> 💡 For production, use environment variable or interactive prompt. Store passphrase in password manager.

### 3. Create Identities

```bash
# Create owner identity (you/your organization)
agent-did create owner --name "Acme Corp"

# Create agent identity
agent-did create agent \
  --name "Support Bot" \
  --owner did:key:z6MkhaXg...
```

### 4. Issue Credentials

```bash
# Prove ownership (auto-stored in keystore)
agent-did vc issue ownership \
  --issuer did:key:z6MkhaXg... \
  --subject did:key:z6Mkj7yH...
# ✓ Stored in keystore: ~/.agent-did/credentials/ownership-391f062c...json

# Grant capabilities (auto-stored in keystore)
agent-did vc issue capability \
  --issuer did:key:z6MkhaXg... \
  --subject did:key:z6Mkj7yH... \
  --scopes "read,write,refund" \
  --expires "2025-12-31T23:59:59Z"
# ✓ Stored in keystore: ~/.agent-did/credentials/capability-f9b4e891...json

# Optional: Also save to file
agent-did vc issue ownership --issuer ... --subject ... --out ownership.jwt

# Optional: Skip keystore storage (for immediate API use)
agent-did vc issue capability --issuer ... --subject ... --no-store
```

### 5. Verify Credentials

```bash
agent-did vc verify --file capability.jwt
```

---

## Core Concepts

### DID (Decentralized Identifier)

Self-sovereign cryptographic identity you control.

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
│    │   └─ Base58btc-encoded Ed25519 public key
│    └───── Method (derived from key)
└────────── Scheme
```

### Verifiable Credential

Cryptographically signed claim about a subject.

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "AgentCapabilityCredential"],
  "issuer": "did:key:z6Mk...",
  "validFrom": "2024-01-15T10:30:00Z",
  "validUntil": "2025-12-31T23:59:59Z",
  "credentialSubject": {
    "id": "did:key:z6Mk...",
    "scopes": ["read", "write"]
  }
}
```

**[Learn more about the vision →](docs/VISION.md)**

---

## Command Reference

### Identity Management

```bash
# Create owner
agent-did create owner --name <name>

# Create agent
agent-did create agent --name <name> --owner <did>

# List identities
agent-did list

# Inspect identity
agent-did inspect --did <did>

# Delete identity
agent-did delete --did <did> --yes
```

### Verifiable Credentials

```bash
# Issue ownership VC (auto-stored in keystore)
agent-did vc issue ownership \
  --issuer <did> --subject <did>

# Issue capability VC (auto-stored in keystore)
agent-did vc issue capability \
  --issuer <did> --subject <did> \
  --scopes <scopes> \
  --expires <iso-date>

# Optional flags:
#   --out <file>     Also save to file
#   --no-store       Skip keystore storage

# List stored VCs
agent-did vc list

# Verify VC
agent-did vc verify --file <file>

# Revoke VC
agent-did vc revoke --file <file> --reason <reason>

# Check revocation
agent-did vc check-revocation --file <file>

# Inspect VC (decode without verifying)
agent-did vc inspect --file <file>
```

### Authentication

```bash
# Sign challenge
agent-did auth sign \
  --did <did> \
  --challenge <nonce> \
  --audience <service> \
  --json

# Verify signature
agent-did auth verify \
  --did <did> \
  --payload <base64url> \
  --signature <base64url>
```

### Key Rotation

```bash
# Rotate key
agent-did rotate-key --did <did> --reason <reason>

# View rotation history
agent-did rotation-history
```

### Status Lists

```bash
# Create status list
agent-did vc create-status-list --issuer <did>

# View statistics
agent-did vc status-list-stats --issuer <did>
```

### Expiration Management

```bash
# Check expiring credentials
agent-did vc check-expiring --days 30

# Get summary
agent-did vc expiration-summary

# Check specific credential
agent-did vc check-credential-expiry --file <file>
```

### Keystore Operations

```bash
# Check keystore health
agent-did keystore doctor

# Backup keystore
agent-did keystore backup --out backup.json --encrypt

# Restore keystore
agent-did keystore restore --file backup.json
```

**[Complete command reference →](docs/GUIDE.md#commands)**

---

## Integration Examples

### Authentication Flow

> 💡 **Quick Start:** For production use, check out [`agent-did-server`](https://github.com/dantber/agent-did-server) - a ready-to-use authentication server that handles the entire flow below.

**Manual Implementation - Server generates challenge:**
```javascript
const challenge = crypto.randomUUID();
await redis.setex(`auth:${challenge}`, 120, 'pending');
res.json({ challenge });
```

**Client signs challenge:**
```bash
agent-did auth sign \
  --did did:key:z6Mkj7yH... \
  --challenge "$CHALLENGE" \
  --audience "api.example.com" \
  --json > auth.json
```

**Server verifies:**
```javascript
import { didKeyToPublicKey } from 'agent-did/did';
import { verify } from 'agent-did/crypto';

const { did, payloadEncoded, signature } = req.body;

// 1. Extract public key from DID
const publicKey = didKeyToPublicKey(did);

// 2. Verify Ed25519 signature
const isValid = await verify(
  Buffer.from(payloadEncoded),
  Buffer.from(signature, 'base64url'),
  publicKey
);

// 3. Check payload (nonce, expiration, audience)
const payload = JSON.parse(
  Buffer.from(payloadEncoded, 'base64url').toString()
);
```

**[More examples →](examples/)**

---

## Security

- **Encryption:** AES-256-GCM with PBKDF2 (600k iterations - OWASP 2024)
- **Signatures:** Ed25519 (EdDSA)
- **Key Storage:** Encrypted at rest, file permissions 0o600
- **Randomness:** Cryptographically secure (crypto.randomBytes)
- **Passphrase Options:** Environment variable, interactive prompt, or no encryption

**Best Practices:**
1. **Production:** Use encrypted keystore with strong passphrase (16+ chars)
2. **Development:** Interactive prompt or `--no-encryption` for testing
3. **CI/CD:** Set `AGENT_DID_PASSPHRASE` environment variable
4. Rotate keys quarterly or after compromise
5. Set expiration on all capability credentials
6. Backup keystore regularly with encryption
7. Use Bitstring Status List for production revocation

**[Security details →](docs/GUIDE.md#security)**

---

## Documentation

- **[VISION.md](docs/VISION.md)** - Why decentralized identity for AI agents matters
- **[GUIDE.md](docs/GUIDE.md)** - Complete usage guide with tutorials
- **[examples/](examples/)** - Integration examples

---

## Development

```bash
# Clone
git clone https://github.com/dantber/agent-did.git
cd agent-did

# Install dependencies
npm install

# Build
npm run build

# Test
npm test

# Smoke test
npm run smoke
```

**Requirements:**
- Node.js 20+
- TypeScript 5+

**[Contributing →](CONTRIBUTING.md)**

---

## License

MIT - see [LICENSE](LICENSE)

---

## Community

- **Website:** [agent-did.xyz](https://agent-did.xyz)
- **Issues:** [Report bugs](https://github.com/dantber/agent-did/issues)
- **npm:** [agent-did](https://www.npmjs.com/package/agent-did)

---

**Built with ❤️ for the agentic future**
