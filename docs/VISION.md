# Vision: The Missing Identity Layer for AI Agents

> *How do you trust an AI agent?*

In a world where autonomous agents negotiate contracts, access APIs, and make decisions on our behalf, we face a fundamental question about trust and control.

## The Problem

Today's AI agents lack portable, verifiable identity:

- **Centralized platforms control agent identities** (OpenAI, Anthropic, etc.)
- **No proof of ownership** when agents act on your behalf
- **No standardized way to delegate capabilities**
- **No revocation mechanism** when agents misbehave
- **No interoperability** between agent frameworks

### Real-World Scenarios

**Scenario 1: The Rogue Agent**
You deploy an AI agent with access to your company's API. Later, you discover it's making unauthorized purchases. How do you prove you own this agent? How do you revoke its access across all services?

**Scenario 2: The Trusted Delegate**
Your assistant AI needs to book travel, approve expenses under $1,000, and respond to customer emails. How do you delegate these specific capabilities with time limits? How do relying parties verify the delegation is legitimate?

**Scenario 3: The Platform Migration**
You've built workflows around OpenAI's agents. Now you want to switch to Anthropic. Your agent's identity is locked to the platform. You lose all credentials, permissions, and trust relationships.

## The Solution: Decentralized Identity

The answer isn't more surveillance or centralized control—it's **cryptographic identity**.

Just as TLS certificates transformed web security by enabling decentralized trust, decentralized identifiers will transform agent trust.

### Core Principles

| Problem | Solution |
|---------|----------|
| **Who owns this agent?** | DID (Decentralized Identifier) - Self-sovereign cryptographic identity you control |
| **Can I trust its credentials?** | VC (Verifiable Credential) - Cryptographically signed, tamper-proof attestations |
| **What can this agent do?** | Capability Credentials - Scoped permissions with expiration |
| **How do I revoke access?** | Bitstring Status List - Privacy-preserving revocation |
| **What if keys are compromised?** | Key Rotation - Maintain identity continuity with new keys |

## Why Decentralized?

### Self-Sovereignty
**Your keys, your identity.** No company can:
- Ban your agent's identity
- Lock you into their platform
- Shut down and take your credentials with them
- Track which services your agent accesses

### Interoperability
**One identity, many platforms.** Your agent can:
- Move between AI providers (OpenAI → Anthropic → Local)
- Authenticate to any service that accepts W3C standards
- Present the same credentials everywhere
- Build portable trust relationships

### Privacy-Preserving
**Selective disclosure.** Your agent can:
- Prove age without revealing birthdate
- Show capability without revealing all permissions
- Check revocation without revealing which credential

### Cryptographically Verifiable
**Trust through math, not authority.** Anyone can:
- Verify credentials offline (no API calls)
- Extract public keys from DIDs
- Confirm signatures are valid
- Check revocation status privately

## The Technical Approach

### DIDs (Decentralized Identifiers)

A globally unique identifier that you control, not a company.

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

- **did:** - Scheme
- **key** - Method (derived from public key)
- **z6Mk...** - Base58btc-encoded Ed25519 public key

**No central registry.** The identifier itself contains the public key. Your identity can't be taken away or censored.

### Verifiable Credentials

Tamper-proof claims about a subject, signed by an issuer.

Think of them as:
- **Passports** (but cryptographic)
- **API keys** (but delegatable and time-bound)
- **Authorization tokens** (but verifiable offline)

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

**Cryptographic guarantees:**
- Can't be forged (Ed25519 signature)
- Can't be modified (tamper-evident)
- Can be verified offline (no API needed)
- Can be revoked (privacy-preserving)

## Use Cases

### 1. Agent Marketplace
**Scenario:** You hire an AI agent from a marketplace to manage your social media.

**With agent-did:**
```bash
# Marketplace creates agent identity
agent-did create agent --name "SocialBot" --owner your-did

# You issue capability credential
agent-did vc issue capability \
  --issuer your-did \
  --subject agent-did \
  --scopes "twitter:post,twitter:reply" \
  --expires "2024-12-31T23:59:59Z"

# Agent authenticates to Twitter using credential
# Twitter verifies signature + checks expiration + validates scopes

# Agent misbehaves? Revoke instantly
agent-did vc revoke --file capability.jwt
```

**Benefit:** You maintain control. The marketplace can't impersonate your agent. Twitter doesn't need to trust the marketplace—only your signature.

### 2. Multi-Agent Systems
**Scenario:** You deploy multiple specialized agents (research, writing, coding) that need to collaborate.

**With agent-did:**
```bash
# Create owner identity (you)
agent-did create owner --name "Engineering Team"

# Create specialized agents
agent-did create agent --name "Researcher" --owner owner-did
agent-did create agent --name "Writer" --owner owner-did
agent-did create agent --name "Coder" --owner owner-did

# Issue hierarchical credentials
agent-did vc issue capability \
  --issuer owner-did \
  --subject researcher-did \
  --scopes "api:read,database:read"

agent-did vc issue capability \
  --issuer researcher-did \
  --subject writer-did \
  --scopes "api:read"  # Delegated subset
```

**Benefit:** Clear hierarchy. Provable ownership. Auditable delegation chain.

### 3. Regulatory Compliance
**Scenario:** Financial services require proof of agent authorization for trades.

**With agent-did:**
- Issue time-bound credentials (expires daily)
- Prove agent is owned by registered trader (ownership VC)
- Demonstrate specific permissions (capability VC with scopes)
- Provide complete audit trail (all VCs are cryptographically timestamped)
- Revoke instantly if needed (status list)

**Benefit:** Cryptographic non-repudiation. Clear accountability. Regulator can verify everything offline.

## Comparison to Alternatives

### vs. API Keys

| API Keys | agent-did |
|----------|-----------|
| ❌ Platform-specific | ✅ Universal |
| ❌ No standard format | ✅ W3C standard |
| ❌ Can't be delegated | ✅ Delegatable VCs |
| ❌ No proof of ownership | ✅ Cryptographic ownership |
| ❌ Centralized revocation | ✅ Privacy-preserving revocation |

### vs. OAuth

| OAuth | agent-did |
|-------|-----------|
| ❌ Requires online IdP | ✅ Offline verification |
| ❌ Platform lock-in | ✅ Self-sovereign |
| ❌ Tracks usage | ✅ Privacy-preserving |
| ❌ Complex flows | ✅ Simple signature verification |
| ❌ Tokens expire, no renewal path | ✅ Re-issuable VCs |

### vs. Traditional PKI/X.509

| X.509 | agent-did |
|-------|-----------|
| ❌ Requires Certificate Authority | ✅ Self-issued DIDs |
| ❌ Annual renewal costs | ✅ Free |
| ❌ CRL/OCSP reveals checks | ✅ Privacy-preserving status lists |
| ❌ Complex chain validation | ✅ Simple Ed25519 verification |
| ❌ Not designed for delegation | ✅ Built for capability delegation |

## Standards Compliance

agent-did implements **W3C Recommendations** (not drafts):

- ✅ **W3C DID Core 1.0** - Decentralized Identifiers ([spec](https://www.w3.org/TR/did-core/))
- ✅ **W3C VC Data Model 2.0** - Verifiable Credentials ([spec](https://www.w3.org/TR/vc-data-model-2.0/))
- ✅ **W3C Bitstring Status List** - Privacy-preserving revocation ([spec](https://www.w3.org/TR/vc-status-list-2021/))

**Why standards matter:**
- Interoperability with other implementations
- Long-term stability (W3C process)
- Legal recognition (increasing globally)
- Tool ecosystem (verifiers, validators, libraries)

## The Future

### What We Envision

**Short-term (6-12 months):**
- Agent marketplaces using DIDs for identity
- AI platforms accepting VCs for authorization
- Open-source agent frameworks integrating DIDs

**Medium-term (1-3 years):**
- Regulatory frameworks recognizing DIDs
- Cross-platform agent migration
- Decentralized agent reputation systems

**Long-term (3+ years):**
- Agent-to-agent trust networks
- Decentralized agent employment markets
- AI agents as first-class digital citizens

### How to Get Involved

1. **Use it** - Deploy agent-did in your projects
2. **Contribute** - Submit issues, PRs, documentation
3. **Advocate** - Demand DID support from AI platforms
4. **Build** - Create tools, integrations, and services

## Philosophy

We believe:

- **Agents should be sovereign** - Not controlled by platforms
- **Trust should be cryptographic** - Not based on corporate reputation
- **Privacy should be default** - Not an afterthought
- **Standards should be open** - Not proprietary

agent-did is our answer to the question: *"How do you trust an AI agent?"*

**The answer:** You don't trust the platform. You trust the math.

---

**Learn more:** [agent-did.xyz](https://agent-did.xyz)

Ready to build the identity layer for the agentic future? [Get started →](../README.md)
