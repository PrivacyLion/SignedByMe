# SignedByMe Integration Guide

**Users get PAID to log in. Enterprises get cryptographic identity.**

SignedByMe is a decentralized authentication system where users prove their identity with zero-knowledge proofs and receive Lightning payments for logging in.

---

## How It Works

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│   1. ENTERPRISE              2. USER                3. RESULT        │
│   Creates session            Scans QR              Gets paid +       │
│   with payment offer         Proves identity       Enterprise gets   │
│                              via app               verified token    │
│                                                                      │
│   ┌─────────┐    QR/Link    ┌─────────┐   Proof   ┌─────────┐       │
│   │ Your    │ ───────────▶  │ User's  │ ────────▶ │ Signed  │       │
│   │ Server  │               │ App     │           │ ByMe    │       │
│   └─────────┘  ◀─────────── └─────────┘ ◀──────── └─────────┘       │
│                  ID Token      Sats via Lightning                    │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**The user proves:**
- They control a DID (decentralized identifier)
- Their identity via STWO zero-knowledge proof
- Optionally: membership in a group you define

**You receive:**
- Signed OIDC-compatible ID token
- Cryptographic attestation of identity
- Proof of payment (Lightning preimage)

---

## Two Authentication Modes

### Basic Login
Any user with the SignedByMe app can authenticate.

```json
{
  "require_membership": false
}
```

Best for: Public apps, marketplaces, open communities

### Membership-Verified Login
Only users in your defined group can authenticate.

```json
{
  "require_membership": true,
  "allowed_purposes": ["employees"]
}
```

Best for: Employee SSO, premium tiers, age-gated content, KYC'd users

---

## Use Cases

| Scenario | Mode | Verification | Example |
|----------|------|--------------|---------|
| Public app login | Basic | None needed | Social platform |
| Employee SSO | Membership | HR system | Corporate apps |
| Premium features | Membership | Payment processor | SaaS tiers |
| Age-gated content | Membership | ID verification service | Alcohol, gambling |
| KYC'd users | Membership | Compliance provider | Finance apps |
| Anti-sybil | Membership | Proof of humanity | Voting, airdrops |

**Note:** For membership scenarios, YOU define the verification requirements. SignedByMe stores and proves membership—verification is your responsibility.

---

## Why SignedByMe?

| Traditional Auth | SignedByMe |
|-----------------|------------|
| Users give up data | Users keep control |
| You store passwords | No passwords to breach |
| Users pay with attention (ads) | Users get paid in sats |
| Identity tied to email | Identity tied to cryptographic keys |
| Trust the provider | Trust the math |

---

## Quick Links

| Document | Description |
|----------|-------------|
| [Quick Start](./QUICK_START.md) | Get running in 5 minutes |
| [Authentication Flow](./AUTHENTICATION.md) | Detailed auth sequence |
| [Membership Proofs](./MEMBERSHIP.md) | Restrict access to groups |
| [API Reference](./API_REFERENCE.md) | Complete endpoint docs |
| [ID Token Claims](./ID_TOKEN.md) | JWT structure and validation |
| [Code Examples](./EXAMPLES.md) | Copy-paste snippets |
| [Troubleshooting](./TROUBLESHOOTING.md) | Common issues and fixes |

---

## Getting Started

### 1. Register as an Enterprise Client

Contact us to receive:
- `client_id` - Your unique identifier
- `client_secret` - For server-to-server calls (keep secret!)
- Configured `redirect_uris` - Your allowed callback URLs

### 2. Integrate the Flow

```bash
# Create a login session
curl -X POST https://api.beta.privacy-lion.com/v1/enterprise/session \
  -H "Content-Type: application/json" \
  -d '{"client_id": "your_client_id", "amount_sats": 100}'

# Response includes session_id and QR code data
```

### 3. Display QR to User

User scans with SignedByMe app → proves identity → gets paid → you get token.

**[Continue to Quick Start →](./QUICK_START.md)**

---

## API Base URL

```
https://api.beta.privacy-lion.com
```

## Support

- Documentation issues: Open a GitHub issue
- Security issues: ops@privacy-lion.com
- Integration help: ops@privacy-lion.com

---

## License

SignedByMe is dual-licensed under MIT and Apache 2.0. See [LICENSE](../LICENSE) for details.
