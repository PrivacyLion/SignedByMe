# Authentication Flow

Detailed walkthrough of the SignedByMe authentication sequence.

---

## Overview

SignedByMe uses a hybrid flow combining:
- **OIDC Authorization Code** for token exchange
- **Lightning Network** for payment verification
- **STWO Zero-Knowledge Proofs** for identity attestation
- **Merkle Proofs** for optional group membership

---

## Sequence Diagram

```
┌─────────┐     ┌─────────┐     ┌──────────┐     ┌─────────┐     ┌──────────┐
│ Browser │     │  Your   │     │ SignedBy │     │  User   │     │Lightning │
│         │     │ Server  │     │ Me API   │     │  App    │     │ Network  │
└────┬────┘     └────┬────┘     └────┬─────┘     └────┬────┘     └────┬─────┘
     │               │               │                │               │
     │ 1. Click      │               │                │               │
     │   "Login"     │               │                │               │
     │──────────────▶│               │                │               │
     │               │               │                │               │
     │               │ 2. Create     │                │               │
     │               │    session    │                │               │
     │               │──────────────▶│                │               │
     │               │               │                │               │
     │               │ 3. session_id │                │               │
     │               │    + deep_link│                │               │
     │               │◀──────────────│                │               │
     │               │               │                │               │
     │ 4. QR code /  │               │                │               │
     │    deep link  │               │                │               │
     │◀──────────────│               │                │               │
     │               │               │                │               │
     │ 5. User scans ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│               │
     │    QR code                                     │               │
     │               │               │                │               │
     │               │               │ 6. Submit STWO │               │
     │               │               │    proof +     │               │
     │               │               │    invoice     │               │
     │               │               │◀───────────────│               │
     │               │               │                │               │
     │               │               │ 7. Verify      │               │
     │               │               │    proof       │               │
     │               │               │────┐           │               │
     │               │               │    │           │               │
     │               │               │◀───┘           │               │
     │               │               │                │               │
     │               │               │ 8. Pay invoice │               │
     │               │               │───────────────────────────────▶│
     │               │               │                │               │
     │               │               │ 9. Preimage    │               │
     │               │               │◀───────────────────────────────│
     │               │               │                │               │
     │               │               │ 10. Session    │               │
     │               │               │     complete   │               │
     │               │               │───────────────▶│               │
     │               │               │                │               │
     │               │ 11. Poll:     │                │               │
     │               │     complete  │                │               │
     │               │     + code    │                │               │
     │               │◀──────────────│                │               │
     │               │               │                │               │
     │               │ 12. Exchange  │                │               │
     │               │     code      │                │               │
     │               │──────────────▶│                │               │
     │               │               │                │               │
     │               │ 13. ID Token  │                │               │
     │               │◀──────────────│                │               │
     │               │               │                │               │
     │ 14. Logged in │               │                │               │
     │◀──────────────│               │                │               │
     │               │               │                │               │
```

---

## Step-by-Step Breakdown

### 1-3: Session Creation

Your server requests a new login session:

```bash
POST /v1/enterprise/session
{
  "client_id": "acme",
  "redirect_uri": "https://acme.com/callback",
  "amount_sats": 100
}
```

Response includes everything needed to display to the user:

```json
{
  "session_id": "sess_abc123",
  "deep_link": "signedby.me://login?session=sess_abc123&employer=Acme&amount=100",
  "qr_data": "signedby.me://login?session=sess_abc123&employer=Acme&amount=100",
  "expires_at": 1704067200
}
```

### 4-5: User Engagement

Display the QR code on desktop, or the deep link on mobile. User opens SignedByMe app and scans.

**Deep Link Format:**
```
signedby.me://login?session={session_id}&employer={name}&amount={sats}
```

| Parameter | Description |
|-----------|-------------|
| `session` | Unique session identifier |
| `employer` | Display name shown to user |
| `amount` | Satoshis the user will receive |

### 6-7: Identity Proof

The user's app generates and submits:

1. **STWO Proof** - Zero-knowledge proof binding:
   - Their DID (decentralized identifier)
   - The session parameters (employer, amount, expiry)
   - Their Lightning invoice for payment

2. **Lightning Invoice** - For receiving payment

3. **Binding Signature** - Links proof to this specific session

The API verifies:
- STWO proof is valid (cryptographic verification)
- DID matches the proof
- Session parameters match
- Invoice is properly formatted

### 8-9: Payment

SignedByMe (or the enterprise) pays the user's Lightning invoice:

```
Invoice: lnbc1000n1p...
Amount: 100 sats
→ Payment preimage returned as proof
```

The preimage cryptographically proves payment occurred.

### 10-11: Completion

Session status updates to `complete`. Your server polls and receives:

```json
{
  "session_id": "sess_abc123",
  "status": "complete",
  "auth_code": "code_xyz789...",
  "did": "did:key:z6MkhaXgBZD..."
}
```

### 12-13: Token Exchange

Standard OIDC code exchange:

```bash
POST /oidc/token
grant_type=authorization_code
code=code_xyz789...
client_id=acme
redirect_uri=https://acme.com/callback
```

Response:

```json
{
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 14: Done

User is authenticated. The ID token contains their verified identity.

---

## Session States

```
          ┌──────────┐
          │ pending  │ ◀─── Session created, waiting for user
          └────┬─────┘
               │
               ▼ User submits proof + invoice
        ┌──────────────────┐
        │ proof_submitted  │ ◀─── Proof verified, awaiting payment
        └────────┬─────────┘
                 │
                 ▼ Payment confirmed
       ┌───────────────────────┐
       │ payment_confirmed     │ ◀─── Generating auth code
       └───────────┬───────────┘
                   │
                   ▼
           ┌────────────┐
           │ complete   │ ◀─── Ready to exchange for token
           └────────────┘

        OR at any point:

           ┌────────────┐
           │ expired    │ ◀─── Session timed out (10 min default)
           └────────────┘

           ┌────────────┐
           │ failed     │ ◀─── Proof invalid, payment failed, etc.
           └────────────┘
```

---

## PKCE (Proof Key for Code Exchange)

For enhanced security, especially for public clients (SPAs, mobile apps), use PKCE:

### 1. Generate Code Verifier

```javascript
// Random 43-128 character string
const codeVerifier = generateRandomString(64);
```

### 2. Create Code Challenge

```javascript
// SHA256 hash, base64url encoded
const codeChallenge = base64url(sha256(codeVerifier));
```

### 3. Include in Session Creation

```bash
POST /v1/enterprise/session
{
  "client_id": "acme",
  "redirect_uri": "https://acme.com/callback",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256"
}
```

### 4. Include Verifier in Token Exchange

```bash
POST /oidc/token
grant_type=authorization_code
code=code_xyz789...
client_id=acme
redirect_uri=https://acme.com/callback
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

---

## With Membership Verification

When `require_membership: true` is set for your client, the flow includes additional verification:

### User Must Also Submit
- **Merkle witness proof** - Path from their leaf to the root
- **Root ID** - Which membership tree they're proving

### API Additionally Verifies
- User's leaf commitment is in the tree
- Tree's root matches a published root for your client
- Root's purpose matches allowed purposes

### Token Includes
```json
{
  "amr": ["did_sig", "stwo_proof", "ln_payment", "merkle"],
  "https://signedby.me/claims/membership_verified": true,
  "https://signedby.me/claims/membership_purpose": "employees",
  "https://signedby.me/claims/membership_root_id": "acme-employees-2024-02"
}
```

See [Membership Proofs](./MEMBERSHIP.md) for details.

---

## Security Considerations

### Replay Protection
- Each session has a unique `session_id` and `nonce`
- Auth codes are one-time use
- Binding signature includes session-specific data

### Payment Binding
- The STWO proof commits to the specific invoice
- Payment preimage proves THIS invoice was paid
- Can't reuse proofs across sessions

### Time Limits
- Sessions expire in 10 minutes (configurable)
- Auth codes expire in 5 minutes
- ID tokens expire in 1 hour

### HTTPS Required
- All redirect URIs must be HTTPS
- API only available over HTTPS
- HSTS enabled on all endpoints
