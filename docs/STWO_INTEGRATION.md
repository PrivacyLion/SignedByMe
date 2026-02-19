# STWO Integration (Production)

> **Status:** ✅ LIVE — Real Circle STARK proofs in production since Feb 17, 2026

SignedByMe uses [STWO](https://github.com/starkware-libs/stwo) (StarkWare's Circle STARK prover) for cryptographic identity proofs. This document describes the production implementation.

---

## What's Implemented

### Identity Proof Circuit

Real STWO Circle STARK proofs verify:

1. **DID Ownership** — User controls the private key for their DID
2. **Wallet Binding** — DID is cryptographically bound to Lightning wallet
3. **Session Binding** — Proof is bound to specific login session (prevents replay)

**Public Inputs:**
- `did_pubkey` — User's DID public key
- `wallet_address_hash` — Hash of Lightning wallet
- `binding_hash` — Session-specific binding (includes employer, amount, expiry)

**Private Inputs (never revealed):**
- `did_private_key`
- `wallet_signature`

### Performance

| Metric | Target | Actual |
|--------|--------|--------|
| Proof generation (mobile) | < 10s | ~1ms ✅ |
| Proof verification (server) | < 500ms | ~5ms ✅ |
| Proof size | < 50KB | ~2KB ✅ |

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     MOBILE APP (Android)                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  NativeBridge.kt ──JNI──▶ btcdid_core (Rust)                   │
│                              │                                  │
│                              ├── stwo_prover.rs (real STWO)    │
│                              ├── membership/merkle.rs          │
│                              └── secp256k1 signatures          │
│                                                                 │
│  Compiled for: arm64-v8a, x86_64 (with --features real-stwo)   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS + JSON
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     API SERVER (Python)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  app/routes/login_invoice.py                                   │
│       │                                                         │
│       ├── verify_stwo_proof() ──▶ stwo_verifier binary (Rust)  │
│       │                                                         │
│       └── verify_membership() ──▶ membership_verifier binary   │
│                                                                 │
│  Binaries at: /opt/sbm-api/bin/                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Proof Schema (v3)

The STWO proof JSON structure:

```json
{
  "version": 3,
  "circuit_type": "identity_binding_v3",
  "public_inputs": {
    "did_pubkey": "02a1b2c3...",
    "wallet_address_hash": "abc123...",
    "binding_hash": "def456...",
    "expires_at": 1704067200,
    "ea_domain": "acme.com",
    "amount_sats": 100
  },
  "stwo_proof_hash": "789xyz...",
  "commitment": {
    "r": "...",
    "s": "...",
    "hash": "..."
  },
  "proof_data": "base64-encoded-stark-proof..."
}
```

### Version History

| Version | Changes |
|---------|---------|
| v1 | Basic DID + wallet binding |
| v2 | Added `stwo_proof_hash` |
| v3 | Added `expires_at`, `ea_domain`, `amount_sats` in binding hash (prevents tampering) |

---

## Verification Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROOF VERIFICATION                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Parse proof JSON                                           │
│                                                                 │
│  2. Check version (must be ≥ 1)                                │
│                                                                 │
│  3. Verify STWO proof mathematically:                          │
│     - Deserialize proof_data                                   │
│     - Reconstruct public inputs                                │
│     - Run STARK verifier                                       │
│     - Confirm: proof is cryptographically valid                │
│                                                                 │
│  4. Verify binding (v3+):                                      │
│     - Recompute expected binding_hash from session params      │
│     - Confirm: proof's binding_hash matches                    │
│     - This prevents cross-session replay                       │
│                                                                 │
│  5. Verify signature:                                          │
│     - Check commitment signature with secp256k1                │
│     - Confirm: DID private key signed this proof               │
│                                                                 │
│  Result: User provably controls DID + wallet for THIS session  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Building the Rust Libraries

### For Android (mobile prover)

```bash
cd native/btcdid_core

# Set up NDK environment
export ANDROID_NDK_HOME=/path/to/ndk

# Build with real STWO (not mock)
cargo build --release --target aarch64-linux-android --features real-stwo
cargo build --release --target x86_64-linux-android --features real-stwo

# Copy to Android project
cp target/aarch64-linux-android/release/libbtcdid_core.so \
   ../app/src/main/jniLibs/arm64-v8a/

cp target/x86_64-linux-android/release/libbtcdid_core.so \
   ../app/src/main/jniLibs/x86_64/
```

### For Server (verifier binary)

```bash
cd native/btcdid_core

# Build verifier binary
cargo build --release --features real-stwo --bin stwo_verifier

# Deploy to server
scp target/release/stwo_verifier root@your-server:/opt/sbm-api/bin/
```

---

## Security Properties

### What STWO Proves

| Property | Guarantee |
|----------|-----------|
| **DID ownership** | User knows private key for claimed DID |
| **Wallet binding** | DID is bound to specific Lightning wallet |
| **Session binding** | Proof is valid only for this session (employer, amount, expiry) |
| **Non-transferable** | Proof cannot be reused by someone else |

### What STWO Does NOT Prove

| Property | How It's Verified Instead |
|----------|---------------------------|
| Payment occurred | Lightning preimage (separate check) |
| Group membership | Merkle proof (separate circuit) |
| Real-world identity | External KYC (your responsibility) |

### Attack Resistance

| Attack | Mitigation |
|--------|------------|
| Replay attack | Binding hash includes session-specific nonce |
| Cross-site replay | Binding hash includes `ea_domain` |
| Amount tampering | Binding hash includes `amount_sats` |
| Expired proof | Binding hash includes `expires_at`, checked server-side |
| Fake proof | STARK verification fails mathematically |

---

## Troubleshooting

### "STWO verification failed"

1. Check proof version matches expected
2. Verify binding hash was computed correctly
3. Ensure server has `stwo_verifier` binary installed
4. Check binary has execute permissions

### "Proof generation timeout"

On older devices, proof generation may take longer:
- Ensure sufficient memory (512MB+ free)
- Run in background thread
- Consider caching proofs for repeated logins

### "Library not found" (Android)

- Verify `.so` files are in correct `jniLibs/` subdirectory
- Check ABI matches device (arm64-v8a vs x86_64)
- Rebuild with `--features real-stwo`

---

## References

- [STWO GitHub](https://github.com/starkware-libs/stwo) — StarkWare's Circle STARK implementation
- [Circle STARKs Paper](https://eprint.iacr.org/2024/278) — The underlying cryptography
- [btcdid_core source](../native/btcdid_core/) — Our Rust implementation
