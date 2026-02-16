# Security Audit Findings

*Audit Date: 2026-02-16*

## Critical Issues

### 1. STWO Verifier Not Wired (Server-Side)
**Status:** ⚠️ NEEDS FIX
**Location:** `app/lib/stwo_verify.py`
**Issue:** Python expects `bin/stwo_verifier` binary but it's not built/deployed.
**Risk:** STWO proofs are not actually cryptographically verified server-side. The server accepts any well-formed proof.
**Fix:** Build Rust verifier binary with `cargo build --release --features real-stwo --bin stwo_verifier` and deploy to `/opt/sbm-api/bin/`.

### 2. Signature Verification Stub
**Status:** ⚠️ NEEDS FIX  
**Location:** `app/lib/crypto.py:verify_secp256k1_signature_stub()`
**Issue:** Function always returns `True` without verifying signature.
**Risk:** Any message can be "signed" without actual cryptographic verification.
**Fix:** Implement using `coincurve` or `python-secp256k1` library.

### 3. API_SECRET Default Fallback
**Status:** ✅ MITIGATED (warns in logs)
**Location:** `app/lib/crypto.py`
**Issue:** Previously fell back silently to "dev-secret" if env var not set.
**Fix Applied:** Now emits warning if API_SECRET not set. Still uses insecure default but loudly.
**Production:** Must set `API_SECRET` environment variable with a strong random secret.

## Medium Issues

### 4. No Rate Limiting
**Location:** API endpoints
**Risk:** Brute force attacks, DoS
**Fix:** Add rate limiting middleware (e.g., `slowapi` for FastAPI)

### 5. Session Token in URL (QR/Deep Link)
**Location:** Login flow
**Issue:** Session tokens appear in QR codes and deep links which could be logged.
**Mitigation:** Tokens are short-lived (5 min default). Consider using reference tokens that are exchanged server-side.

## Low Issues

### 6. Verbose Logging
**Location:** Various
**Issue:** Some sensitive data may be logged (truncated proofs, partial tokens).
**Fix:** Audit log statements before production.

## Good Practices Already Implemented

- ✅ HTTPS for all API communication
- ✅ Android Keystore for key storage
- ✅ AES-GCM encryption for sensitive local data
- ✅ Nonce-based replay attack prevention
- ✅ Domain binding in proofs (prevents cross-RP replay)
- ✅ Binding hash verification (tamper detection)
- ✅ Short-lived sessions (5 min default)

## Pre-Production Checklist

- [ ] Set `API_SECRET` environment variable
- [ ] Build and deploy `stwo_verifier` binary
- [ ] Implement real secp256k1 signature verification
- [ ] Add rate limiting to API
- [ ] Review and sanitize all log statements
- [ ] Enable HSTS headers
- [ ] Security review of OIDC implementation
- [ ] Penetration testing
