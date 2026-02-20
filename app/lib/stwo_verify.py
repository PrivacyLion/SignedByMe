"""
Real STWO Proof Verification
Uses the compiled Rust verifier binary for cryptographically sound verification
Supports v1, v2, and v3 binding hash formats
"""
import subprocess
import json
import os
import hashlib
import time
from pathlib import Path
from typing import Tuple, Optional

# Path to the verifier binary (built by GitHub Actions)
VERIFIER_PATH = Path(__file__).resolve().parents[2] / "bin" / "stwo_verifier"

# Schema version constants
SCHEMA_VERSION_V2 = 2
SCHEMA_VERSION_V3 = 3
SCHEMA_VERSION_V4 = 4
DOMAIN_SEPARATOR_V2 = b"signedby.me:identity:v2"
DOMAIN_SEPARATOR_V3 = b"signedby.me:identity:v3"
DOMAIN_SEPARATOR_V4 = b"signedby.me:identity:v4"


def has_real_verifier() -> bool:
    """Check if the real STWO verifier binary is available"""
    return VERIFIER_PATH.exists() and os.access(VERIFIER_PATH, os.X_OK)


def compute_binding_hash_v3(
    did_pubkey: bytes,
    wallet_address: str,
    payment_hash: bytes,
    amount_sats: int,
    expires_at: int,
    ea_domain: str,
    nonce: bytes,
) -> bytes:
    """
    Compute the v3 binding hash (canonical, length-prefixed).
    
    Layout:
        schema_version: u8           // 1 byte (value: 3)
        domain_separator: [u8; 24]   // "signedby.me:identity:v3"
        did_pubkey_len: u8           // 1 byte
        did_pubkey: [u8; N]          // N bytes (33 typical)
        wallet_address_len: u8       // 1 byte
        wallet_address: [u8; M]      // M bytes UTF-8
        payment_hash: [u8; 32]       // 32 bytes
        amount_sats: u64             // 8 bytes LE
        expires_at: u64              // 8 bytes LE (unix timestamp)
        ea_domain_len: u8            // 1 byte
        ea_domain: [u8; K]           // K bytes UTF-8
        nonce: [u8; 16]              // 16 bytes
    """
    hasher = hashlib.sha256()
    
    # Schema version (1 byte)
    hasher.update(bytes([SCHEMA_VERSION_V3]))
    
    # Domain separator (24 bytes)
    hasher.update(DOMAIN_SEPARATOR_V3)
    
    # DID pubkey (length-prefixed)
    did_len = min(len(did_pubkey), 255)
    hasher.update(bytes([did_len]))
    hasher.update(did_pubkey[:did_len])
    
    # Wallet address (length-prefixed, UTF-8)
    wallet_bytes = wallet_address.encode('utf-8')
    wallet_len = min(len(wallet_bytes), 255)
    hasher.update(bytes([wallet_len]))
    hasher.update(wallet_bytes[:wallet_len])
    
    # Payment hash (fixed 32 bytes)
    hasher.update(payment_hash)
    
    # Amount sats (8 bytes LE)
    hasher.update(amount_sats.to_bytes(8, 'little'))
    
    # Expires at (8 bytes LE)
    hasher.update(expires_at.to_bytes(8, 'little'))
    
    # Enterprise domain (length-prefixed, UTF-8)
    domain_bytes = ea_domain.encode('utf-8')
    domain_len = min(len(domain_bytes), 255)
    hasher.update(bytes([domain_len]))
    hasher.update(domain_bytes[:domain_len])
    
    # Nonce (fixed 16 bytes)
    hasher.update(nonce)
    
    return hasher.digest()


def compute_binding_hash_v2(
    did_pubkey: bytes,
    wallet_address: str,
    payment_hash: bytes,
    timestamp: int,
) -> bytes:
    """Compute the v2 binding hash (legacy format)."""
    hasher = hashlib.sha256()
    hasher.update(DOMAIN_SEPARATOR_V2)
    hasher.update(did_pubkey)
    hasher.update(wallet_address.encode('utf-8'))
    hasher.update(payment_hash)
    hasher.update(timestamp.to_bytes(8, 'little'))
    return hasher.digest()


def hash_field(prefix: str, value: str) -> bytes:
    """Hash a string field with prefix for domain separation."""
    return hashlib.sha256(f"{prefix}:{value}".encode()).digest()


def compute_binding_hash_v4(
    did_pubkey: bytes,
    wallet_address: str,
    client_id: str,
    session_id: str,
    payment_hash: bytes,
    amount_sats: int,
    expires_at: int,
    nonce: bytes,
    ea_domain: str,
    purpose_id: int,
    root_id: str,
) -> bytes:
    """
    Compute v4 binding hash (circuit-friendly, all fixed-size fields).
    
    This is THE canonical binding that:
    - STWO proof must commit to
    - Membership proof must commit to
    - Prevents all replay attacks
    
    Layout (283 bytes fixed input):
        schema_version: u8           = 4                              // 1 byte
        domain_sep: [u8; 24]         = "signedby.me:identity:v4"      // 24 bytes
        did_pubkey: [u8; 33]         = compressed secp256k1 pubkey    // 33 bytes
        wallet_hash: [u8; 32]        = H("wallet:" || wallet_addr)    // 32 bytes
        client_id_hash: [u8; 32]     = H("client_id:" || client_id)   // 32 bytes
        session_id_hash: [u8; 32]    = H("session_id:" || session_id) // 32 bytes
        payment_hash: [u8; 32]       = from invoice                   // 32 bytes
        amount_sats: u64 LE          = payment amount                 // 8 bytes
        expires_at: u64 LE           = session expiry                 // 8 bytes
        nonce: [u8; 16]              = session nonce                  // 16 bytes
        ea_domain_hash: [u8; 32]     = H("ea_domain:" || domain)      // 32 bytes
        purpose_id: u8               = 0/1/2/3 enum                   // 1 byte
        root_id_hash: [u8; 32]       = H("root_id:" || root_id)       // 32 bytes
                                       or zeros if no membership
    """
    hasher = hashlib.sha256()
    
    # Schema version (1 byte)
    hasher.update(bytes([SCHEMA_VERSION_V4]))
    
    # Domain separator (24 bytes, padded)
    domain_sep = DOMAIN_SEPARATOR_V4.ljust(24, b'\x00')[:24]
    hasher.update(domain_sep)
    
    # DID pubkey (33 bytes, padded)
    did_padded = (did_pubkey + b'\x00' * 33)[:33]
    hasher.update(did_padded)
    
    # Wallet address hash (32 bytes)
    hasher.update(hash_field("wallet", wallet_address))
    
    # Client ID hash (32 bytes)
    hasher.update(hash_field("client_id", client_id))
    
    # Session ID hash (32 bytes)
    hasher.update(hash_field("session_id", session_id))
    
    # Payment hash (32 bytes)
    payment_padded = (payment_hash + b'\x00' * 32)[:32]
    hasher.update(payment_padded)
    
    # Amount sats (8 bytes LE)
    hasher.update(amount_sats.to_bytes(8, 'little'))
    
    # Expires at (8 bytes LE)
    hasher.update(expires_at.to_bytes(8, 'little'))
    
    # Nonce (16 bytes)
    nonce_padded = (nonce + b'\x00' * 16)[:16]
    hasher.update(nonce_padded)
    
    # EA domain hash (32 bytes)
    hasher.update(hash_field("ea_domain", ea_domain))
    
    # Purpose ID (1 byte)
    hasher.update(bytes([purpose_id]))
    
    # Root ID hash (32 bytes, zeros if no membership)
    if root_id:
        hasher.update(hash_field("root_id", root_id))
    else:
        hasher.update(b'\x00' * 32)
    
    return hasher.digest()


def verify_binding_hash(proof: dict) -> Tuple[bool, str]:
    """
    Verify the binding hash in a proof matches the computed hash from public inputs.
    This catches tampering attacks even without running the full STARK verification.
    """
    try:
        public_inputs = proof.get("public_inputs", {})
        stored_hash = bytes.fromhex(public_inputs.get("binding_hash", ""))
        schema_version = public_inputs.get("schema_version", 2)
        
        # Parse common inputs
        did_pubkey = bytes.fromhex(public_inputs.get("did_pubkey", ""))
        wallet_address = public_inputs.get("wallet_address", "")
        payment_hash = bytes.fromhex(public_inputs.get("payment_hash", ""))
        
        if len(payment_hash) != 32:
            return False, "Payment hash must be 32 bytes"
        
        if schema_version >= 3:
            # v3: Full security bindings
            amount_sats = public_inputs.get("amount_sats", 0)
            expires_at = public_inputs.get("expires_at", 0)
            ea_domain = public_inputs.get("ea_domain", "")
            nonce = bytes.fromhex(public_inputs.get("nonce", ""))
            
            if len(nonce) != 16:
                return False, "Nonce must be 16 bytes"
            
            computed_hash = compute_binding_hash_v3(
                did_pubkey,
                wallet_address,
                payment_hash,
                amount_sats,
                expires_at,
                ea_domain,
                nonce,
            )
        else:
            # v2: Legacy format
            timestamp = public_inputs.get("timestamp", 0)
            computed_hash = compute_binding_hash_v2(
                did_pubkey,
                wallet_address,
                payment_hash,
                timestamp,
            )
        
        if stored_hash != computed_hash:
            return False, "Binding hash mismatch - proof may have been tampered"
        
        return True, "Binding hash verified"
        
    except ValueError as e:
        return False, f"Invalid hex value: {e}"
    except Exception as e:
        return False, f"Binding hash verification error: {e}"


def verify_expiry(proof: dict) -> Tuple[bool, str]:
    """Check if the proof has expired."""
    public_inputs = proof.get("public_inputs", {})
    expires_at = public_inputs.get("expires_at", 0)
    
    if expires_at == 0:
        return True, "No expiry set"
    
    now = int(time.time())
    if now > expires_at:
        return False, f"Proof expired at {expires_at}, current time {now}"
    
    return True, "Proof not expired"


def verify_domain(proof: dict, expected_domain: Optional[str] = None) -> Tuple[bool, str]:
    """
    Verify the enterprise domain in the proof matches the expected domain.
    This prevents cross-RP replay attacks.
    """
    if expected_domain is None:
        return True, "No domain verification requested"
    
    public_inputs = proof.get("public_inputs", {})
    schema_version = public_inputs.get("schema_version", 2)
    
    if schema_version < 3:
        return True, "v2 proofs don't have domain binding (consider upgrading)"
    
    proof_domain = public_inputs.get("ea_domain", "")
    
    # Normalize domains (lowercase, strip whitespace)
    expected_norm = expected_domain.lower().strip()
    proof_norm = proof_domain.lower().strip()
    
    if proof_norm != expected_norm:
        return False, f"Domain mismatch: expected '{expected_norm}', got '{proof_norm}'"
    
    return True, f"Domain verified: {proof_domain}"


def verify_amount(proof: dict, expected_amount: Optional[int] = None) -> Tuple[bool, str]:
    """
    Verify the amount in the proof matches the expected amount.
    This prevents payment substitution attacks.
    """
    if expected_amount is None:
        return True, "No amount verification requested"
    
    public_inputs = proof.get("public_inputs", {})
    schema_version = public_inputs.get("schema_version", 2)
    
    if schema_version < 3:
        return True, "v2 proofs don't have amount binding (consider upgrading)"
    
    proof_amount = public_inputs.get("amount_sats", 0)
    
    if proof_amount != expected_amount:
        return False, f"Amount mismatch: expected {expected_amount} sats, got {proof_amount} sats"
    
    return True, f"Amount verified: {proof_amount} sats"


def verify_stwo_proof(proof_json: str) -> Tuple[bool, str]:
    """
    Verify an STWO proof using the real Rust verifier.
    
    Args:
        proof_json: JSON string of the proof to verify
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not has_real_verifier():
        return False, "Real STWO verifier not available (binary not found)"
    
    try:
        result = subprocess.run(
            [str(VERIFIER_PATH)],
            input=proof_json,
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout for verification
        )
        
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        
        if result.returncode == 0 and stdout == "VALID":
            return True, "Proof cryptographically verified"
        elif result.returncode == 1 and stdout == "INVALID":
            return False, "Proof verification failed (invalid proof)"
        else:
            return False, f"Verifier error: {stderr or stdout or 'Unknown error'}"
            
    except subprocess.TimeoutExpired:
        return False, "Verification timed out"
    except Exception as e:
        return False, f"Verification failed: {str(e)}"


def verify_proof_dict(proof: dict) -> Tuple[bool, str]:
    """
    Verify an STWO proof from a dictionary.
    
    Args:
        proof: Proof dictionary
        
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        proof_json = json.dumps(proof)
        return verify_stwo_proof(proof_json)
    except json.JSONDecodeError as e:
        return False, f"Invalid proof format: {str(e)}"


def is_real_stwo_proof(proof: dict) -> bool:
    """Check if a proof is a real STWO proof (vs the mock version)"""
    return proof.get("version", "").startswith("stwo-real-")


def get_proof_version(proof: dict) -> str:
    """Get the version string of a proof"""
    return proof.get("version", "unknown")


def get_schema_version(proof: dict) -> int:
    """Get the schema version of a proof's binding hash"""
    return proof.get("public_inputs", {}).get("schema_version", 2)


# Legacy/mock verification for backwards compatibility
def verify_mock_proof(proof_json: str) -> Tuple[bool, str]:
    """
    Verify a mock STWO proof (for backwards compatibility).
    This is NOT cryptographically sound - just checks structure.
    """
    try:
        proof = json.loads(proof_json)
        
        # Check basic structure
        if not proof.get("valid", False):
            return False, "Proof marked as invalid"
        
        if "public_inputs" not in proof:
            return False, "Missing public inputs"
        
        if not proof.get("proof_hash"):
            return False, "Missing proof hash"
        
        # Check expiry
        expires_at = proof.get("public_inputs", {}).get("expires_at")
        if expires_at and time.time() > expires_at:
            return False, "Proof expired"
        
        return True, "Mock proof structure valid (NOT cryptographically verified)"
        
    except json.JSONDecodeError:
        return False, "Invalid JSON"
    except Exception as e:
        return False, f"Verification error: {str(e)}"


def verify_any_proof(
    proof_json: str,
    expected_domain: Optional[str] = None,
    expected_amount: Optional[int] = None,
) -> Tuple[bool, str]:
    """
    Verify any STWO proof - uses real verifier if available and proof is real,
    falls back to mock verification for legacy proofs.
    
    Also verifies:
    - Binding hash integrity (catches tampering)
    - Expiry timestamp
    - Domain binding (if expected_domain provided)
    - Amount binding (if expected_amount provided)
    """
    try:
        proof = json.loads(proof_json)
    except json.JSONDecodeError:
        return False, "Invalid JSON"
    
    # First, verify the binding hash (catches tampering without full STARK verification)
    if is_real_stwo_proof(proof):
        hash_valid, hash_msg = verify_binding_hash(proof)
        if not hash_valid:
            return False, f"Binding hash verification failed: {hash_msg}"
    
    # Check expiry
    expiry_valid, expiry_msg = verify_expiry(proof)
    if not expiry_valid:
        return False, expiry_msg
    
    # Check domain if provided
    domain_valid, domain_msg = verify_domain(proof, expected_domain)
    if not domain_valid:
        return False, domain_msg
    
    # Check amount if provided
    amount_valid, amount_msg = verify_amount(proof, expected_amount)
    if not amount_valid:
        return False, amount_msg
    
    # Check if it's a real STWO proof
    if is_real_stwo_proof(proof):
        if has_real_verifier():
            return verify_stwo_proof(proof_json)
        else:
            # SECURITY: Fail closed when verifier not available
            # Don't silently pass - the STARK proof is the core security guarantee
            import logging
            logging.getLogger(__name__).error(
                "SECURITY: STWO verifier binary not available - cannot verify proof"
            )
            return False, "STWO verifier not available - cannot verify cryptographic proof"
    else:
        # Legacy mock proof - reject in production
        return False, "Mock proofs not accepted - real STWO proof required"


def verify_proof_for_login(
    proof_json: str,
    expected_domain: str,
    expected_amount: int,
    expected_payment_hash: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Comprehensive verification for login flow.
    Verifies all security bindings required for SignedByMe login.
    
    Args:
        proof_json: The STWO proof JSON
        expected_domain: The enterprise domain (e.g., "acmecorp.com")
        expected_amount: The expected payment amount in satoshis
        expected_payment_hash: Optional payment hash to verify
        
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        proof = json.loads(proof_json)
    except json.JSONDecodeError:
        return False, "Invalid JSON"
    
    # Verify basic structure
    if not is_real_stwo_proof(proof):
        return False, "Login requires real STWO proof (mock proofs not accepted)"
    
    schema_version = get_schema_version(proof)
    if schema_version < 3:
        return False, f"Login requires schema v3 or higher (got v{schema_version})"
    
    # Verify binding hash
    hash_valid, hash_msg = verify_binding_hash(proof)
    if not hash_valid:
        return False, f"Binding hash failed: {hash_msg}"
    
    # Verify expiry
    expiry_valid, expiry_msg = verify_expiry(proof)
    if not expiry_valid:
        return False, expiry_msg
    
    # Verify domain (required for login)
    domain_valid, domain_msg = verify_domain(proof, expected_domain)
    if not domain_valid:
        return False, domain_msg
    
    # Verify amount (required for login)
    amount_valid, amount_msg = verify_amount(proof, expected_amount)
    if not amount_valid:
        return False, amount_msg
    
    # Verify payment hash if provided
    if expected_payment_hash:
        public_inputs = proof.get("public_inputs", {})
        proof_payment_hash = public_inputs.get("payment_hash", "")
        if proof_payment_hash.lower() != expected_payment_hash.lower():
            return False, f"Payment hash mismatch"
    
    # Run full STARK verification - REQUIRED
    if has_real_verifier():
        stark_valid, stark_msg = verify_stwo_proof(proof_json)
        if not stark_valid:
            return False, f"STARK verification failed: {stark_msg}"
        return True, "Full cryptographic verification passed (schema v3)"
    
    # SECURITY: Fail closed when verifier not available
    import logging
    logging.getLogger(__name__).error(
        "SECURITY: STWO verifier not available - login verification failed"
    )
    return False, "STWO verifier not available - cannot complete login verification"
