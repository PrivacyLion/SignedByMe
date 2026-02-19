"""
SignedByMe Login Invoice API
Handles invoice submission with STWO proof verification (v1, v2, v3)

v3 Security Bindings:
- expires_at: Bound into hash (prevents expiry tampering)
- ea_domain: Bound into hash (prevents cross-RP replay)
- amount_sats: Bound into hash (prevents payment substitution)
- nonce: Bound into hash (prevents replay attacks)

Option B (OIDC) Flow:
- Enterprise calls /confirm-payment with preimage (payer-side proof)
- SA verifies preimage, returns auth_code
- Enterprise exchanges auth_code at /oidc/token for id_token
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional
import time
import hashlib
import json
import secrets
import os
from pathlib import Path
import shelve

from .roots import get_canonical_root, get_purpose_id, PURPOSE_NONE
from . import session as session_module
from ..lib import strike

router = APIRouter(tags=["login"])


async def process_payout_if_enabled(
    session_id: str,
    client_id: str,
    invoice: str,
    did: str
) -> Optional[dict]:
    """
    Process payout if enabled for this client.
    
    Non-blocking: login succeeds even if payout fails.
    Idempotent: uses session_id as idempotency key.
    Server-authoritative: amount comes from clients.json, not request.
    
    Returns payout result dict or None if payout not enabled.
    """
    # Get client config
    clients = load_clients()
    client_config = clients.get(client_id, {})
    reward_policy = client_config.get("reward_policy", {})
    
    # Check if payout is enabled for this client
    if not reward_policy.get("enabled"):
        print(f"Payout skipped: reward not enabled for client {client_id}")
        return None
    
    provider = reward_policy.get("provider")
    if provider != "strike":
        print(f"Payout skipped: unknown provider '{provider}' for client {client_id}")
        return {"status": "skipped", "reason": f"unknown provider: {provider}"}
    
    # Get amount from SERVER config (never trust client-provided amount)
    amount_sats = reward_policy.get("amount_sats", 0)
    if amount_sats <= 0:
        print(f"Payout skipped: amount_sats is {amount_sats} for client {client_id}")
        return {"status": "skipped", "reason": "amount_sats not configured"}
    
    # Call Strike (non-blocking, idempotent)
    try:
        result = await strike.pay_invoice(
            bolt11=invoice,
            idempotency_key=session_id,  # Prevents double-pay on retries
            amount_sats=amount_sats,
            description=f"SignedByMe login reward for {client_id}"
        )
        
        payout_result = result.to_dict()
        
        # Log payout attempt for admin dashboard
        session_module.log_payout_attempt(
            session_id=session_id,
            client_id=client_id,
            invoice=invoice,
            result=payout_result
        )
        
        # Update canonical session (if it exists in the new session store)
        session_module.complete_session(
            session_id=session_id,
            did=did,
            payout_result=payout_result
        )
        
        print(f"Payout result for session {session_id}: {payout_result}")
        return payout_result
        
    except Exception as e:
        error_result = {"status": "failed", "error": str(e)}
        print(f"Payout error for session {session_id}: {e}")
        
        # Log failure
        session_module.log_payout_attempt(
            session_id=session_id,
            client_id=client_id,
            invoice=invoice,
            result=error_result
        )
        
        # Still complete the session (login succeeded, payout failed)
        session_module.complete_session(
            session_id=session_id,
            did=did,
            payout_result=error_result
        )
        
        return error_result

# Storage
VAR_DIR = Path(__file__).resolve().parents[2] / "var"
VAR_DIR.mkdir(parents=True, exist_ok=True)
SESSIONS_DB = str(VAR_DIR / "login_sessions.db")
NONCES_DB = str(VAR_DIR / "used_nonces.db")
CODES_DB = str(VAR_DIR / "oidc_codes.db")  # Shared with OIDC endpoints

# Clients config
CLIENTS_PATH = Path(__file__).resolve().parents[2] / "clients.json"


def load_clients() -> dict:
    """Load client configuration from clients.json and/or SBM_CLIENTS_JSON env var."""
    clients = {}
    
    # Load from file first
    if CLIENTS_PATH.exists():
        try:
            clients = json.loads(CLIENTS_PATH.read_text())
        except Exception as e:
            print(f"Warning: Could not load clients.json: {e}")
    
    # Override/extend with env var
    env_clients = os.environ.get("SBM_CLIENTS_JSON")
    if env_clients:
        try:
            env_data = json.loads(env_clients)
            clients.update(env_data)
        except Exception as e:
            print(f"Warning: Could not parse SBM_CLIENTS_JSON: {e}")
    
    return clients


def validate_api_key(api_key: str) -> tuple[str, dict]:
    """
    Validate API key and return (client_id, client_config).
    Raises HTTPException if invalid.
    """
    if not api_key:
        raise HTTPException(401, "Missing API key")
    
    clients = load_clients()
    
    for client_id, config in clients.items():
        if config.get("api_key") == api_key:
            return client_id, config
    
    raise HTTPException(401, "Invalid API key")


class DlcContractModel(BaseModel):
    """DLC contract for 90/10 payout split"""
    contract_id: str
    login_id: Optional[str] = None
    did: str
    user_pubkey_hex: str
    oracle: Optional[dict] = None
    outcome: str = "auth_verified"
    payout_split: Optional[dict] = None
    amount_sats: int
    created_at: int
    adaptor_point_hex: Optional[str] = None
    script_hash_hex: Optional[str] = None


class MembershipBundle(BaseModel):
    """
    Membership proof bundle.
    Client sends root_id only - server looks up canonical root.
    """
    purpose: str = Field(..., description="Membership purpose: 'allowlist' | 'issuer_batch'")
    root_id: str = Field(..., description="Root identifier (server looks up canonical root)")
    proof: str = Field(..., description="Membership proof (base64-encoded)")
    # NOTE: No 'root' field - server is authoritative
    # NOTE: No 'leaf_commitment' - never exposed


class LoginInvoiceRequest(BaseModel):
    """Request to submit a login invoice with STWO proof"""
    session_id: str = Field(..., description="Session ID from QR/deep link")
    invoice: str = Field(..., description="BOLT11 Lightning invoice")
    did: str = Field(..., description="User's DID (did:btcr:...)")
    enterprise: str = Field(..., description="Enterprise name/domain (informational)")
    amount_sats: Optional[int] = Field(None, description="Expected payment amount in sats")
    stwo_proof: Optional[str] = Field(None, description="STWO identity proof JSON")
    binding_signature: Optional[str] = Field(None, description="Signature binding proof to payment (legacy)")
    nonce: Optional[str] = Field(None, description="Nonce for replay protection (16 bytes hex)")
    dlc_contract: Optional[dict] = Field(None, description="DLC contract for 90/10 split")
    # NEW: Optional membership proof
    membership: Optional[MembershipBundle] = Field(None, description="Optional membership proof bundle")
    # Wallet address for binding hash (Lightning address, e.g., spark1pgss9...)
    wallet_address: Optional[str] = Field(None, description="Lightning wallet address for binding hash")
    # DEV-ONLY: Override payment hash for testing (requires SBM_ALLOW_TEST_PAYMENT_HASH=1)
    payment_hash_hex: Optional[str] = Field(None, description="DEV ONLY: Override payment hash (64 hex chars)")


class LoginInvoiceResponse(BaseModel):
    """Response after invoice submission"""
    ok: bool
    session_id: str
    stwo_verified: bool = False
    binding_verified: bool = False
    dlc_verified: bool = False
    schema_version: int = 2
    contract_id: Optional[str] = None
    message: Optional[str] = None
    # NEW: Membership verification result
    membership_verified: bool = False
    # NEW: Payout result (optional, only if reward enabled)
    payout: Optional[dict] = None


class SessionStatusResponse(BaseModel):
    """Session status for enterprise polling"""
    session_id: str
    invoice: Optional[str] = None
    did: Optional[str] = None
    enterprise: str
    verified: bool  # STWO + binding verified
    paid: bool
    schema_version: int = 2
    amount_sats: Optional[int] = None
    user_amount_sats: Optional[int] = None  # 90% to user
    operator_amount_sats: Optional[int] = None  # 10% to operator
    contract_id: Optional[str] = None  # DLC contract ID
    audit_hash: Optional[str] = None  # Settlement audit hash
    session_token: Optional[str] = None  # JWT for enterprise after verification
    created_at: int
    paid_at: Optional[int] = None
    # NEW: Membership status (exposed to enterprise)
    membership_verified: bool = False
    membership_purpose: Optional[str] = None
    membership_root_id: Optional[str] = None


class LoginStartRequest(BaseModel):
    """Request to start a new login session"""
    enterprise: str = Field(..., description="Enterprise name/domain")
    amount_sats: int = Field(500, description="Payment amount in sats")
    expiry_minutes: int = Field(5, description="Session expiry in minutes")
    # NEW: Optional required membership
    required_root_id: Optional[str] = Field(None, description="If set, user MUST prove membership against this root")


class LoginStartResponse(BaseModel):
    """Response with session details for QR/deep link"""
    session_id: str
    nonce: str  # 16 bytes hex (32 chars)
    enterprise: str
    client_id: str  # For mobile to fetch correct roots
    # Membership info (always present for Pattern A)
    required_root_id: Optional[str] = None  # The specific root to prove against
    purpose_id: int = 0  # 0=none, 1=allowlist, 2=issuer_batch, 3=revocation
    amount_sats: int
    expires_at: int
    qr_data: str  # Deep link URL


def sha256_hex(data: str) -> str:
    """Compute SHA-256 hash of string"""
    return hashlib.sha256(data.encode()).hexdigest()


def generate_nonce() -> str:
    """Generate a cryptographically secure 16-byte nonce (32 hex chars)"""
    return secrets.token_hex(16)


def extract_payment_hash(invoice: str) -> str:
    """
    Extract payment hash from BOLT11 invoice.
    For now, we use a simple heuristic - in production use a proper decoder.
    """
    # Payment hash is typically the last 64 hex chars before any trailing data
    # This is a simplification - real implementation should decode BOLT11
    clean = invoice.strip().lower()
    if clean.startswith("lnbc") or clean.startswith("lntb"):
        # Try to extract from the invoice structure
        # For demo purposes, hash the invoice itself
        return sha256_hex(invoice)[:64]
    return sha256_hex(invoice)[:64]


def verify_stwo_proof(
    proof_json: str,
    did: str,
    expected_domain: Optional[str] = None,
    expected_amount: Optional[int] = None,
) -> tuple[bool, int, str]:
    """
    Verify STWO identity proof.
    Uses the real Rust verifier if available, otherwise verifies binding hash.
    
    Returns:
        Tuple of (is_valid, schema_version, message)
    """
    try:
        # Import the verification library
        from ..lib.stwo_verify import (
            verify_any_proof,
            is_real_stwo_proof,
            get_schema_version,
            verify_proof_for_login,
        )
        
        proof = json.loads(proof_json)
        
        # Check DID matches first
        public_inputs = proof.get("public_inputs", {})
        proof_did = public_inputs.get("did_pubkey", "")
        
        # DID format: did:btcr:<pubkey>
        did_pubkey = did.replace("did:btcr:", "")
        if proof_did and proof_did != did_pubkey:
            return False, 0, f"DID mismatch: expected {did_pubkey}, got {proof_did}"
        
        schema_version = get_schema_version(proof)
        
        # For v3 proofs with domain/amount requirements, use comprehensive verification
        if schema_version >= 3 and (expected_domain or expected_amount):
            is_valid, message = verify_proof_for_login(
                proof_json,
                expected_domain=expected_domain or "",
                expected_amount=expected_amount or 0,
            )
            return is_valid, schema_version, message
        
        # Otherwise use standard verification
        is_valid, message = verify_any_proof(
            proof_json,
            expected_domain=expected_domain,
            expected_amount=expected_amount,
        )
        
        return is_valid, schema_version, message
        
    except Exception as e:
        print(f"STWO verification error: {e}")
        return False, 0, str(e)


def verify_binding_signature(
    proof_json: str,
    payment_hash: str,
    nonce: str,
    signature: str,
    did: str
) -> bool:
    """
    Verify the binding signature that links the proof to the payment.
    In production, this would verify the secp256k1 signature.
    For now, we do basic validation.
    
    NOTE: For v3 proofs, the binding is cryptographically enforced in the
    H_bind hash itself, so this is mainly for legacy v2 compatibility.
    """
    try:
        # Compute expected binding data
        proof_hash = sha256_hex(proof_json)
        
        # The binding should include proof_hash, payment_hash, and nonce
        # For now, just check the signature is present and non-empty
        if not signature or len(signature) < 20:
            return False
        
        return True
    except Exception as e:
        print(f"Binding verification error: {e}")
        return False


@router.post("/v1/login/start", response_model=LoginStartResponse)
def start_login_session(
    body: LoginStartRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Start a new login session. Returns session details for QR/deep link.
    The enterprise displays this to the user.
    
    Requires X-API-Key header for authentication.
    """
    # Validate API key and get client_id
    client_id, client_config = validate_api_key(x_api_key)
    
    session_id = secrets.token_urlsafe(16)
    nonce = generate_nonce()  # 16 bytes hex = 32 chars
    expires_at = int(time.time()) + (body.expiry_minutes * 60)
    
    # Determine required root (explicit > client default > none)
    required_root_id = body.required_root_id or client_config.get("default_root_id")
    
    # INVARIANT: If client requires membership (default: yes), a root MUST be resolvable
    if client_config.get("require_membership", True) and not required_root_id:
        raise HTTPException(
            400, 
            f"Client {client_id} has require_membership=true but no root_id provided and no default_root_id configured"
        )
    
    # Resolve purpose_id from root (Pattern A: always provide required_root_id)
    purpose_id = 0
    if required_root_id:
        from .roots import get_canonical_root
        root_info = get_canonical_root(required_root_id, client_id)
        if root_info:
            purpose_id = root_info.get("purpose_id", 0)
        else:
            # Root not found or doesn't belong to this client
            raise HTTPException(400, f"Invalid or inaccessible root_id: {required_root_id}")
    
    # Build deep link URL (always include client_id for mobile root fetching)
    qr_parts = [
        f"signedby.me://login?session={session_id}",
        f"enterprise={body.enterprise}",
        f"client_id={client_id}",  # For mobile to fetch correct roots
        f"amount={body.amount_sats}",
        f"nonce={nonce}",
        f"expires={expires_at}",
    ]
    if required_root_id:
        qr_parts.append(f"root_id={required_root_id}")
        qr_parts.append(f"purpose_id={purpose_id}")
    qr_data = "&".join(qr_parts)
    
    # Store session (pre-create for polling)
    session_data = {
        "session_id": session_id,
        "client_id": client_id,  # Track which enterprise owns this session
        "nonce": nonce,
        "enterprise": body.enterprise,
        "amount_sats": body.amount_sats,
        "expires_at": expires_at,
        "required_root_id": required_root_id,  # Required membership root
        "required_purpose_id": purpose_id,     # Purpose ID for the required root
        "invoice": None,
        "payment_hash": None,
        "did": None,
        "stwo_verified": False,
        "binding_verified": False,
        "membership_verified": False,
        "membership_purpose": None,
        "membership_root_id": None,
        "schema_version": 4,  # v4 binding hash
        "stwo_proof": None,
        "paid": False,
        "created_at": int(time.time()),
        "paid_at": None
    }
    
    with shelve.open(SESSIONS_DB) as sessions:
        sessions[session_id] = session_data
    
    return LoginStartResponse(
        session_id=session_id,
        nonce=nonce,
        required_root_id=required_root_id,
        purpose_id=purpose_id,
        enterprise=body.enterprise,
        client_id=client_id,  # For mobile root fetching
        amount_sats=body.amount_sats,
        expires_at=expires_at,
        qr_data=qr_data,
    )


import subprocess

# Path to the membership verifier binary
MEMBERSHIP_VERIFIER_PATH = Path(__file__).resolve().parents[2] / "bin" / "membership_verifier"


def has_membership_verifier() -> bool:
    """Check if the membership verifier binary is available."""
    return MEMBERSHIP_VERIFIER_PATH.exists() and os.access(MEMBERSHIP_VERIFIER_PATH, os.X_OK)


def verify_membership_proof(
    proof: str,
    root: str,
    binding_hash: bytes,
    purpose_id: int,
) -> bool:
    """
    Verify Merkle membership proof.
    
    The proof must assert:
    1. Prover knows leaf_secret such that leaf = H(leaf_secret || ...)
    2. MerkleVerify(leaf, path, root) == true
    3. binding_hash is correctly incorporated
    
    Calls the Rust membership_verifier binary via subprocess.
    """
    if not has_membership_verifier():
        print(f"Membership verifier not found at {MEMBERSHIP_VERIFIER_PATH}, returning False")
        return False
    
    # Build request JSON
    request_data = {
        "proof": proof,
        "root": root,
        "binding_hash": binding_hash.hex(),
        "purpose_id": purpose_id,
    }
    
    try:
        result = subprocess.run(
            [str(MEMBERSHIP_VERIFIER_PATH)],
            input=json.dumps(request_data),
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        
        if result.returncode == 0 and stdout == "VALID":
            print(f"Membership proof VALID")
            return True
        elif result.returncode == 1 and stdout == "INVALID":
            print(f"Membership proof INVALID")
            return False
        else:
            print(f"Membership verification error: {stderr or stdout}")
            return False
            
    except subprocess.TimeoutExpired:
        print("Membership verification timed out")
        return False
    except Exception as e:
        print(f"Membership verification exception: {e}")
        return False


@router.post("/v1/login/invoice", response_model=LoginInvoiceResponse)
async def submit_invoice(body: LoginInvoiceRequest):
    """
    Submit a login invoice with STWO proof and optional membership proof.
    
    For v3+ proofs, verifies:
    - Binding hash integrity (catches any tampering)
    - expires_at (prevents expiry extension)
    - ea_domain (prevents cross-RP replay)
    - amount_sats (prevents payment substitution)
    - nonce (prevents replay attacks)
    
    For v4+ with membership:
    - client_id binding (prevents cross-enterprise replay)
    - session_id binding (prevents cross-session replay)
    - root_id binding (ties membership to session)
    
    The enterprise will poll /v1/login/session/{session_id} to get the invoice
    and check verification/payment status.
    """
    stwo_verified = False
    binding_verified = False
    schema_version = 2
    membership_verified = False
    membership_purpose: Optional[str] = None
    membership_root_id: Optional[str] = None
    
    # Load existing session (required for v4)
    with shelve.open(SESSIONS_DB) as sessions:
        existing = sessions.get(body.session_id)
        if not existing:
            raise HTTPException(404, "Session not found")
        
        # Verify session hasn't expired
        if existing.get("expires_at", 0) > 0 and int(time.time()) > existing["expires_at"]:
            raise HTTPException(400, "Session expired")
        
        # Use stored nonce if not provided in request
        if not body.nonce and existing.get("nonce"):
            body.nonce = existing["nonce"]
    
    # Server-authoritative values
    server_client_id = existing.get("client_id", "")
    server_nonce = existing.get("nonce", "")
    server_expires_at = existing.get("expires_at", 0)
    required_root_id = existing.get("required_root_id")
    
    # Get client config for ea_domain (server-derived, not client-supplied)
    client_config = {}
    if server_client_id:
        clients = load_clients()
        client_config = clients.get(server_client_id, {})
    server_ea_domain = client_config.get("ea_domain", body.enterprise)
    
    # === Membership Setup ===
    purpose_id = PURPOSE_NONE
    root_id_for_hash = ""
    canonical_root = None
    
    if body.membership:
        # Check if enterprise required a specific root
        if required_root_id and body.membership.root_id != required_root_id:
            raise HTTPException(
                400, 
                f"Required root_id is {required_root_id}, got {body.membership.root_id}"
            )
        
        # Server-authoritative root lookup (scoped to session's client_id to prevent cross-client confusion)
        canonical_root = get_canonical_root(body.membership.root_id, server_client_id)
        if not canonical_root:
            raise HTTPException(400, f"Unknown or inaccessible root_id: {body.membership.root_id}")
        
        # Validate purpose matches
        if canonical_root["purpose"] != body.membership.purpose:
            raise HTTPException(
                400, 
                f"Purpose mismatch: root expects '{canonical_root['purpose']}', got '{body.membership.purpose}'"
            )
        
        # Check allowed purposes for this client
        allowed = client_config.get("allowed_purposes", [])
        if allowed and body.membership.purpose not in allowed:
            raise HTTPException(400, f"Purpose '{body.membership.purpose}' not allowed for this client")
        
        purpose_id = get_purpose_id(body.membership.purpose)
        root_id_for_hash = body.membership.root_id
    
    elif required_root_id:
        # Enterprise required membership but user didn't provide it
        raise HTTPException(400, f"Membership proof required for root_id: {required_root_id}")
    
    # Extract payment hash from invoice (or use dev override if enabled)
    if body.payment_hash_hex and os.environ.get("SBM_ALLOW_TEST_PAYMENT_HASH") == "1":
        # DEV ONLY: Use provided payment hash for testing
        if len(body.payment_hash_hex) != 64:
            raise HTTPException(400, "payment_hash_hex must be exactly 64 hex chars")
        try:
            bytes.fromhex(body.payment_hash_hex)  # Validate hex
        except ValueError:
            raise HTTPException(400, "payment_hash_hex must be valid hex")
        payment_hash = body.payment_hash_hex
        print(f"DEV: Using test payment_hash override: {payment_hash[:16]}...")
    elif body.payment_hash_hex:
        # Env flag not set but payment_hash_hex provided - ignore silently
        payment_hash = extract_payment_hash(body.invoice)
    else:
        payment_hash = extract_payment_hash(body.invoice)
    
    # Verify STWO proof if provided
    if body.stwo_proof:
        print(f"DEBUG STWO proof received (first 500 chars): {body.stwo_proof[:500]}")
        stwo_verified, schema_version, verify_msg = verify_stwo_proof(
            body.stwo_proof,
            body.did,
            expected_domain=server_ea_domain,  # Use server-derived domain
            expected_amount=body.amount_sats,
        )
        
        if stwo_verified:
            print(f"STWO verification passed (v{schema_version}): {verify_msg}")
            # For v3+, binding is enforced in the hash - no separate signature needed
            if schema_version >= 3:
                binding_verified = True
        else:
            print(f"STWO proof verification failed for session {body.session_id}: {verify_msg}")
    
    # Legacy: Verify binding signature if STWO proof was provided (v2)
    if body.stwo_proof and body.binding_signature and body.nonce and not binding_verified:
        # Check nonce not reused
        with shelve.open(NONCES_DB) as nonces:
            if body.nonce in nonces:
                raise HTTPException(400, "Nonce already used (replay attack?)")
            nonces[body.nonce] = int(time.time())
        
        binding_verified = verify_binding_signature(
            proof_json=body.stwo_proof,
            payment_hash=payment_hash,
            nonce=body.nonce,
            signature=body.binding_signature,
            did=body.did
        )
    
    # For v3+ proofs, mark nonce as used if binding verified
    if schema_version >= 3 and binding_verified and body.nonce:
        with shelve.open(NONCES_DB) as nonces:
            if body.nonce not in nonces:
                nonces[body.nonce] = int(time.time())
    
    # === Verify membership proof (if present and STWO passed) ===
    if body.membership and stwo_verified and binding_verified and canonical_root:
        # Compute v4 binding hash for membership verification
        from ..lib.stwo_verify import compute_binding_hash_v4
        
        did_pubkey_hex = body.did.replace("did:btcr:", "")
        did_pubkey = bytes.fromhex(did_pubkey_hex) if did_pubkey_hex else b""
        
        # Use wallet_address if provided, fall back to did for backwards compat
        wallet_addr_for_hash = body.wallet_address or body.did
        
        binding_hash = compute_binding_hash_v4(
            did_pubkey=did_pubkey,
            wallet_address=wallet_addr_for_hash,
            client_id=server_client_id,
            session_id=body.session_id,
            payment_hash=bytes.fromhex(payment_hash),
            amount_sats=body.amount_sats or 0,
            expires_at=server_expires_at,
            nonce=bytes.fromhex(server_nonce) if server_nonce else b"",
            ea_domain=server_ea_domain,
            purpose_id=purpose_id,
            root_id=root_id_for_hash,
        )
        
        membership_verified = verify_membership_proof(
            proof=body.membership.proof,
            root=canonical_root["root"],
            binding_hash=binding_hash,
            purpose_id=purpose_id,
        )
        
        if membership_verified:
            membership_purpose = body.membership.purpose
            membership_root_id = body.membership.root_id
            print(f"Membership verified: purpose={membership_purpose}, root={membership_root_id}")
        else:
            print(f"Membership proof failed for session {body.session_id}")
    
    # Verify DLC contract if provided
    dlc_verified = False
    contract_id = None
    user_amount_sats = None
    operator_amount_sats = None
    
    if body.dlc_contract:
        try:
            dlc = body.dlc_contract
            contract_id = dlc.get("contract_id")
            
            # Verify DLC matches the session
            if dlc.get("did") == body.did and dlc.get("amount_sats") == body.amount_sats:
                dlc_verified = True
                
                # Calculate payout split (default 90/10)
                payout_split = dlc.get("payout_split", {"user_pct": 90, "operator_pct": 10})
                user_pct = payout_split.get("user_pct", 90)
                if body.amount_sats:
                    user_amount_sats = (body.amount_sats * user_pct) // 100
                    operator_amount_sats = body.amount_sats - user_amount_sats
                
                print(f"DLC contract verified: {contract_id} (90/10 split)")
            else:
                print(f"DLC contract mismatch: DID or amount doesn't match")
        except Exception as e:
            print(f"DLC verification error: {e}")
    
    # Store/update session
    session_data = {
        "session_id": body.session_id,
        "client_id": server_client_id,
        "invoice": body.invoice,
        "payment_hash": payment_hash,
        "did": body.did,
        "enterprise": body.enterprise,
        "amount_sats": body.amount_sats,
        "user_amount_sats": user_amount_sats,
        "operator_amount_sats": operator_amount_sats,
        "stwo_verified": stwo_verified,
        "binding_verified": binding_verified,
        "membership_verified": membership_verified,
        "membership_purpose": membership_purpose,
        "membership_root_id": membership_root_id,
        "dlc_verified": dlc_verified,
        "contract_id": contract_id,
        "schema_version": schema_version,
        "stwo_proof": body.stwo_proof,
        "dlc_contract": body.dlc_contract,
        "nonce": body.nonce,
        "paid": False,
        "created_at": int(time.time()),
        "paid_at": None
    }
    
    with shelve.open(SESSIONS_DB, writeback=True) as sessions:
        # Preserve fields from pre-created session
        if existing:
            session_data["expires_at"] = existing.get("expires_at")
            session_data["required_root_id"] = existing.get("required_root_id")
        sessions[body.session_id] = session_data
    
    # Build response message
    message = None
    if stwo_verified and binding_verified:
        if membership_verified:
            message = f"Identity verified with membership (purpose: {membership_purpose})"
        elif dlc_verified:
            message = f"Identity verified with DLC (90/10 split: {user_amount_sats}/{operator_amount_sats} sats)"
        elif schema_version >= 4:
            message = f"Identity cryptographically verified (v4: session/client bound)"
        elif schema_version >= 3:
            message = f"Identity cryptographically verified (v3: amount, domain, expiry bound)"
        else:
            message = "Identity cryptographically verified"
    
    # === Payout Logic (non-blocking) ===
    payout_result = None
    if stwo_verified and binding_verified:
        payout_result = await process_payout_if_enabled(
            session_id=body.session_id,
            client_id=server_client_id,
            invoice=body.invoice,
            did=body.did
        )
    
    return LoginInvoiceResponse(
        ok=True,
        session_id=body.session_id,
        stwo_verified=stwo_verified,
        binding_verified=binding_verified,
        dlc_verified=dlc_verified,
        schema_version=schema_version,
        contract_id=contract_id,
        message=message,
        membership_verified=membership_verified,
        payout=payout_result,
    )


def generate_session_token(session_id: str, did: str, enterprise: str) -> str:
    """Generate a JWT session token for the enterprise after successful login."""
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip('=')
    
    payload_data = {
        "session_id": session_id,
        "did": did,
        "enterprise": enterprise,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour expiry
        "verified": True
    }
    payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip('=')
    
    # Simplified signature (in production, use proper HMAC)
    sig_data = f"{header}.{payload}.signedby_secret"
    sig = hashlib.sha256(sig_data.encode()).hexdigest()[:43]
    
    return f"{header}.{payload}.{sig}"


@router.get("/v1/login/session/{session_id}", response_model=SessionStatusResponse)
def get_session(
    session_id: str,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Get session status for enterprise polling.
    Returns invoice, DID, verification status, payment status.
    
    Requires X-API-Key header. Only returns data to the enterprise that created the session.
    Invoice is only returned if the session is verified (STWO proof passed).
    """
    # Validate API key and get client_id
    client_id, _ = validate_api_key(x_api_key)
    
    with shelve.open(SESSIONS_DB) as sessions:
        session = sessions.get(session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        
        # Verify this enterprise owns the session
        if session.get("client_id") != client_id:
            raise HTTPException(403, "Not authorized to access this session")
        
        # Only return invoice if session is verified (prevent leaking before proof)
        invoice = ""
        if session.get("stwo_verified") and session.get("binding_verified"):
            invoice = session.get("invoice", "")
        
        # No longer return session_token here - use /confirm-payment + /oidc/token instead
        session_token = None
        
        return SessionStatusResponse(
            session_id=session_id,
            invoice=invoice,  # Only populated if verified
            did=session.get("did", ""),
            enterprise=session["enterprise"],
            verified=session.get("stwo_verified", False) and session.get("binding_verified", False),
            paid=session.get("paid", False),
            schema_version=session.get("schema_version", 2),
            amount_sats=session.get("amount_sats"),
            user_amount_sats=session.get("user_amount_sats"),
            operator_amount_sats=session.get("operator_amount_sats"),
            contract_id=session.get("contract_id"),
            audit_hash=session.get("audit_hash"),
            session_token=session_token,
            created_at=session["created_at"],
            paid_at=session.get("paid_at"),
            # NEW: Membership fields
            membership_verified=session.get("membership_verified", False),
            membership_purpose=session.get("membership_purpose"),
            membership_root_id=session.get("membership_root_id"),
        )


@router.post("/v1/login/session/{session_id}/paid")
def mark_session_paid(session_id: str, preimage: str = ""):
    """
    Mark a session as paid (called when payment is detected).
    Optionally verify preimage matches payment hash.
    """
    with shelve.open(SESSIONS_DB, writeback=True) as sessions:
        session = sessions.get(session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        
        # Optionally verify preimage
        if preimage:
            computed_hash = sha256_hex(bytes.fromhex(preimage).hex())
            if computed_hash != session["payment_hash"]:
                raise HTTPException(400, "Preimage doesn't match payment hash")
        
        session["paid"] = True
        session["paid_at"] = int(time.time())
        sessions[session_id] = session
        
        return {
            "ok": True,
            "session_id": session_id,
            "status": "paid",
            "verified": session.get("stwo_verified", False) and session.get("binding_verified", False),
            "schema_version": session.get("schema_version", 2),
            "did": session.get("did", "")
        }


class ConfirmPaymentRequest(BaseModel):
    """Enterprise confirms payment with preimage (payer-side proof)"""
    preimage_hex: str = Field(..., description="Lightning preimage (32 bytes hex)")


class ConfirmPaymentResponse(BaseModel):
    """Response after payment confirmation - includes auth_code for OIDC exchange"""
    ok: bool
    session_id: str
    did: str
    paid: bool
    paid_at: int
    auth_code: str  # Exchange this at /oidc/token
    auth_code_expires_in: int
    attestation: dict  # SA's signed attestation
    audit_hash: str
    user_amount_sats: Optional[int] = None
    operator_amount_sats: Optional[int] = None


def compute_attestation(session: dict) -> tuple[dict, str]:
    """
    Compute canonical attestation and sign it.
    Returns (attestation_dict, audit_hash).
    """
    now = int(time.time())
    
    # Canonical attestation data (fixed order for hashing)
    attestation_data = {
        "schema_version": 1,
        "outcome": "auth_verified",
        "client_id": session.get("client_id", ""),
        "session_id": session.get("session_id", ""),
        "did": session.get("did", ""),
        "payment_hash": session.get("payment_hash", ""),
        "amount_sats": session.get("amount_sats", 0),
        "paid_at": session.get("paid_at", now),
    }
    
    # Compute canonical hash (sorted keys, no whitespace)
    canonical = json.dumps(attestation_data, separators=(",", ":"), sort_keys=True)
    audit_hash = hashlib.sha256(canonical.encode()).hexdigest()
    
    # Add hash to attestation
    attestation_data["audit_hash"] = audit_hash
    
    # TODO: Sign with SA's Schnorr key (for now, include hash as "signature")
    # In production, this would be a real Schnorr signature
    attestation_data["signature_hex"] = audit_hash[:64]  # Placeholder
    attestation_data["pubkey_hex"] = "sa_pubkey_placeholder"  # Placeholder
    
    return attestation_data, audit_hash


@router.post("/v1/login/session/{session_id}/confirm-payment", response_model=ConfirmPaymentResponse)
def confirm_payment(
    session_id: str,
    body: ConfirmPaymentRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Enterprise confirms payment with preimage (payer-side proof).
    
    This is the key endpoint for Option B (OIDC):
    1. Enterprise (payer) proves they paid by providing the preimage
    2. SA verifies sha256(preimage) == payment_hash
    3. SA generates auth_code for OIDC token exchange
    4. SA signs attestation
    5. Enterprise exchanges auth_code at /oidc/token for id_token
    
    Requires X-API-Key header. Only the enterprise that created the session can confirm.
    """
    # Validate API key and get client_id
    client_id, client_config = validate_api_key(x_api_key)
    
    with shelve.open(SESSIONS_DB, writeback=True) as sessions:
        session = sessions.get(session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        
        # Verify this enterprise owns the session
        if session.get("client_id") != client_id:
            raise HTTPException(403, "Not authorized to confirm this session")
        
        # Verify session not expired
        if session.get("expires_at", 0) > 0 and int(time.time()) > session["expires_at"]:
            raise HTTPException(400, "Session expired")
        
        # Verify session is verified (STWO proof passed)
        if not (session.get("stwo_verified") and session.get("binding_verified")):
            raise HTTPException(400, "Session not verified - waiting for user proof")
        
        # === NEW: Enforce membership policy (mandatory by default) ===
        if client_config.get("require_membership", True):
            if not session.get("membership_verified"):
                raise HTTPException(
                    400, 
                    "Membership verification required but not provided"
                )
            
            allowed = client_config.get("allowed_purposes", [])
            if allowed and session.get("membership_purpose") not in allowed:
                raise HTTPException(
                    400, 
                    f"Membership purpose '{session.get('membership_purpose')}' not allowed"
                )
        
        # Verify session not already paid
        if session.get("paid"):
            raise HTTPException(400, "Session already paid")
        
        # Verify preimage matches payment_hash
        try:
            preimage_bytes = bytes.fromhex(body.preimage_hex)
            if len(preimage_bytes) != 32:
                raise ValueError("Preimage must be 32 bytes")
            computed_hash = hashlib.sha256(preimage_bytes).hexdigest()
        except Exception as e:
            raise HTTPException(400, f"Invalid preimage: {e}")
        
        stored_payment_hash = session.get("payment_hash", "")
        if computed_hash.lower() != stored_payment_hash.lower():
            raise HTTPException(400, "Preimage does not match payment hash")
        
        # Mark as paid
        now = int(time.time())
        session["paid"] = True
        session["paid_at"] = now
        session["preimage_hex"] = body.preimage_hex
        
        # Generate auth_code (short-lived, one-time use)
        auth_code = secrets.token_urlsafe(32)
        auth_code_expires = now + 60  # 60 seconds to exchange
        
        # Compute attestation
        attestation, audit_hash = compute_attestation(session)
        session["audit_hash"] = audit_hash
        session["attestation"] = attestation
        
        # Save session
        sessions[session_id] = session
    
    # Store auth_code in OIDC codes DB (shared with oidc_endpoints.py)
    with shelve.open(CODES_DB, writeback=True) as codes:
        codes[auth_code] = {
            "client_id": client_id,
            "redirect_uri": None,  # Not used for API flow
            "nonce": session.get("nonce", ""),
            "iat": now,
            "exp": auth_code_expires,
            # SignedByMe-specific fields
            "signedby": True,
            "signedby_session_id": session_id,
            "did": session.get("did", ""),
            "payment_hash": session.get("payment_hash", ""),
            "amount_sats": session.get("amount_sats"),
            "audit_hash": audit_hash,
            # NEW: Membership fields
            "membership_verified": session.get("membership_verified", False),
            "membership_purpose": session.get("membership_purpose"),
            "membership_root_id": session.get("membership_root_id"),
        }
    
    print(f"Payment confirmed for session {session_id}: auth_code issued")
    
    return ConfirmPaymentResponse(
        ok=True,
        session_id=session_id,
        did=session.get("did", ""),
        paid=True,
        paid_at=now,
        auth_code=auth_code,
        auth_code_expires_in=60,
        attestation=attestation,
        audit_hash=audit_hash,
        user_amount_sats=session.get("user_amount_sats"),
        operator_amount_sats=session.get("operator_amount_sats"),
    )


@router.get("/v1/login/sessions")
def list_sessions(enterprise: str = None, limit: int = 50):
    """
    List recent login sessions (admin/debug endpoint).
    Optionally filter by enterprise.
    """
    results = []
    with shelve.open(SESSIONS_DB) as sessions:
        for key in list(sessions.keys())[-limit:]:
            session = sessions[key]
            if enterprise and session.get("enterprise") != enterprise:
                continue
            results.append({
                "session_id": key,
                "did": session.get("did", ""),
                "enterprise": session.get("enterprise", ""),
                "verified": session.get("stwo_verified", False) and session.get("binding_verified", False),
                "dlc_verified": session.get("dlc_verified", False),
                "contract_id": session.get("contract_id"),
                "schema_version": session.get("schema_version", 2),
                "amount_sats": session.get("amount_sats"),
                "user_amount_sats": session.get("user_amount_sats"),
                "paid": session.get("paid", False),
                "audit_hash": session.get("audit_hash"),
                "created_at": session.get("created_at", 0)
            })
    
    return {"sessions": results, "count": len(results)}
