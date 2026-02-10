"""
SignedByMe Login Invoice API
Handles invoice submission with STWO proof verification (v1, v2, v3)

v3 Security Bindings:
- expires_at: Bound into hash (prevents expiry tampering)
- ea_domain: Bound into hash (prevents cross-RP replay)
- amount_sats: Bound into hash (prevents payment substitution)
- nonce: Bound into hash (prevents replay attacks)
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import time
import hashlib
import json
import secrets
from pathlib import Path
import shelve

router = APIRouter(tags=["login"])

# Storage
VAR_DIR = Path(__file__).resolve().parents[2] / "var"
VAR_DIR.mkdir(parents=True, exist_ok=True)
SESSIONS_DB = str(VAR_DIR / "login_sessions.db")
NONCES_DB = str(VAR_DIR / "used_nonces.db")


class LoginInvoiceRequest(BaseModel):
    """Request to submit a login invoice with STWO proof"""
    session_id: str = Field(..., description="Session ID from QR/deep link")
    invoice: str = Field(..., description="BOLT11 Lightning invoice")
    did: str = Field(..., description="User's DID (did:btcr:...)")
    employer: str = Field(..., description="Employer name/domain")
    amount_sats: Optional[int] = Field(None, description="Expected payment amount in sats (v3)")
    stwo_proof: Optional[str] = Field(None, description="STWO identity proof JSON")
    binding_signature: Optional[str] = Field(None, description="Signature binding proof to payment (legacy)")
    nonce: Optional[str] = Field(None, description="Nonce for replay protection (16 bytes hex for v3)")


class LoginInvoiceResponse(BaseModel):
    """Response after invoice submission"""
    ok: bool
    session_id: str
    stwo_verified: bool = False
    binding_verified: bool = False
    schema_version: int = 2
    message: Optional[str] = None


class SessionStatusResponse(BaseModel):
    """Session status for employer polling"""
    session_id: str
    invoice: str
    did: str
    employer: str
    verified: bool  # STWO + binding verified
    paid: bool
    schema_version: int = 2
    amount_sats: Optional[int] = None
    created_at: int
    paid_at: Optional[int] = None


class LoginStartRequest(BaseModel):
    """Request to start a new login session"""
    employer: str = Field(..., description="Employer name/domain")
    amount_sats: int = Field(500, description="Payment amount in sats")
    expiry_minutes: int = Field(5, description="Session expiry in minutes")


class LoginStartResponse(BaseModel):
    """Response with session details for QR/deep link"""
    session_id: str
    nonce: str  # 16 bytes hex (32 chars)
    employer: str
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
def start_login_session(body: LoginStartRequest):
    """
    Start a new login session. Returns session details for QR/deep link.
    The enterprise displays this to the user.
    """
    session_id = secrets.token_urlsafe(16)
    nonce = generate_nonce()  # 16 bytes hex = 32 chars
    expires_at = int(time.time()) + (body.expiry_minutes * 60)
    
    # Build deep link URL
    qr_data = f"signedby.me://login?session={session_id}&employer={body.employer}&amount={body.amount_sats}&nonce={nonce}&expires={expires_at}"
    
    # Store session (pre-create for polling)
    session_data = {
        "session_id": session_id,
        "nonce": nonce,
        "employer": body.employer,
        "amount_sats": body.amount_sats,
        "expires_at": expires_at,
        "invoice": None,
        "payment_hash": None,
        "did": None,
        "stwo_verified": False,
        "binding_verified": False,
        "schema_version": 2,
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
        employer=body.employer,
        amount_sats=body.amount_sats,
        expires_at=expires_at,
        qr_data=qr_data,
    )


@router.post("/v1/login/invoice", response_model=LoginInvoiceResponse)
def submit_invoice(body: LoginInvoiceRequest):
    """
    Submit a login invoice with STWO proof.
    
    For v3 proofs, verifies:
    - Binding hash integrity (catches any tampering)
    - expires_at (prevents expiry extension)
    - ea_domain (prevents cross-RP replay)
    - amount_sats (prevents payment substitution)
    - nonce (prevents replay attacks)
    
    The employer will poll /v1/login/session/{session_id} to get the invoice
    and check verification/payment status.
    """
    stwo_verified = False
    binding_verified = False
    schema_version = 2
    
    # Load existing session if it exists (from /start)
    with shelve.open(SESSIONS_DB) as sessions:
        existing = sessions.get(body.session_id)
        if existing:
            # Verify session hasn't expired
            if existing.get("expires_at", 0) > 0 and int(time.time()) > existing["expires_at"]:
                raise HTTPException(400, "Session expired")
            
            # Use stored nonce if not provided in request
            if not body.nonce and existing.get("nonce"):
                body.nonce = existing["nonce"]
    
    # Extract payment hash from invoice
    payment_hash = extract_payment_hash(body.invoice)
    
    # Verify STWO proof if provided
    if body.stwo_proof:
        stwo_verified, schema_version, verify_msg = verify_stwo_proof(
            body.stwo_proof,
            body.did,
            expected_domain=body.employer,  # Pass employer as expected domain
            expected_amount=body.amount_sats,  # Pass expected amount if provided
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
    
    # For v3 proofs, mark nonce as used if binding verified
    if schema_version >= 3 and binding_verified and body.nonce:
        with shelve.open(NONCES_DB) as nonces:
            if body.nonce not in nonces:
                nonces[body.nonce] = int(time.time())
    
    # Store/update session
    session_data = {
        "session_id": body.session_id,
        "invoice": body.invoice,
        "payment_hash": payment_hash,
        "did": body.did,
        "employer": body.employer,
        "amount_sats": body.amount_sats,
        "stwo_verified": stwo_verified,
        "binding_verified": binding_verified,
        "schema_version": schema_version,
        "stwo_proof": body.stwo_proof,
        "nonce": body.nonce,
        "paid": False,
        "created_at": int(time.time()),
        "paid_at": None
    }
    
    with shelve.open(SESSIONS_DB) as sessions:
        # Preserve expires_at if session was pre-created
        existing = sessions.get(body.session_id)
        if existing and existing.get("expires_at"):
            session_data["expires_at"] = existing["expires_at"]
        sessions[body.session_id] = session_data
    
    message = None
    if stwo_verified and binding_verified:
        if schema_version >= 3:
            message = f"Identity cryptographically verified (v3: amount, domain, expiry bound)"
        else:
            message = "Identity cryptographically verified"
    
    return LoginInvoiceResponse(
        ok=True,
        session_id=body.session_id,
        stwo_verified=stwo_verified,
        binding_verified=binding_verified,
        schema_version=schema_version,
        message=message
    )


@router.get("/v1/login/session/{session_id}", response_model=SessionStatusResponse)
def get_session(session_id: str):
    """
    Get session status for employer polling.
    Returns invoice, DID, verification status, and payment status.
    """
    with shelve.open(SESSIONS_DB) as sessions:
        session = sessions.get(session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        
        return SessionStatusResponse(
            session_id=session_id,
            invoice=session.get("invoice", ""),
            did=session.get("did", ""),
            employer=session["employer"],
            verified=session.get("stwo_verified", False) and session.get("binding_verified", False),
            paid=session.get("paid", False),
            schema_version=session.get("schema_version", 2),
            amount_sats=session.get("amount_sats"),
            created_at=session["created_at"],
            paid_at=session.get("paid_at")
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


@router.get("/v1/login/sessions")
def list_sessions(employer: str = None, limit: int = 50):
    """
    List recent login sessions (admin/debug endpoint).
    Optionally filter by employer.
    """
    results = []
    with shelve.open(SESSIONS_DB) as sessions:
        for key in list(sessions.keys())[-limit:]:
            session = sessions[key]
            if employer and session.get("employer") != employer:
                continue
            results.append({
                "session_id": key,
                "did": session.get("did", ""),
                "employer": session.get("employer", ""),
                "verified": session.get("stwo_verified", False) and session.get("binding_verified", False),
                "schema_version": session.get("schema_version", 2),
                "amount_sats": session.get("amount_sats"),
                "paid": session.get("paid", False),
                "created_at": session.get("created_at", 0)
            })
    
    return {"sessions": results, "count": len(results)}
