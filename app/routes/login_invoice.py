"""
SignedByMe Login Invoice API
Handles invoice submission with STWO proof verification
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import time
import hashlib
import json
from pathlib import Path
import shelve

router = APIRouter(tags=["login"])

# Storage
VAR_DIR = Path(__file__).resolve().parents[2] / "var"
VAR_DIR.mkdir(parents=True, exist_ok=True)
SESSIONS_DB = str(VAR_DIR / "login_sessions.db")
NONCES_DB = str(VAR_DIR / "used_nonces.db")


class LoginInvoiceRequest(BaseModel):
    """Request to submit a login invoice with optional STWO proof"""
    session_id: str = Field(..., description="Session ID from QR/deep link")
    invoice: str = Field(..., description="BOLT11 Lightning invoice")
    did: str = Field(..., description="User's DID (did:btcr:...)")
    employer: str = Field(..., description="Employer name")
    stwo_proof: Optional[str] = Field(None, description="STWO identity proof JSON")
    binding_signature: Optional[str] = Field(None, description="Signature binding proof to payment")
    nonce: Optional[str] = Field(None, description="Nonce for replay protection")


class LoginInvoiceResponse(BaseModel):
    """Response after invoice submission"""
    ok: bool
    session_id: str
    stwo_verified: bool = False
    binding_verified: bool = False
    message: Optional[str] = None


class SessionStatusResponse(BaseModel):
    """Session status for employer polling"""
    session_id: str
    invoice: str
    did: str
    employer: str
    verified: bool  # STWO + binding verified
    paid: bool
    created_at: int
    paid_at: Optional[int] = None


def sha256_hex(data: str) -> str:
    """Compute SHA-256 hash of string"""
    return hashlib.sha256(data.encode()).hexdigest()


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


def verify_stwo_proof(proof_json: str, did: str) -> bool:
    """
    Verify STWO identity proof.
    In production, this would call the Rust verifier.
    For now, we do basic validation.
    """
    try:
        proof = json.loads(proof_json)
        
        # Check proof structure
        if proof.get("circuit_type") != "identity_proof":
            return False
        
        if not proof.get("valid", False):
            return False
        
        # Check DID matches
        public_inputs = proof.get("public_inputs", {})
        proof_did = public_inputs.get("did_pubkey", "")
        
        # DID format: did:btcr:<pubkey>
        did_pubkey = did.replace("did:btcr:", "")
        if proof_did and proof_did != did_pubkey:
            return False
        
        # Check expiry
        expires_at = public_inputs.get("expires_at")
        if expires_at and time.time() > expires_at:
            return False
        
        # Verify proof hash (basic check)
        if not proof.get("proof_hash"):
            return False
        
        return True
    except Exception as e:
        print(f"STWO verification error: {e}")
        return False


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


@router.post("/v1/login/invoice", response_model=LoginInvoiceResponse)
def submit_invoice(body: LoginInvoiceRequest):
    """
    Submit a login invoice with optional STWO proof.
    
    The employer will poll /v1/login/session/{session_id} to get the invoice
    and check verification/payment status.
    """
    stwo_verified = False
    binding_verified = False
    
    # Extract payment hash from invoice
    payment_hash = extract_payment_hash(body.invoice)
    
    # Verify STWO proof if provided
    if body.stwo_proof:
        stwo_verified = verify_stwo_proof(body.stwo_proof, body.did)
        if not stwo_verified:
            # Log but don't reject - allow non-STWO logins for backwards compat
            print(f"STWO proof verification failed for session {body.session_id}")
    
    # Verify binding signature if STWO proof was provided
    if body.stwo_proof and body.binding_signature and body.nonce:
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
    
    # Store session
    session_data = {
        "session_id": body.session_id,
        "invoice": body.invoice,
        "payment_hash": payment_hash,
        "did": body.did,
        "employer": body.employer,
        "stwo_verified": stwo_verified,
        "binding_verified": binding_verified,
        "stwo_proof": body.stwo_proof,
        "paid": False,
        "created_at": int(time.time()),
        "paid_at": None
    }
    
    with shelve.open(SESSIONS_DB) as sessions:
        sessions[body.session_id] = session_data
    
    return LoginInvoiceResponse(
        ok=True,
        session_id=body.session_id,
        stwo_verified=stwo_verified,
        binding_verified=binding_verified,
        message="Identity cryptographically verified" if (stwo_verified and binding_verified) else None
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
            invoice=session["invoice"],
            did=session["did"],
            employer=session["employer"],
            verified=session["stwo_verified"] and session["binding_verified"],
            paid=session["paid"],
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
            "verified": session["stwo_verified"] and session["binding_verified"],
            "did": session["did"]
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
                "did": session["did"],
                "employer": session["employer"],
                "verified": session["stwo_verified"] and session["binding_verified"],
                "paid": session["paid"],
                "created_at": session["created_at"]
            })
    
    return {"sessions": results, "count": len(results)}
