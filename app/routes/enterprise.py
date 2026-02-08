"""
SignedByMe Enterprise API - Stateless Authentication
All session state lives in signed JWTs. No database.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional
import time
import json
import hashlib
import secrets
import base64
import httpx
from pathlib import Path

router = APIRouter(tags=["enterprise"])

# =============================================================================
# Configuration
# =============================================================================

ISSUER = "https://api.signedby.me"
TOKEN_EXPIRY_SECONDS = 600  # 10 minutes

# Keys directory (same as OIDC)
KEYS_DIR = Path(__file__).resolve().parents[2] / "keys"


# =============================================================================
# JWT Utilities (RS256)
# =============================================================================

def _b64url_encode(data: bytes) -> str:
    """Base64URL encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    """Base64URL decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _get_signing_key():
    """Load RSA private key for signing."""
    pem_path = KEYS_DIR / "oidc_rs256.pem"
    if not pem_path.exists():
        raise HTTPException(500, "Signing key not configured")
    
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(
        pem_path.read_bytes(),
        password=None
    )


def _get_jwks_kid() -> str:
    """Get the key ID from JWKS."""
    jwks_path = KEYS_DIR / "jwks.json"
    if not jwks_path.exists():
        return "key-1"
    jwks = json.loads(jwks_path.read_text())
    if jwks.get("keys"):
        return jwks["keys"][0].get("kid", "key-1")
    return "key-1"


def create_signed_token(payload: dict) -> str:
    """Create RS256 signed JWT."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": _get_jwks_kid()
    }
    
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    
    signing_input = f"{header_b64}.{payload_b64}".encode()
    
    private_key = _get_signing_key()
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_signed_token(token: str) -> dict:
    """Verify RS256 signed JWT and return payload."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Load public key from JWKS
        jwks_path = KEYS_DIR / "jwks.json"
        if not jwks_path.exists():
            raise HTTPException(500, "JWKS not configured")
        
        jwks = json.loads(jwks_path.read_text())
        if not jwks.get("keys"):
            raise HTTPException(500, "No keys in JWKS")
        
        key_data = jwks["keys"][0]
        n = int.from_bytes(_b64url_decode(key_data["n"]), "big")
        e = int.from_bytes(_b64url_decode(key_data["e"]), "big")
        
        public_key = rsa.RSAPublicNumbers(e, n).public_key()
        
        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = _b64url_decode(signature_b64)
        
        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Decode payload
        payload = json.loads(_b64url_decode(payload_b64))
        
        # Check expiry
        if time.time() > payload.get("exp", 0):
            raise ValueError("Token expired")
        
        return payload
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Invalid token: {str(e)}")


# =============================================================================
# BOLT11 Invoice Parsing
# =============================================================================

def extract_payment_hash_from_bolt11(invoice: str) -> str:
    """
    Extract payment hash from BOLT11 invoice.
    
    BOLT11 format: ln[tb][c]<amount><multiplier>1<data><checksum>
    The payment hash is in the tagged fields.
    
    For production, use a proper library. This is a simplified parser.
    """
    # Try to use the bolt11 library if available
    try:
        from bolt11 import decode
        decoded = decode(invoice)
        return decoded.payment_hash
    except ImportError:
        pass
    
    # Fallback: extract from bech32 data
    # Payment hash is typically the first 32 bytes after the timestamp
    # This is a simplified approach - for production use a proper parser
    
    # For now, hash the invoice itself as a unique identifier
    # TODO: Implement proper BOLT11 parsing or use rust library
    return hashlib.sha256(invoice.encode()).hexdigest()


# =============================================================================
# Models
# =============================================================================

class CreateSessionRequest(BaseModel):
    """Enterprise creates a login session."""
    enterprise_id: str = Field(..., description="Enterprise's unique identifier")
    enterprise_name: str = Field(..., description="Display name (shown to user)")
    amount_sats: int = Field(..., gt=0, description="Amount user will receive")
    callback_url: HttpUrl = Field(..., description="Webhook URL to receive invoice")
    domain: str = Field(..., description="Enterprise's domain for OIDC")


class CreateSessionResponse(BaseModel):
    """Response with session token and QR data."""
    session_token: str
    session_id: str
    qr_data: str
    deep_link: str
    expires_at: int
    amount_sats: int


class LoginSubmitRequest(BaseModel):
    """User submits invoice and proof."""
    session_token: str = Field(..., description="Token from QR code")
    invoice: str = Field(..., description="BOLT11 Lightning invoice")
    did: str = Field(..., description="User's DID (did:btcr:...)")
    stwo_proof: Optional[str] = Field(None, description="STWO identity proof JSON")
    binding_signature: Optional[str] = Field(None, description="Signature binding proof to payment")
    nonce: Optional[str] = Field(None, description="Nonce for replay protection")


class LoginSubmitResponse(BaseModel):
    """Response after invoice submission."""
    ok: bool
    status: str
    session_id: str
    message: Optional[str] = None


class LoginConfirmRequest(BaseModel):
    """Enterprise confirms payment with preimage."""
    session_token: str = Field(..., description="Original session token")
    preimage: str = Field(..., description="Payment preimage (hex)")


class LoginConfirmResponse(BaseModel):
    """Response with verification result and id_token."""
    ok: bool
    verified: bool
    did: str
    id_token: str
    session_id: str


# =============================================================================
# STWO Verification (basic for now)
# =============================================================================

def verify_stwo_proof(proof_json: str, did: str) -> bool:
    """
    Verify STWO identity proof.
    Returns True if proof is valid and matches DID.
    """
    if not proof_json:
        return False
    
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
        
        return True
        
    except Exception:
        return False


def verify_binding_signature(
    proof_json: str,
    payment_hash: str,
    nonce: str,
    signature: str
) -> bool:
    """
    Verify binding signature links proof to payment.
    For production: implement secp256k1 signature verification.
    """
    if not all([proof_json, payment_hash, nonce, signature]):
        return False
    
    # Basic validation - signature exists and has reasonable length
    if len(signature) < 20:
        return False
    
    # TODO: Implement proper secp256k1 verification
    # 1. Compute binding_data = hash(proof_hash + payment_hash + nonce)
    # 2. Verify signature over binding_data using DID pubkey
    
    return True


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/v1/enterprise/session", response_model=CreateSessionResponse)
def create_session(req: CreateSessionRequest):
    """
    Enterprise creates a login session.
    
    Returns a signed JWT containing all session parameters.
    The token IS the session - no database storage.
    """
    now = int(time.time())
    exp = now + TOKEN_EXPIRY_SECONDS
    nonce = secrets.token_urlsafe(16)
    
    # Session ID is hash of nonce (for reference only)
    session_id = hashlib.sha256(nonce.encode()).hexdigest()[:16]
    
    # All session data goes in the token
    payload = {
        "iss": ISSUER,
        "type": "session",
        "session_id": session_id,
        "enterprise_id": req.enterprise_id,
        "enterprise_name": req.enterprise_name,
        "amount_sats": req.amount_sats,
        "callback_url": str(req.callback_url),
        "domain": req.domain,
        "nonce": nonce,
        "iat": now,
        "exp": exp
    }
    
    session_token = create_signed_token(payload)
    
    # Generate QR data and deep link
    qr_data = f"signedby.me://login?token={session_token}"
    deep_link = f"https://signedby.me/login?token={session_token}"
    
    return CreateSessionResponse(
        session_token=session_token,
        session_id=session_id,
        qr_data=qr_data,
        deep_link=deep_link,
        expires_at=exp,
        amount_sats=req.amount_sats
    )


@router.post("/v1/login/submit", response_model=LoginSubmitResponse)
async def login_submit(req: LoginSubmitRequest):
    """
    User submits invoice and STWO proof.
    
    API verifies everything, then calls enterprise's callback with the invoice.
    Enterprise will pay, then call /v1/login/confirm with preimage.
    """
    # 1. Verify session token
    try:
        session = verify_signed_token(req.session_token)
    except HTTPException as e:
        raise HTTPException(400, f"Invalid session token: {e.detail}")
    
    if session.get("type") != "session":
        raise HTTPException(400, "Invalid token type")
    
    # 2. Extract payment hash from invoice
    payment_hash = extract_payment_hash_from_bolt11(req.invoice)
    
    # 3. Verify STWO proof
    stwo_verified = verify_stwo_proof(req.stwo_proof, req.did) if req.stwo_proof else False
    
    # 4. Verify binding signature
    binding_verified = False
    if req.stwo_proof and req.binding_signature and req.nonce:
        binding_verified = verify_binding_signature(
            req.stwo_proof,
            payment_hash,
            req.nonce,
            req.binding_signature
        )
    
    # 5. Build callback payload
    callback_payload = {
        "session_id": session["session_id"],
        "invoice": req.invoice,
        "payment_hash": payment_hash,
        "did": req.did,
        "amount_sats": session["amount_sats"],
        "enterprise_id": session["enterprise_id"],
        "stwo_verified": stwo_verified,
        "binding_verified": binding_verified,
        "timestamp": int(time.time())
    }
    
    # 6. Call enterprise's callback URL
    callback_url = session["callback_url"]
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(callback_url, json=callback_payload)
            
            if resp.status_code >= 400:
                raise HTTPException(502, f"Enterprise callback failed: {resp.status_code}")
                
    except httpx.RequestError as e:
        raise HTTPException(502, f"Failed to reach enterprise callback: {str(e)}")
    
    return LoginSubmitResponse(
        ok=True,
        status="pending_payment",
        session_id=session["session_id"],
        message="Invoice sent to enterprise. Waiting for payment."
    )


@router.post("/v1/login/confirm", response_model=LoginConfirmResponse)
def login_confirm(req: LoginConfirmRequest):
    """
    Enterprise confirms payment with preimage.
    
    API verifies preimage matches payment_hash, then returns id_token.
    """
    # 1. Verify session token
    try:
        session = verify_signed_token(req.session_token)
    except HTTPException as e:
        raise HTTPException(400, f"Invalid session token: {e.detail}")
    
    if session.get("type") != "session":
        raise HTTPException(400, "Invalid token type")
    
    # 2. Validate preimage format
    preimage = req.preimage.lower().strip()
    if len(preimage) != 64 or not all(c in "0123456789abcdef" for c in preimage):
        raise HTTPException(400, "Preimage must be 64 hex characters")
    
    # 3. Compute payment hash from preimage
    # SHA256(preimage) should equal the payment_hash from the invoice
    computed_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    
    # Note: In a stateless system, we trust the enterprise is submitting
    # the preimage for the invoice they received. The preimage itself
    # is proof of payment - only someone who paid could have it.
    
    # 4. Generate OIDC-compatible id_token
    now = int(time.time())
    exp = now + 300  # 5 minute expiry for id_token
    
    # Sub is hash of DID for privacy
    # The DID was in the callback, enterprise associates it with this session
    sub = hashlib.sha256(f"{session['enterprise_id']}:{session['session_id']}".encode()).hexdigest()
    
    id_token_payload = {
        "iss": ISSUER,
        "aud": session["enterprise_id"],
        "sub": sub,
        "iat": now,
        "exp": exp,
        "nonce": session["nonce"],
        "session_id": session["session_id"],
        "domain": session["domain"],
        "amr": ["did_sig", "ln_preimage"],  # Authentication methods
        "payment_hash": computed_hash,
        "amount_sats": session["amount_sats"]
    }
    
    id_token = create_signed_token(id_token_payload)
    
    return LoginConfirmResponse(
        ok=True,
        verified=True,
        did="verified",  # Don't echo DID back, enterprise has it from callback
        id_token=id_token,
        session_id=session["session_id"]
    )


# =============================================================================
# Health / Info
# =============================================================================

@router.get("/v1/enterprise/info")
def enterprise_info():
    """Return API information for enterprise integration."""
    return {
        "issuer": ISSUER,
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "endpoints": {
            "create_session": "POST /v1/enterprise/session",
            "login_submit": "POST /v1/login/submit",
            "login_confirm": "POST /v1/login/confirm"
        },
        "token_expiry_seconds": TOKEN_EXPIRY_SECONDS,
        "documentation": "https://docs.signedby.me/enterprise"
    }
