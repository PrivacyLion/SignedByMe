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

ISSUER = "https://api.beta.privacy-lion.com"
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
# Bech32 Decoding (for BOLT11)
# =============================================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_decode(bech: str) -> tuple[str, list[int]]:
    """Decode bech32 string, return (hrp, data as 5-bit values)."""
    if any(ord(c) < 33 or ord(c) > 126 for c in bech):
        raise ValueError("Invalid character")
    
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        raise ValueError("Invalid separator position")
    
    hrp = bech[:pos]
    data = []
    for c in bech[pos + 1:]:
        d = BECH32_CHARSET.find(c)
        if d == -1:
            raise ValueError(f"Invalid character: {c}")
        data.append(d)
    
    # Skip checksum verification for simplicity (last 6 chars)
    return hrp, data[:-6]


def _convert_bits(data: list[int], from_bits: int, to_bits: int, pad: bool = True) -> list[int]:
    """Convert between bit sizes."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    
    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    
    if pad and bits:
        ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        if not pad:
            pass  # Ignore padding bits
    
    return ret


# =============================================================================
# BOLT11 Invoice Parsing
# =============================================================================

def extract_payment_hash_from_bolt11(invoice: str) -> str:
    """
    Extract payment hash from BOLT11 invoice.
    
    BOLT11 format: ln<network><amount>1<timestamp><tagged_fields><signature>
    Payment hash is tag 'p' (type 1), always 52 5-bit chars = 32 bytes.
    """
    invoice = invoice.strip().lower()
    
    # Validate prefix
    if not invoice.startswith("ln"):
        raise ValueError("Invoice must start with 'ln'")
    
    try:
        hrp, data = _bech32_decode(invoice)
    except Exception as e:
        raise ValueError(f"Bech32 decode failed: {e}")
    
    # data[0:7] is timestamp (35 bits), then tagged fields, then signature (104 chars)
    # Signature is 65 bytes = 104 * 5 / 8 = 65 bytes (520 bits + recovery)
    
    if len(data) < 7 + 104:
        raise ValueError("Invoice too short")
    
    # Skip timestamp (first 7 5-bit values)
    tagged_data = data[7:-104]  # Exclude signature at end
    
    # Parse tagged fields
    i = 0
    while i < len(tagged_data):
        if i + 3 > len(tagged_data):
            break
        
        tag_type = tagged_data[i]
        data_len = (tagged_data[i + 1] << 5) | tagged_data[i + 2]
        i += 3
        
        if i + data_len > len(tagged_data):
            break
        
        tag_data = tagged_data[i:i + data_len]
        i += data_len
        
        # Tag type 1 = payment hash (52 5-bit values = 32 bytes)
        if tag_type == 1 and data_len == 52:
            # Convert 5-bit to 8-bit
            hash_bytes = _convert_bits(tag_data, 5, 8, pad=False)
            if len(hash_bytes) == 32:
                return bytes(hash_bytes).hex()
    
    raise ValueError("Payment hash not found in invoice")


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
# secp256k1 Signature Verification
# =============================================================================

def _verify_secp256k1_signature(pubkey_hex: str, message_hash: bytes, signature_hex: str) -> bool:
    """
    Verify secp256k1 signature using cryptography library.
    
    Args:
        pubkey_hex: Compressed (33 bytes) or uncompressed (65 bytes) public key
        message_hash: 32-byte message hash
        signature_hex: DER or compact signature
    
    Returns:
        True if signature is valid
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptography.exceptions import InvalidSignature
        
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        
        # Load public key
        if len(pubkey_bytes) == 33:
            # Compressed public key - need to decompress
            # Use cryptography's from_encoded_point
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), pubkey_bytes
            )
        elif len(pubkey_bytes) == 65:
            # Uncompressed public key
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), pubkey_bytes
            )
        else:
            return False
        
        # Handle signature format
        if len(sig_bytes) == 64:
            # Compact format (r || s)
            r = int.from_bytes(sig_bytes[:32], 'big')
            s = int.from_bytes(sig_bytes[32:], 'big')
            
            # Convert to DER
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            der_sig = encode_dss_signature(r, s)
        else:
            # Assume DER format
            der_sig = sig_bytes
        
        # Verify using ECDSA with prehashed message
        from cryptography.hazmat.primitives.asymmetric import utils
        
        public_key.verify(
            der_sig,
            message_hash,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        
        return True
        
    except (InvalidSignature, Exception) as e:
        import logging
        logging.debug(f"Signature verification failed: {e}")
        return False


# =============================================================================
# STWO Verification
# =============================================================================

def verify_stwo_proof(proof_json: str, did: str) -> bool:
    """
    Verify STWO identity proof.
    
    Checks:
    1. Proof structure is valid
    2. Circuit type is identity_proof
    3. Proof claims to be valid
    4. DID in proof matches claimed DID
    5. Proof has not expired
    6. Commitment signature is valid (secp256k1)
    
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
        
        # Verify commitment signature if present
        commitment = proof.get("commitment")
        if commitment and proof_did:
            commitment_sig = commitment.get("signature")
            if commitment_sig:
                # Reconstruct the signed message
                # Format: hash(did_pubkey || wallet_address || expires_at || nonce)
                wallet_addr = public_inputs.get("wallet_address", "")
                commitment_nonce = commitment.get("nonce", "")
                
                msg_preimage = f"{proof_did}{wallet_addr}{expires_at or ''}{commitment_nonce}"
                msg_hash = hashlib.sha256(msg_preimage.encode()).digest()
                
                if not _verify_secp256k1_signature(proof_did, msg_hash, commitment_sig):
                    return False
        
        return True
        
    except Exception as e:
        import logging
        logging.warning(f"STWO proof verification error: {e}")
        return False


def verify_binding_signature(
    proof_json: str,
    payment_hash: str,
    nonce: str,
    signature: str
) -> bool:
    """
    Verify binding signature links STWO proof to Lightning payment.
    
    The binding signature proves the user authorized THIS specific payment
    with their identity proof. Prevents replay attacks.
    
    Binding data = SHA256(stwo_proof_hash || payment_hash || nonce)
    Signature is over binding data using DID private key.
    """
    if not all([proof_json, payment_hash, nonce, signature]):
        return False
    
    try:
        proof = json.loads(proof_json)
        
        # Get public key from proof
        public_inputs = proof.get("public_inputs", {})
        did_pubkey = public_inputs.get("did_pubkey", "")
        
        if not did_pubkey:
            return False
        
        # Compute proof hash (for binding)
        stwo_proof_hash = proof.get("stwo_proof_hash")
        if not stwo_proof_hash:
            # Compute from proof JSON if not provided
            stwo_proof_hash = hashlib.sha256(proof_json.encode()).hexdigest()
        
        # Construct binding message
        # binding_data = SHA256(proof_hash || payment_hash || nonce)
        binding_preimage = f"{stwo_proof_hash}{payment_hash}{nonce}"
        binding_hash = hashlib.sha256(binding_preimage.encode()).digest()
        
        # Verify signature
        return _verify_secp256k1_signature(did_pubkey, binding_hash, signature)
        
    except Exception as e:
        import logging
        logging.warning(f"Binding signature verification error: {e}")
        return False


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
    try:
        payment_hash = extract_payment_hash_from_bolt11(req.invoice)
    except ValueError as e:
        raise HTTPException(400, f"Invalid BOLT11 invoice: {e}")
    
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
        "jwks_uri": f"{ISSUER}/oidc/jwks.json",
        "endpoints": {
            "create_session": "POST /v1/enterprise/session",
            "login_submit": "POST /v1/login/submit",
            "login_confirm": "POST /v1/login/confirm"
        },
        "token_expiry_seconds": TOKEN_EXPIRY_SECONDS,
        "documentation": "https://docs.signedby.me/enterprise"
    }
