"""
Enterprise Payment Integration

Enterprises register their Strike API key, we handle auto-payments.
No NWC, no Nostr for payments - just REST API to their existing payment provider.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import time
import hashlib
import secrets

from app.services.strike import (
    StrikeClient,
    register_enterprise_strike,
    get_enterprise_strike_client,
    auto_pay_login,
    StrikePaymentResult
)
from app.routes.enterprise import (
    create_signed_token,
    verify_signed_token,
    extract_payment_hash_from_bolt11,
    verify_stwo_proof,
    verify_binding_signature,
    ISSUER,
    TOKEN_EXPIRY_SECONDS
)


router = APIRouter(tags=["enterprise-payments"])


# =============================================================================
# Models
# =============================================================================

class EnterpriseRegisterRequest(BaseModel):
    """Enterprise registers with their Strike API key"""
    enterprise_id: str = Field(..., description="Unique enterprise identifier")
    enterprise_name: str = Field(..., description="Display name")
    domain: str = Field(..., description="Enterprise domain for OIDC")
    strike_api_key: str = Field(..., description="Strike API key for auto-payments")
    default_amount_sats: int = Field(default=100, gt=0, description="Default login reward")
    max_amount_sats: int = Field(default=1000, gt=0, description="Max per login")


class EnterpriseRegisterResponse(BaseModel):
    """Response with enterprise credentials"""
    ok: bool
    enterprise_id: str
    api_key: str  # Their key to call our API
    message: str


class AutoPaySessionRequest(BaseModel):
    """Enterprise creates an auto-pay login session"""
    enterprise_id: str
    api_key: str  # Our API key (from registration)
    amount_sats: Optional[int] = None  # Override default
    metadata: Optional[dict] = None  # Custom data


class AutoPaySessionResponse(BaseModel):
    """Session token for user to scan"""
    session_token: str
    session_id: str
    qr_data: str
    deep_link: str
    expires_at: int
    amount_sats: int


class UserLoginRequest(BaseModel):
    """User submits invoice for auto-payment"""
    session_token: str
    invoice: str
    did: str
    stwo_proof: Optional[str] = None
    binding_signature: Optional[str] = None
    nonce: Optional[str] = None


class UserLoginResponse(BaseModel):
    """Response after auto-pay completes"""
    ok: bool
    paid: bool
    id_token: Optional[str] = None
    payment_id: Optional[str] = None
    error: Optional[str] = None


# =============================================================================
# Enterprise Key Storage (in production: encrypted DB)
# =============================================================================

_enterprise_api_keys: dict[str, dict] = {}  # enterprise_id -> config


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/v1/enterprise/register", response_model=EnterpriseRegisterResponse)
async def register_enterprise(req: EnterpriseRegisterRequest):
    """
    Enterprise one-time registration.
    
    They give us their Strike API key, we give them an API key for our service.
    """
    # Validate Strike API key works
    client = StrikeClient(req.strike_api_key)
    if not await client.validate_key():
        raise HTTPException(400, "Invalid Strike API key - could not authenticate")
    
    # Generate our API key for them
    our_api_key = secrets.token_urlsafe(32)
    
    # Store enterprise config
    _enterprise_api_keys[req.enterprise_id] = {
        "name": req.enterprise_name,
        "domain": req.domain,
        "api_key_hash": _hash_api_key(our_api_key),
        "default_amount": req.default_amount_sats,
        "max_amount": req.max_amount_sats,
        "created_at": int(time.time())
    }
    
    # Register Strike key for auto-payments
    register_enterprise_strike(req.enterprise_id, req.strike_api_key)
    
    return EnterpriseRegisterResponse(
        ok=True,
        enterprise_id=req.enterprise_id,
        api_key=our_api_key,
        message="Registration complete. Use api_key to create login sessions."
    )


@router.post("/v1/enterprise/session/autopay", response_model=AutoPaySessionResponse)
def create_autopay_session(req: AutoPaySessionRequest):
    """
    Enterprise creates a login session with auto-pay enabled.
    
    When user submits invoice, we pay it immediately via Strike.
    """
    # Verify enterprise API key
    enterprise = _enterprise_api_keys.get(req.enterprise_id)
    if not enterprise:
        raise HTTPException(404, "Enterprise not registered")
    
    if _hash_api_key(req.api_key) != enterprise["api_key_hash"]:
        raise HTTPException(401, "Invalid API key")
    
    # Determine amount
    amount = req.amount_sats or enterprise["default_amount"]
    if amount > enterprise["max_amount"]:
        raise HTTPException(400, f"Amount exceeds max ({enterprise['max_amount']} sats)")
    
    # Create session token (same as regular flow, but with autopay flag)
    now = int(time.time())
    exp = now + TOKEN_EXPIRY_SECONDS
    nonce = secrets.token_urlsafe(16)
    session_id = hashlib.sha256(nonce.encode()).hexdigest()[:16]
    
    payload = {
        "iss": ISSUER,
        "type": "autopay_session",
        "session_id": session_id,
        "enterprise_id": req.enterprise_id,
        "enterprise_name": enterprise["name"],
        "amount_sats": amount,
        "domain": enterprise["domain"],
        "autopay": True,
        "metadata": req.metadata,
        "nonce": nonce,
        "iat": now,
        "exp": exp
    }
    
    session_token = create_signed_token(payload)
    
    qr_data = f"signedby.me://login?token={session_token}"
    deep_link = f"https://signedby.me/login?token={session_token}"
    
    return AutoPaySessionResponse(
        session_token=session_token,
        session_id=session_id,
        qr_data=qr_data,
        deep_link=deep_link,
        expires_at=exp,
        amount_sats=amount
    )


@router.post("/v1/login/autopay", response_model=UserLoginResponse)
async def user_login_autopay(req: UserLoginRequest):
    """
    User submits invoice - we auto-pay via Strike.
    
    Flow:
    1. Verify session token
    2. Verify STWO proof (optional but recommended)
    3. Extract payment hash from invoice
    4. Pay invoice via Strike API
    5. Return id_token with preimage proof
    
    User gets paid INSTANTLY - no webhook, no polling.
    """
    # 1. Verify session token
    try:
        session = verify_signed_token(req.session_token)
    except Exception as e:
        raise HTTPException(400, f"Invalid session: {e}")
    
    if session.get("type") != "autopay_session":
        raise HTTPException(400, "Not an auto-pay session")
    
    if not session.get("autopay"):
        raise HTTPException(400, "Auto-pay not enabled for this session")
    
    enterprise_id = session["enterprise_id"]
    
    # 2. Verify STWO proof (if provided)
    stwo_verified = False
    binding_verified = False
    
    if req.stwo_proof:
        stwo_verified = verify_stwo_proof(req.stwo_proof, req.did)
    
    # 3. Extract payment hash
    try:
        payment_hash = extract_payment_hash_from_bolt11(req.invoice)
    except ValueError as e:
        raise HTTPException(400, f"Invalid invoice: {e}")
    
    # 4. Verify binding (if STWO provided)
    if req.stwo_proof and req.binding_signature and req.nonce:
        binding_verified = verify_binding_signature(
            req.stwo_proof,
            payment_hash,
            req.nonce,
            req.binding_signature
        )
    
    # 5. PAY THE INVOICE via Strike
    result: StrikePaymentResult = await auto_pay_login(enterprise_id, req.invoice)
    
    if not result.success:
        return UserLoginResponse(
            ok=False,
            paid=False,
            error=result.error
        )
    
    # 6. Generate id_token (proof of verified login)
    now = int(time.time())
    exp = now + 300
    
    sub = hashlib.sha256(f"{enterprise_id}:{session['session_id']}".encode()).hexdigest()
    
    id_token_payload = {
        "iss": ISSUER,
        "aud": enterprise_id,
        "sub": sub,
        "iat": now,
        "exp": exp,
        "nonce": session["nonce"],
        "session_id": session["session_id"],
        "domain": session["domain"],
        "amr": ["did_sig", "ln_preimage", "autopay"],
        "payment_hash": payment_hash,
        "preimage": result.preimage,  # Proof of payment
        "amount_sats": session["amount_sats"],
        "stwo_verified": stwo_verified,
        "binding_verified": binding_verified
    }
    
    id_token = create_signed_token(id_token_payload)
    
    return UserLoginResponse(
        ok=True,
        paid=True,
        id_token=id_token,
        payment_id=result.payment_id
    )


# =============================================================================
# Info
# =============================================================================

@router.get("/v1/enterprise/autopay/info")
def autopay_info():
    """Enterprise integration info for auto-pay."""
    return {
        "flow": "enterprise_autopay",
        "description": "Enterprise registers Strike API key, we auto-pay login invoices",
        "endpoints": {
            "1_register": "POST /v1/enterprise/register (once)",
            "2_create_session": "POST /v1/enterprise/session/autopay (per login)",
            "3_user_login": "POST /v1/login/autopay (user calls, we pay)"
        },
        "supported_providers": ["strike"],
        "coming_soon": ["voltage", "opennode", "cash_app"],
        "documentation": "https://docs.signedby.me/enterprise/autopay"
    }
