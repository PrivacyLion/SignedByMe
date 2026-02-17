"""
Canonical session endpoints for SignedByMe login flow.

POST /v1/session  - Create a login session (RP calls this)
GET  /v1/session/{id} - Poll session status (RP polls this)

Session lifecycle:
1. RP creates session with redirect_uri
2. User scans QR, app calls /v1/login/invoice
3. RP polls until status=completed or expired
"""

import os
import json
import time
import secrets
import logging
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("session")

router = APIRouter(prefix="/v1/session", tags=["session"])

# Session TTL in seconds (5 minutes)
SESSION_TTL = 300

# In-memory session store
# Key: session_id, Value: SessionRecord
_sessions: dict[str, dict] = {}

# Login events log (for admin dashboard)
_login_events: list[dict] = []

# Payout attempts log (for admin dashboard)
_payout_attempts: list[dict] = []


def load_clients() -> dict:
    """Load clients config."""
    clients_path = os.environ.get("CLIENTS_JSON", "/opt/sbm-api/clients.json")
    # Fallback for local dev
    if not os.path.exists(clients_path):
        clients_path = os.path.join(os.path.dirname(__file__), "../../clients.json")
    
    with open(clients_path) as f:
        return json.load(f)


def get_client_by_api_key(api_key: str) -> tuple[Optional[str], Optional[dict]]:
    """Look up client by API key. Returns (client_id, config) or (None, None)."""
    clients = load_clients()
    for client_id, config in clients.items():
        if config.get("api_key") == api_key:
            return client_id, config
    return None, None


def generate_session_id() -> str:
    """Generate a URL-safe session ID."""
    return secrets.token_urlsafe(16)


# --- Request/Response Models ---

class CreateSessionRequest(BaseModel):
    redirect_uri: str = Field(..., description="OAuth-style redirect URI for callback")


class CreateSessionResponse(BaseModel):
    session_id: str
    qr_data: str
    deep_link: str
    amount_sats: int
    employer_name: str
    expires_at: int
    require_membership: bool = False


class SessionStatusResponse(BaseModel):
    session_id: str
    status: str  # pending, completed, expired
    created_at: int
    expires_at: int
    # Populated on completion
    did: Optional[str] = None
    verified_at: Optional[int] = None
    payout: Optional[dict] = None


# --- Endpoints ---

@router.post("", response_model=CreateSessionResponse)
async def create_session(
    body: CreateSessionRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Create a new login session.
    
    Called by the RP (e.g., Acme Corp website) to initiate a SignedByMe login.
    Returns QR data and deep link for the user to scan/click.
    """
    # Derive client_id from API key (never from request body)
    client_id, client_config = get_client_by_api_key(x_api_key)
    if not client_id:
        raise HTTPException(401, "Invalid API key")
    
    # Validate redirect_uri against allowed list
    allowed_uris = client_config.get("redirect_uris", [])
    if body.redirect_uri not in allowed_uris:
        raise HTTPException(400, f"redirect_uri not in allowed list for client '{client_id}'")
    
    # Get reward amount from server config (not client-provided)
    reward_policy = client_config.get("reward_policy", {})
    amount_sats = reward_policy.get("amount_sats", 0) if reward_policy.get("enabled") else 0
    
    # Get membership requirement
    require_membership = client_config.get("require_membership", False)
    default_root_id = client_config.get("default_root_id")
    
    # Create session
    session_id = generate_session_id()
    now = int(time.time())
    expires_at = now + SESSION_TTL
    
    employer_name = client_config.get("name", client_id)
    
    # Build QR data (deep link format)
    qr_data = f"signedby.me://login?session={session_id}&employer={employer_name}&amount={amount_sats}"
    if require_membership and default_root_id:
        qr_data += f"&root={default_root_id}"
    
    # HTTPS deep link for mobile-to-mobile
    deep_link = f"https://signedby.me/login?session={session_id}&employer={employer_name}&amount={amount_sats}"
    if require_membership and default_root_id:
        deep_link += f"&root={default_root_id}"
    
    # Store session
    _sessions[session_id] = {
        "session_id": session_id,
        "client_id": client_id,
        "redirect_uri": body.redirect_uri,
        "amount_sats": amount_sats,
        "require_membership": require_membership,
        "default_root_id": default_root_id,
        "employer_name": employer_name,
        "status": "pending",
        "created_at": now,
        "expires_at": expires_at,
        # Populated on completion
        "did": None,
        "verified_at": None,
        "payout": None
    }
    
    logger.info(f"Session created: {session_id} for client={client_id}")
    
    return CreateSessionResponse(
        session_id=session_id,
        qr_data=qr_data,
        deep_link=deep_link,
        amount_sats=amount_sats,
        employer_name=employer_name,
        expires_at=expires_at,
        require_membership=require_membership
    )


@router.get("/{session_id}", response_model=SessionStatusResponse)
async def get_session_status(session_id: str):
    """
    Poll session status.
    
    Called by the RP to check if the user has completed login.
    No auth required (session_id is the secret).
    """
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    
    # Check expiration
    now = int(time.time())
    if session["status"] == "pending" and now > session["expires_at"]:
        session["status"] = "expired"
    
    return SessionStatusResponse(
        session_id=session_id,
        status=session["status"],
        created_at=session["created_at"],
        expires_at=session["expires_at"],
        did=session.get("did"),
        verified_at=session.get("verified_at"),
        payout=session.get("payout")
    )


# --- Internal functions (called by login_invoice.py) ---

def get_session(session_id: str) -> Optional[dict]:
    """Get session record (for login_invoice to use)."""
    return _sessions.get(session_id)


def complete_session(
    session_id: str,
    did: str,
    payout_result: Optional[dict] = None
):
    """
    Mark session as completed.
    
    Called by login_invoice after successful verification.
    """
    session = _sessions.get(session_id)
    if not session:
        logger.warning(f"Cannot complete unknown session: {session_id}")
        return
    
    now = int(time.time())
    session["status"] = "completed"
    session["did"] = did
    session["verified_at"] = now
    session["payout"] = payout_result
    
    # Log event for admin dashboard
    event = {
        "event_id": secrets.token_urlsafe(8),
        "session_id": session_id,
        "client_id": session["client_id"],
        "did": did,
        "verified_at": now,
        "payout": payout_result,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    _login_events.append(event)
    
    # Keep only last 1000 events
    if len(_login_events) > 1000:
        _login_events.pop(0)
    
    logger.info(f"Session completed: {session_id} did={did[:20]}...")


def log_payout_attempt(
    session_id: str,
    client_id: str,
    invoice: str,
    result: dict
):
    """Log a payout attempt for admin dashboard."""
    attempt = {
        "attempt_id": secrets.token_urlsafe(8),
        "session_id": session_id,
        "client_id": client_id,
        "invoice_prefix": invoice[:30] + "...",
        "result": result,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    _payout_attempts.append(attempt)
    
    # Keep only last 1000 attempts
    if len(_payout_attempts) > 1000:
        _payout_attempts.pop(0)


def get_login_events(limit: int = 100) -> list[dict]:
    """Get recent login events (for admin dashboard)."""
    return list(reversed(_login_events[-limit:]))


def get_payout_attempts(limit: int = 100) -> list[dict]:
    """Get recent payout attempts (for admin dashboard)."""
    return list(reversed(_payout_attempts[-limit:]))


def cleanup_expired_sessions():
    """Remove expired sessions (call periodically)."""
    now = int(time.time())
    expired = [sid for sid, s in _sessions.items() 
               if s["status"] == "pending" and now > s["expires_at"] + 3600]
    for sid in expired:
        del _sessions[sid]
    if expired:
        logger.info(f"Cleaned up {len(expired)} expired sessions")
