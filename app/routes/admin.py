"""
SignedByMe Admin API - Read-Only Dashboard Endpoints

All endpoints require Basic Auth with SBM_ADMIN_PASSWORD.
No write operations - config changes via clients.json + redeploy.
"""

import os
import json
import base64
import logging
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from . import session as session_module
from ..lib import strike

logger = logging.getLogger("admin")

router = APIRouter(prefix="/v1/admin", tags=["admin"])


def verify_admin_auth(authorization: Optional[str]) -> bool:
    """
    Verify Basic Auth credentials.
    
    Expected format: "Basic base64(admin:password)"
    Password from SBM_ADMIN_PASSWORD env var.
    """
    if not authorization:
        return False
    
    expected_password = os.environ.get("SBM_ADMIN_PASSWORD")
    if not expected_password:
        logger.warning("SBM_ADMIN_PASSWORD not set, admin endpoints disabled")
        return False
    
    try:
        if not authorization.startswith("Basic "):
            return False
        
        encoded = authorization[6:]
        decoded = base64.b64decode(encoded).decode("utf-8")
        
        if ":" not in decoded:
            return False
        
        username, password = decoded.split(":", 1)
        return username == "admin" and password == expected_password
        
    except Exception as e:
        logger.warning(f"Admin auth error: {e}")
        return False


def require_admin(authorization: Optional[str] = Header(None)):
    """Dependency to require admin auth."""
    if not verify_admin_auth(authorization):
        raise HTTPException(
            status_code=401,
            detail="Admin authentication required",
            headers={"WWW-Authenticate": "Basic realm=\"SignedByMe Admin\""}
        )


# --- Response Models ---

class AdminStatusResponse(BaseModel):
    """Service status overview."""
    ok: bool
    timestamp: str
    strike_configured: bool
    strike_balance: Optional[dict] = None
    active_sessions: int
    total_login_events: int
    total_payout_attempts: int


class LoginEvent(BaseModel):
    """A login event for the dashboard."""
    event_id: str
    session_id: str
    client_id: str
    did: str
    verified_at: int
    payout: Optional[dict] = None
    timestamp: str


class LoginEventsResponse(BaseModel):
    """List of login events."""
    events: list[LoginEvent]
    total: int


class PayoutAttempt(BaseModel):
    """A payout attempt for the dashboard."""
    attempt_id: str
    session_id: str
    client_id: str
    invoice_prefix: str
    result: dict
    timestamp: str


class PayoutAttemptsResponse(BaseModel):
    """List of payout attempts."""
    attempts: list[PayoutAttempt]
    total: int


class ClientConfigView(BaseModel):
    """Read-only view of client config (no secrets)."""
    client_id: str
    name: str
    reward_enabled: bool
    reward_amount_sats: int
    reward_provider: Optional[str] = None
    require_membership: bool
    redirect_uris: list[str]


class ClientsResponse(BaseModel):
    """List of configured clients."""
    clients: list[ClientConfigView]


# --- Endpoints ---

@router.get("/status", response_model=AdminStatusResponse)
async def get_admin_status(authorization: Optional[str] = Header(None)):
    """
    Get service status overview.
    
    Includes Strike configuration status and balance (if configured).
    """
    require_admin(authorization)
    
    # Check Strike
    strike_configured = strike.is_strike_configured()
    strike_balance = None
    if strike_configured:
        strike_balance = await strike.get_account_balance()
    
    # Get counts
    events = session_module.get_login_events(limit=1)
    payouts = session_module.get_payout_attempts(limit=1)
    
    return AdminStatusResponse(
        ok=True,
        timestamp=datetime.now(timezone.utc).isoformat(),
        strike_configured=strike_configured,
        strike_balance=strike_balance,
        active_sessions=0,  # TODO: count non-expired sessions
        total_login_events=len(session_module._login_events),
        total_payout_attempts=len(session_module._payout_attempts)
    )


@router.get("/events", response_model=LoginEventsResponse)
async def get_login_events(
    authorization: Optional[str] = Header(None),
    limit: int = Query(100, ge=1, le=1000),
    client_id: Optional[str] = Query(None)
):
    """
    Get recent login events.
    
    Optionally filter by client_id.
    """
    require_admin(authorization)
    
    events = session_module.get_login_events(limit=limit)
    
    # Filter by client_id if specified
    if client_id:
        events = [e for e in events if e.get("client_id") == client_id]
    
    return LoginEventsResponse(
        events=[LoginEvent(**e) for e in events],
        total=len(events)
    )


@router.get("/payments", response_model=PayoutAttemptsResponse)
async def get_payout_attempts(
    authorization: Optional[str] = Header(None),
    limit: int = Query(100, ge=1, le=1000),
    client_id: Optional[str] = Query(None)
):
    """
    Get recent payout attempts.
    
    Optionally filter by client_id.
    """
    require_admin(authorization)
    
    attempts = session_module.get_payout_attempts(limit=limit)
    
    # Filter by client_id if specified
    if client_id:
        attempts = [a for a in attempts if a.get("client_id") == client_id]
    
    return PayoutAttemptsResponse(
        attempts=[PayoutAttempt(**a) for a in attempts],
        total=len(attempts)
    )


@router.get("/clients", response_model=ClientsResponse)
async def get_clients(authorization: Optional[str] = Header(None)):
    """
    Get configured clients (read-only, no secrets).
    
    Shows reward policy and membership requirements.
    """
    require_admin(authorization)
    
    # Load clients config
    clients_path = os.environ.get("CLIENTS_JSON", "/opt/sbm-api/clients.json")
    if not os.path.exists(clients_path):
        clients_path = os.path.join(os.path.dirname(__file__), "../../clients.json")
    
    try:
        with open(clients_path) as f:
            clients_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load clients.json: {e}")
        raise HTTPException(500, "Failed to load client configuration")
    
    clients = []
    for client_id, config in clients_data.items():
        reward_policy = config.get("reward_policy", {})
        clients.append(ClientConfigView(
            client_id=client_id,
            name=config.get("name", client_id),
            reward_enabled=reward_policy.get("enabled", False),
            reward_amount_sats=reward_policy.get("amount_sats", 0),
            reward_provider=reward_policy.get("provider"),
            require_membership=config.get("require_membership", False),
            redirect_uris=config.get("redirect_uris", [])
        ))
    
    return ClientsResponse(clients=clients)
