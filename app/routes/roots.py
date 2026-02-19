"""
Root Registry API

Manages Merkle roots for membership proofs.
- Public endpoint for fetching roots by client_id
- Enterprise endpoint for publishing roots (scoped to client_id)
- Admin endpoints for root lifecycle management

INVARIANT: Acme roots NEVER satisfy BetaCorp sessions (client_id scoping)
"""
from fastapi import APIRouter, HTTPException, Header, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional
import time
import json
import os
import logging
from pathlib import Path

logger = logging.getLogger("roots")
router = APIRouter(tags=["roots"])

# Config paths
DATA_DIR = Path(__file__).resolve().parents[2]
ROOTS_PATH = DATA_DIR / "roots.json"
CLIENTS_PATH = DATA_DIR / "clients.json"
ADMIN_API_KEY = os.environ.get("SBM_ADMIN_KEY")


def load_clients() -> dict:
    """Load enterprise client configs."""
    if CLIENTS_PATH.exists():
        return json.loads(CLIENTS_PATH.read_text())
    return {}


def validate_enterprise_key(api_key: str) -> tuple[str, dict]:
    """Validate enterprise API key, return (client_id, config)."""
    clients = load_clients()
    for client_id, config in clients.items():
        if config.get("api_key") == api_key:
            return client_id, config
    raise HTTPException(401, "Invalid API key")


# === Purpose ID Enum (circuit-friendly) ===

PURPOSE_NONE = 0
PURPOSE_ALLOWLIST = 1
PURPOSE_ISSUER_BATCH = 2
PURPOSE_REVOCATION = 3

PURPOSE_MAP = {
    "": PURPOSE_NONE,
    "allowlist": PURPOSE_ALLOWLIST,
    "issuer_batch": PURPOSE_ISSUER_BATCH,
    "revocation": PURPOSE_REVOCATION,
}


def get_purpose_id(purpose: str) -> int:
    """Convert purpose string to circuit-friendly enum."""
    return PURPOSE_MAP.get(purpose, PURPOSE_NONE)


# === Models ===

class RootEntry(BaseModel):
    """A Merkle root entry."""
    root_id: str = Field(..., description="Unique identifier (e.g., 'acme-allowlist-2026-Q1')")
    client_id: str = Field(..., description="Enterprise client_id this root belongs to")
    purpose: str = Field(..., description="Purpose: 'allowlist' | 'issuer_batch' | 'revocation'")
    purpose_id: int = Field(..., description="Circuit-friendly enum: 0=none, 1=allowlist, 2=issuer_batch, 3=revocation")
    root: str = Field(..., description="Merkle root (64 hex chars with 0x prefix)")
    hash_alg: str = Field("poseidon", description="Hash algorithm used")
    depth: int = Field(20, description="Tree depth (standardized to 20, pad with zeros)")
    not_before: int = Field(0, description="Unix timestamp: root becomes valid")
    expires_at: int = Field(2000000000, description="Unix timestamp: root expires")
    description: Optional[str] = Field(None, description="Human description")


class RootPatch(BaseModel):
    """Patch for updating a root."""
    expires_at: Optional[int] = None
    not_before: Optional[int] = None
    description: Optional[str] = None


class RootsResponse(BaseModel):
    """Response containing list of roots."""
    roots: list[RootEntry]


# === Storage Helpers ===

def load_roots() -> list[dict]:
    """Load roots from config file."""
    if ROOTS_PATH.exists():
        try:
            data = json.loads(ROOTS_PATH.read_text())
            return data.get("roots", [])
        except Exception as e:
            logger.warning(f"Could not load roots.json: {e}")
    return []


def save_roots(roots: list[dict]) -> None:
    """Save roots to config file."""
    ROOTS_PATH.write_text(json.dumps({"roots": roots}, indent=2))


def get_canonical_root(root_id: str, client_id: str = None) -> dict | None:
    """
    Server-authoritative root lookup.
    Returns None if root_id not found, not yet valid, expired, or wrong client_id.
    
    INVARIANT: If client_id is provided, root must belong to that client.
    """
    now = int(time.time())
    for r in load_roots():
        if r["root_id"] == root_id:
            # Client scoping check (critical security invariant)
            if client_id and r.get("client_id") != client_id:
                return None  # Wrong client - Acme roots don't satisfy BetaCorp
            if now < r.get("not_before", 0):
                return None  # Not yet valid
            if now > r.get("expires_at", float("inf")):
                return None  # Expired
            return r
    return None


def get_active_root_for_client(client_id: str, purpose: str = None) -> dict | None:
    """
    Get the active root for a client (optionally filtered by purpose).
    Returns the most recently created active root.
    """
    now = int(time.time())
    matching = []
    for r in load_roots():
        if r.get("client_id") != client_id:
            continue
        if purpose and r.get("purpose") != purpose:
            continue
        if now < r.get("not_before", 0):
            continue
        if now > r.get("expires_at", float("inf")):
            continue
        matching.append(r)
    
    if not matching:
        return None
    
    # Return most recent (by not_before or created_at)
    return max(matching, key=lambda r: r.get("not_before", 0))


# === Admin Auth ===

def require_admin(x_admin_key: str = Header(..., alias="X-Admin-Key")):
    """Verify admin API key."""
    if not ADMIN_API_KEY:
        raise HTTPException(500, "Admin key not configured (set SBM_ADMIN_KEY env var)")
    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(403, "Invalid admin key")


# === Public Endpoints ===

@router.get("/v1/roots/current", response_model=RootsResponse)
def get_current_roots(
    client_id: Optional[str] = Query(None, description="Filter by client_id (required for client-specific roots)")
):
    """
    Get currently active roots, optionally filtered by client_id.
    
    Public endpoint - no authentication required.
    Returns roots where: not_before <= now <= expires_at
    
    If client_id is provided, returns only that client's roots.
    Mobile apps should pass client_id to get the correct root for their enterprise.
    """
    now = int(time.time())
    active = []
    for r in load_roots():
        # Time-based filtering
        if not (r.get("not_before", 0) <= now <= r.get("expires_at", float("inf"))):
            continue
        # Client filtering (if requested)
        if client_id and r.get("client_id") != client_id:
            continue
        active.append(r)
    
    # Handle roots without client_id (legacy/global roots) - include if no filter
    if not client_id:
        pass  # Already included
    
    return RootsResponse(roots=[RootEntry(**r) for r in active if "client_id" in r])


@router.get("/v1/roots/{root_id}", response_model=RootEntry)
def get_root(root_id: str):
    """
    Get a specific root by ID.
    
    Returns the root even if expired (for audit purposes).
    Public endpoint - no authentication required.
    """
    for r in load_roots():
        if r["root_id"] == root_id:
            return RootEntry(**r)
    raise HTTPException(404, f"Root not found: {root_id}")


# === Admin Endpoints ===

class RootPublishRequest(BaseModel):
    """Request to publish a new root (from enterprise)."""
    root_id: str = Field(..., description="Unique identifier")
    purpose: str = Field(..., description="Purpose: 'allowlist' | 'issuer_batch' | 'revocation'")
    root: str = Field(..., description="Merkle root (64 hex chars with 0x prefix)")
    hash_alg: str = Field("poseidon", description="Hash algorithm used")
    depth: int = Field(20, description="Tree depth (must be 20)")
    not_before: Optional[int] = Field(None, description="Unix timestamp: root becomes valid (default: now)")
    expires_at: Optional[int] = Field(None, description="Unix timestamp: root expires (default: 1 year)")
    description: Optional[str] = Field(None, description="Human description")


@router.post("/v1/roots", response_model=dict)
def publish_root(
    body: RootPublishRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Publish a new root (enterprise endpoint).
    
    Requires X-API-Key header (enterprise API key).
    Root is automatically scoped to the enterprise's client_id.
    
    INVARIANT: depth must be 20 (standardized, pad with zeros if fewer leaves).
    """
    # Validate enterprise API key and get client_id
    client_id, client_config = validate_enterprise_key(x_api_key)
    
    # Enforce depth=20 standard
    if body.depth != 20:
        raise HTTPException(400, f"depth must be 20 (got {body.depth}). Pad tree with zero leaves if needed.")
    
    roots = load_roots()
    
    # Check for duplicate
    if any(r["root_id"] == body.root_id for r in roots):
        raise HTTPException(400, f"root_id already exists: {body.root_id}")
    
    # Validate purpose_id
    purpose_id = get_purpose_id(body.purpose)
    if purpose_id == 0 and body.purpose:
        raise HTTPException(400, f"Invalid purpose: {body.purpose}")
    
    # Set defaults
    now = int(time.time())
    not_before = body.not_before if body.not_before is not None else now
    expires_at = body.expires_at if body.expires_at is not None else now + (365 * 86400)  # 1 year
    
    root_entry = {
        "root_id": body.root_id,
        "client_id": client_id,  # Scoped to this enterprise
        "purpose": body.purpose,
        "purpose_id": purpose_id,
        "root": body.root,
        "hash_alg": body.hash_alg,
        "depth": body.depth,
        "not_before": not_before,
        "expires_at": expires_at,
        "description": body.description or f"{client_id} {body.purpose} root",
    }
    
    roots.append(root_entry)
    save_roots(roots)
    
    logger.info(f"Root published: {body.root_id} for client {client_id}")
    return {"ok": True, "root_id": body.root_id, "client_id": client_id}


@router.post("/v1/roots/admin", response_model=dict, dependencies=[Depends(require_admin)])
def add_root_admin(body: RootEntry):
    """
    Add a new root (admin endpoint).
    
    Requires X-Admin-Key header. Use for dev/testing.
    This endpoint allows specifying client_id directly.
    
    INVARIANT: depth must be 20 (standardized).
    """
    # Enforce depth=20 standard (same as enterprise endpoint)
    if body.depth != 20:
        raise HTTPException(400, f"depth must be 20 (got {body.depth}). Pad tree with zero leaves if needed.")
    
    roots = load_roots()
    
    # Check for duplicate
    if any(r["root_id"] == body.root_id for r in roots):
        raise HTTPException(400, f"root_id already exists: {body.root_id}")
    
    # Validate purpose_id matches purpose
    expected_id = get_purpose_id(body.purpose)
    if body.purpose_id != expected_id:
        raise HTTPException(400, f"purpose_id mismatch: expected {expected_id} for purpose '{body.purpose}'")
    
    roots.append(body.dict())
    save_roots(roots)
    
    logger.info(f"Root added (admin): {body.root_id}")
    return {"ok": True, "root_id": body.root_id}


@router.patch("/v1/roots/{root_id}", response_model=dict, dependencies=[Depends(require_admin)])
def update_root(root_id: str, patch: RootPatch):
    """
    Update a root (typically for deprecation).
    
    Requires X-Admin-Key header.
    Common use: set expires_at to deprecate a root.
    """
    roots = load_roots()
    
    for r in roots:
        if r["root_id"] == root_id:
            if patch.expires_at is not None:
                r["expires_at"] = patch.expires_at
            if patch.not_before is not None:
                r["not_before"] = patch.not_before
            if patch.description is not None:
                r["description"] = patch.description
            
            save_roots(roots)
            logger.info(f"Root updated: {root_id}")
            return {"ok": True, "root_id": root_id}
    
    raise HTTPException(404, f"Root not found: {root_id}")


@router.delete("/v1/roots/{root_id}", response_model=dict, dependencies=[Depends(require_admin)])
def delete_root(root_id: str):
    """
    Delete a root entirely.
    
    Requires X-Admin-Key header.
    Use with caution - prefer setting expires_at for graceful deprecation.
    """
    roots = load_roots()
    new_roots = [r for r in roots if r["root_id"] != root_id]
    
    if len(new_roots) == len(roots):
        raise HTTPException(404, f"Root not found: {root_id}")
    
    save_roots(new_roots)
    logger.info(f"Root deleted: {root_id}")
    return {"ok": True, "root_id": root_id, "deleted": True}
