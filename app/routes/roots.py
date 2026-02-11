"""
Root Registry API

Manages Merkle roots for membership proofs.
Public endpoints for fetching active roots.
Admin endpoints for root lifecycle management.
"""
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel, Field
from typing import Optional
import time
import json
import os
from pathlib import Path

router = APIRouter(tags=["roots"])

# Config paths
ROOTS_PATH = Path(__file__).resolve().parents[2] / "roots.json"
ADMIN_API_KEY = os.environ.get("SBM_ADMIN_KEY")


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
    root_id: str = Field(..., description="Unique identifier (e.g., 'allowlist-2026-Q1')")
    purpose: str = Field(..., description="Purpose: 'allowlist' | 'issuer_batch' | 'revocation'")
    purpose_id: int = Field(..., description="Circuit-friendly enum: 0=none, 1=allowlist, 2=issuer_batch, 3=revocation")
    root: str = Field(..., description="Merkle root (64 hex chars with 0x prefix)")
    hash_alg: str = Field("poseidon", description="Hash algorithm used")
    depth: int = Field(20, description="Tree depth")
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
            print(f"Warning: Could not load roots.json: {e}")
    return []


def save_roots(roots: list[dict]) -> None:
    """Save roots to config file."""
    ROOTS_PATH.write_text(json.dumps({"roots": roots}, indent=2))


def get_canonical_root(root_id: str) -> dict | None:
    """
    Server-authoritative root lookup.
    Returns None if root_id not found, not yet valid, or expired.
    """
    now = int(time.time())
    for r in load_roots():
        if r["root_id"] == root_id:
            if now < r.get("not_before", 0):
                return None  # Not yet valid
            if now > r.get("expires_at", float("inf")):
                return None  # Expired
            return r
    return None


# === Admin Auth ===

def require_admin(x_admin_key: str = Header(..., alias="X-Admin-Key")):
    """Verify admin API key."""
    if not ADMIN_API_KEY:
        raise HTTPException(500, "Admin key not configured (set SBM_ADMIN_KEY env var)")
    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(403, "Invalid admin key")


# === Public Endpoints ===

@router.get("/v1/roots/current", response_model=RootsResponse)
def get_current_roots():
    """
    Get all currently active roots.
    
    Public endpoint - no authentication required.
    Returns roots where: not_before <= now <= expires_at
    """
    now = int(time.time())
    active = [
        r for r in load_roots()
        if r.get("not_before", 0) <= now <= r.get("expires_at", float("inf"))
    ]
    return RootsResponse(roots=[RootEntry(**r) for r in active])


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

@router.post("/v1/roots", response_model=dict, dependencies=[Depends(require_admin)])
def add_root(body: RootEntry):
    """
    Add a new root.
    
    Requires X-Admin-Key header.
    """
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
    
    print(f"Root added: {body.root_id}")
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
            print(f"Root updated: {root_id}")
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
    print(f"Root deleted: {root_id}")
    return {"ok": True, "root_id": root_id, "deleted": True}
