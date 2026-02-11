"""
Membership enrollment and tree management.

NOTE: These endpoints are GATED behind INTERNAL_ADMIN_ONLY flag.
Production architecture is "enterprise-built trees" where:
- Enterprises collect commitments directly from users
- Enterprises build trees locally with CLI
- Enterprises publish only roots to /v1/roots

These endpoints exist for:
- Internal testing
- Dev/debug workflows  
- Potential future "managed mode"

Set SBM_INTERNAL_ADMIN=true to enable these endpoints.
"""

import os
import json
import time
import secrets
import hashlib
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

router = APIRouter(tags=["membership"])

# Feature flag - these endpoints are internal-only by default
INTERNAL_ADMIN_ONLY = os.getenv("SBM_INTERNAL_ADMIN", "").lower() in ("true", "1", "yes")

# Storage paths
DATA_DIR = Path(__file__).resolve().parents[2]
ENROLLMENTS_FILE = DATA_DIR / "enrollments.json"
ROOTS_FILE = DATA_DIR / "roots.json"

# Admin API key (separate from enterprise keys)
ADMIN_API_KEY = os.getenv("SBM_ADMIN_KEY", "sbm_admin_dev_key")


def require_internal_enabled():
    """Check if internal admin endpoints are enabled."""
    if not INTERNAL_ADMIN_ONLY:
        raise HTTPException(
            403, 
            "Internal admin endpoints disabled. Set SBM_INTERNAL_ADMIN=true to enable. "
            "Production architecture uses enterprise-built trees."
        )


def load_enrollments() -> dict:
    """Load pending enrollments."""
    if ENROLLMENTS_FILE.exists():
        return json.loads(ENROLLMENTS_FILE.read_text())
    return {"pending": [], "approved": []}


def save_enrollments(data: dict):
    """Save enrollments."""
    ENROLLMENTS_FILE.write_text(json.dumps(data, indent=2))


def load_roots() -> dict:
    """Load roots registry."""
    if ROOTS_FILE.exists():
        return json.loads(ROOTS_FILE.read_text())
    return {"roots": []}


def save_roots(data: dict):
    """Save roots registry."""
    ROOTS_FILE.write_text(json.dumps(data, indent=2))


def load_clients() -> dict:
    """Load enterprise client configs."""
    clients_file = DATA_DIR / "clients.json"
    if clients_file.exists():
        return json.loads(clients_file.read_text())
    return {}


def validate_enterprise_key(api_key: str) -> tuple[str, dict]:
    """Validate enterprise API key, return (client_id, config)."""
    clients = load_clients()
    for client_id, config in clients.items():
        if config.get("api_key") == api_key:
            return client_id, config
    raise HTTPException(401, "Invalid API key")


def validate_admin_key(api_key: str):
    """Validate admin API key."""
    if api_key != ADMIN_API_KEY:
        raise HTTPException(401, "Invalid admin key")


# =============================================================================
# Models
# =============================================================================

class EnrollRequest(BaseModel):
    """User enrollment request."""
    leaf_commitment: str = Field(..., description="Hex-encoded leaf commitment (32 bytes)")
    purpose: str = Field("allowlist", description="Purpose: allowlist, issuer_batch, revocation")
    # For allowlist, user should specify which enterprise they're enrolling with
    enterprise_hint: Optional[str] = Field(None, description="Enterprise name (for allowlist)")


class EnrollResponse(BaseModel):
    """Enrollment response."""
    enrollment_id: str
    status: str  # "pending" or "approved"
    purpose: str
    message: str


class ApproveRequest(BaseModel):
    """Admin approval request."""
    enrollment_ids: List[str] = Field(..., description="List of enrollment IDs to approve")


class BuildTreeRequest(BaseModel):
    """Request to build a Merkle tree from approved enrollments."""
    purpose: str = Field(..., description="Purpose: allowlist, issuer_batch, revocation")
    client_id: Optional[str] = Field(None, description="Client ID (required for allowlist)")
    root_id: Optional[str] = Field(None, description="Custom root ID (auto-generated if not provided)")
    description: Optional[str] = Field(None, description="Human-readable description")
    expires_days: int = Field(365, description="Days until root expires")


class BuildTreeResponse(BaseModel):
    """Tree build response."""
    root_id: str
    root: str  # Hex-encoded root hash
    purpose: str
    leaf_count: int
    created_at: int
    expires_at: int


class ListEnrollmentsResponse(BaseModel):
    """List enrollments response."""
    pending: List[dict]
    approved: List[dict]


# =============================================================================
# Purpose ID mapping
# =============================================================================

PURPOSE_IDS = {
    "none": 0,
    "allowlist": 1,
    "issuer_batch": 2,
    "revocation": 3,
}


def get_purpose_id(purpose: str) -> int:
    return PURPOSE_IDS.get(purpose, 0)


# =============================================================================
# Enrollment Endpoints
# =============================================================================

@router.post("/v1/membership/enroll", response_model=EnrollResponse)
def enroll_member(body: EnrollRequest):
    """
    Submit a leaf commitment for membership enrollment.
    
    GATED: Requires SBM_INTERNAL_ADMIN=true.
    Production uses enterprise-built trees (commitments collected by enterprise, not SBM).
    """
    require_internal_enabled()
    
    # Validate commitment format
    try:
        commitment_bytes = bytes.fromhex(body.leaf_commitment)
        if len(commitment_bytes) != 32:
            raise ValueError("Must be 32 bytes")
    except Exception as e:
        raise HTTPException(400, f"Invalid leaf_commitment: {e}")
    
    # Validate purpose
    if body.purpose not in PURPOSE_IDS:
        raise HTTPException(400, f"Invalid purpose. Must be one of: {list(PURPOSE_IDS.keys())}")
    
    # Generate enrollment ID
    enrollment_id = secrets.token_urlsafe(16)
    
    enrollment = {
        "enrollment_id": enrollment_id,
        "leaf_commitment": body.leaf_commitment,
        "purpose": body.purpose,
        "enterprise_hint": body.enterprise_hint,
        "created_at": int(time.time()),
    }
    
    data = load_enrollments()
    
    # Auto-approve issuer_batch (SignedByMe controls this)
    if body.purpose == "issuer_batch":
        enrollment["status"] = "approved"
        enrollment["approved_at"] = int(time.time())
        data["approved"].append(enrollment)
        status = "approved"
        message = "Auto-approved for issuer batch"
    else:
        enrollment["status"] = "pending"
        data["pending"].append(enrollment)
        status = "pending"
        message = "Pending enterprise admin approval"
    
    save_enrollments(data)
    
    return EnrollResponse(
        enrollment_id=enrollment_id,
        status=status,
        purpose=body.purpose,
        message=message,
    )


@router.get("/v1/membership/enrollments", response_model=ListEnrollmentsResponse)
def list_enrollments(
    purpose: Optional[str] = None,
    status: Optional[str] = None,
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """
    List enrollments (admin only).
    
    GATED: Requires SBM_INTERNAL_ADMIN=true.
    """
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    data = load_enrollments()
    
    pending = data.get("pending", [])
    approved = data.get("approved", [])
    
    # Apply filters
    if purpose:
        pending = [e for e in pending if e.get("purpose") == purpose]
        approved = [e for e in approved if e.get("purpose") == purpose]
    
    if status == "pending":
        approved = []
    elif status == "approved":
        pending = []
    
    return ListEnrollmentsResponse(pending=pending, approved=approved)


@router.post("/v1/membership/approve")
def approve_enrollments(
    body: ApproveRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """
    Approve pending enrollments (admin only).
    
    GATED: Requires SBM_INTERNAL_ADMIN=true.
    """
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    data = load_enrollments()
    
    approved_count = 0
    not_found = []
    
    for enrollment_id in body.enrollment_ids:
        # Find in pending
        found = None
        for i, e in enumerate(data["pending"]):
            if e["enrollment_id"] == enrollment_id:
                found = (i, e)
                break
        
        if found:
            idx, enrollment = found
            enrollment["status"] = "approved"
            enrollment["approved_at"] = int(time.time())
            data["approved"].append(enrollment)
            data["pending"].pop(idx)
            approved_count += 1
        else:
            not_found.append(enrollment_id)
    
    save_enrollments(data)
    
    return {
        "approved": approved_count,
        "not_found": not_found,
    }


# =============================================================================
# Tree Building
# =============================================================================

def poseidon_hash_pair(left: bytes, right: bytes) -> bytes:
    """
    Placeholder Poseidon hash. 
    In production, this calls the Rust implementation.
    For now, we use SHA256 as a stand-in.
    """
    # TODO: Call Rust Poseidon via FFI or subprocess
    # For now, use SHA256 with domain separator
    return hashlib.sha256(b"poseidon:" + left + right).digest()


def build_merkle_tree(leaves: List[bytes]) -> tuple[bytes, List[List[bytes]]]:
    """
    Build a Merkle tree from leaves.
    
    Returns (root, layers) where layers[0] = leaves, layers[-1] = [root].
    """
    if not leaves:
        return bytes(32), [[]]
    
    # Ensure power of 2 (pad with zeros)
    n = len(leaves)
    next_pow2 = 1
    while next_pow2 < n:
        next_pow2 *= 2
    
    padded = leaves + [bytes(32)] * (next_pow2 - n)
    
    layers = [padded]
    current = padded
    
    while len(current) > 1:
        next_layer = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else bytes(32)
            parent = poseidon_hash_pair(left, right)
            next_layer.append(parent)
        layers.append(next_layer)
        current = next_layer
    
    root = current[0] if current else bytes(32)
    return root, layers


@router.post("/v1/membership/build-tree", response_model=BuildTreeResponse)
def build_tree(
    body: BuildTreeRequest,
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """
    Build a Merkle tree from approved enrollments and publish the root.
    
    GATED: Requires SBM_INTERNAL_ADMIN=true.
    Production uses enterprise-built trees (CLI tool).
    """
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    # Validate purpose
    if body.purpose not in PURPOSE_IDS:
        raise HTTPException(400, f"Invalid purpose: {body.purpose}")
    
    purpose_id = get_purpose_id(body.purpose)
    
    # Allowlist requires client_id
    if body.purpose == "allowlist" and not body.client_id:
        raise HTTPException(400, "client_id required for allowlist purpose")
    
    # Load approved enrollments for this purpose
    data = load_enrollments()
    approved = data.get("approved", [])
    
    # Filter by purpose (and client_id for allowlist)
    matching = []
    remaining = []
    
    for e in approved:
        if e.get("purpose") == body.purpose:
            # For allowlist, also check enterprise_hint matches client_id
            if body.purpose == "allowlist":
                if e.get("enterprise_hint") == body.client_id:
                    matching.append(e)
                else:
                    remaining.append(e)
            else:
                matching.append(e)
        else:
            remaining.append(e)
    
    if not matching:
        raise HTTPException(400, "No approved enrollments found for this purpose/client")
    
    # Extract leaf commitments
    leaves = []
    for e in matching:
        try:
            leaf = bytes.fromhex(e["leaf_commitment"])
            leaves.append(leaf)
        except:
            pass  # Skip invalid
    
    if not leaves:
        raise HTTPException(400, "No valid leaf commitments")
    
    # Build tree
    root, layers = build_merkle_tree(leaves)
    root_hex = "0x" + root.hex()
    
    # Generate root_id
    now = int(time.time())
    if body.root_id:
        root_id = body.root_id
    else:
        prefix = body.client_id or "sbm"
        root_id = f"{prefix}-{body.purpose}-{now}"
    
    expires_at = now + (body.expires_days * 86400)
    
    # Create root entry
    root_entry = {
        "root_id": root_id,
        "purpose": body.purpose,
        "purpose_id": purpose_id,
        "root": root_hex,
        "hash_alg": "poseidon",
        "depth": len(layers) - 1,
        "leaf_count": len(leaves),
        "client_id": body.client_id,  # None for global roots
        "not_before": now,
        "expires_at": expires_at,
        "description": body.description or f"{body.purpose} tree with {len(leaves)} members",
        "created_at": now,
    }
    
    # Save root
    roots_data = load_roots()
    roots_data["roots"].append(root_entry)
    save_roots(roots_data)
    
    # Remove consumed enrollments
    data["approved"] = remaining
    save_enrollments(data)
    
    return BuildTreeResponse(
        root_id=root_id,
        root=root_hex,
        purpose=body.purpose,
        leaf_count=len(leaves),
        created_at=now,
        expires_at=expires_at,
    )


@router.delete("/v1/membership/enrollments/{enrollment_id}")
def delete_enrollment(
    enrollment_id: str,
    x_admin_key: str = Header(..., alias="X-Admin-Key")
):
    """
    Delete a pending or approved enrollment (admin only).
    
    GATED: Requires SBM_INTERNAL_ADMIN=true.
    """
    require_internal_enabled()
    validate_admin_key(x_admin_key)
    
    data = load_enrollments()
    
    # Check pending
    for i, e in enumerate(data["pending"]):
        if e["enrollment_id"] == enrollment_id:
            data["pending"].pop(i)
            save_enrollments(data)
            return {"deleted": enrollment_id, "was_status": "pending"}
    
    # Check approved
    for i, e in enumerate(data["approved"]):
        if e["enrollment_id"] == enrollment_id:
            data["approved"].pop(i)
            save_enrollments(data)
            return {"deleted": enrollment_id, "was_status": "approved"}
    
    raise HTTPException(404, "Enrollment not found")
