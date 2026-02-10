from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
import json

router = APIRouter()

ISSUER = "https://api.beta.privacy-lion.com"

AUTHZ = f"{ISSUER}/oidc/authorize"
TOKEN = f"{ISSUER}/oidc/token"
JWKS  = f"{ISSUER}/oidc/jwks.json"
USERINFO = f"{ISSUER}/oidc/userinfo"  # optional

@router.get("/.well-known/openid-configuration")
def openid_configuration():
    doc = {
        "issuer": ISSUER,
        "authorization_endpoint": AUTHZ,
        "token_endpoint": TOKEN,
        "jwks_uri": JWKS,
        "userinfo_endpoint": USERINFO,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["openid"],
        "claims_supported": [
            # Standard OIDC claims
            "sub", "aud", "iss", "exp", "iat", "nonce", "amr", "sid", "auth_time",
            # SignedByMe-specific claims
            "https://signedby.me/claims/attestation_hash",
            "https://signedby.me/claims/payment_verified",
            "https://signedby.me/claims/payment_hash",
            "https://signedby.me/claims/amount_sats",
        ],
        "code_challenge_methods_supported": ["S256"],
    }
    return JSONResponse(doc)

@router.get("/oidc/jwks.json")
def jwks():
    p = Path("keys/jwks.json")
    if not p.exists():
        # empty set if not present; avoids 500s during first boot
        return JSONResponse({"keys": []})
    try:
        data = json.loads(p.read_text())
        # minimal sanity check
        if not isinstance(data, dict) or "keys" not in data:
            raise ValueError("Invalid JWKS format")
        return JSONResponse(data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"JWKS load error: {e}")
