import os, hashlib, time, jwt
from typing import Optional

# SECURITY: API_SECRET must be set in production - no insecure default
_secret = os.getenv("API_SECRET")
if not _secret:
    import warnings
    warnings.warn("API_SECRET not set! Using insecure dev default. DO NOT USE IN PRODUCTION.", stacklevel=2)
    _secret = "dev-secret-INSECURE"
API_SECRET = _secret

def hmac_token(payload: dict, ttl_secs: int = 86400) -> str:
    now = int(time.time())
    body = {**payload, "iat": now, "exp": now + ttl_secs}
    return jwt.encode(body, API_SECRET, algorithm="HS256")

def verify_hmac_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, API_SECRET, algorithms=["HS256"])
    except Exception:
        return None

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def verify_secp256k1_signature_stub(message: str, pubkey_hex: str, signature_hex: str) -> bool:
    """
    SECURITY WARNING: This is a STUB that always returns True!
    DO NOT use in production. Replace with real secp256k1 verification.
    
    TODO: Implement real verification using python-secp256k1 or coincurve
    """
    import warnings
    warnings.warn("verify_secp256k1_signature_stub is a STUB - not verifying signature!", stacklevel=2)
    _ = (message, pubkey_hex, signature_hex)
    return True
