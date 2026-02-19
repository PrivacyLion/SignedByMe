import os, hashlib, time, jwt
from typing import Optional

API_SECRET = os.getenv("API_SECRET", "dev-secret")

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
    # TODO: replace with strict check once we lock encoding from your iOS signer
    _ = (message, pubkey_hex, signature_hex)
    return True
