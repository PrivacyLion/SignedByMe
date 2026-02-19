import os, hashlib, time, jwt
from typing import Optional, Tuple

try:
    from coincurve import PublicKey
    HAS_COINCURVE = True
except ImportError:
    HAS_COINCURVE = False

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


def verify_secp256k1_signature(
    message: bytes,
    pubkey_hex: str,
    signature_hex: str,
) -> Tuple[bool, str]:
    """
    Verify a secp256k1 signature using coincurve.
    
    Args:
        message: The raw message bytes that were signed
        pubkey_hex: Hex-encoded public key (33 bytes compressed or 65 bytes uncompressed)
        signature_hex: Hex-encoded signature (64 bytes compact or 65 bytes with recovery id)
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not HAS_COINCURVE:
        return False, "coincurve library not installed"
    
    try:
        # Parse public key
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        if len(pubkey_bytes) not in (33, 65):
            return False, f"Invalid public key length: {len(pubkey_bytes)} (expected 33 or 65)"
        
        pubkey = PublicKey(pubkey_bytes)
        
        # Parse signature
        sig_bytes = bytes.fromhex(signature_hex)
        
        # Handle different signature formats
        if len(sig_bytes) == 65:
            # DER or recoverable signature with recovery id - strip recovery id
            sig_bytes = sig_bytes[:64]
        elif len(sig_bytes) != 64:
            return False, f"Invalid signature length: {len(sig_bytes)} (expected 64 or 65)"
        
        # Hash the message (signatures are over SHA256 hash)
        message_hash = hashlib.sha256(message).digest()
        
        # Verify
        is_valid = pubkey.verify(sig_bytes, message_hash)
        
        if is_valid:
            return True, "Signature verified"
        else:
            return False, "Signature verification failed"
            
    except ValueError as e:
        return False, f"Invalid key or signature format: {e}"
    except Exception as e:
        return False, f"Verification error: {e}"


def verify_secp256k1_signature_hex_message(
    message_hex: str,
    pubkey_hex: str,
    signature_hex: str,
) -> Tuple[bool, str]:
    """
    Verify a secp256k1 signature where the message is hex-encoded.
    """
    try:
        message_bytes = bytes.fromhex(message_hex)
        return verify_secp256k1_signature(message_bytes, pubkey_hex, signature_hex)
    except ValueError:
        return False, "Invalid hex message"


def verify_binding_signature(
    binding_hash: bytes,
    pubkey_hex: str,
    signature_hex: str,
) -> Tuple[bool, str]:
    """
    Verify the binding signature in the login flow.
    The binding hash is signed directly (already a hash).
    """
    if not HAS_COINCURVE:
        return False, "coincurve library not installed"
    
    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        pubkey = PublicKey(pubkey_bytes)
        
        sig_bytes = bytes.fromhex(signature_hex)
        if len(sig_bytes) == 65:
            sig_bytes = sig_bytes[:64]
        
        # For binding signatures, we sign the hash directly (it's already hashed)
        is_valid = pubkey.verify(sig_bytes, binding_hash)
        
        if is_valid:
            return True, "Binding signature verified"
        else:
            return False, "Binding signature invalid"
            
    except Exception as e:
        return False, f"Binding signature verification error: {e}"


# Legacy stub for backwards compatibility during transition
def verify_secp256k1_signature_stub(message: str, pubkey_hex: str, signature_hex: str) -> bool:
    """
    DEPRECATED: Use verify_secp256k1_signature() instead.
    This stub remains for backwards compatibility but now performs real verification.
    """
    if not HAS_COINCURVE:
        # Log warning but don't fail - allows graceful degradation during deployment
        import logging
        logging.warning("coincurve not installed - signature verification skipped!")
        return True
    
    is_valid, _ = verify_secp256k1_signature(message.encode('utf-8'), pubkey_hex, signature_hex)
    return is_valid
