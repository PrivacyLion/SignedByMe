"""
Cryptographic utilities for SignedByMe API.

SECURITY: All verification functions FAIL CLOSED - they return False
if required libraries are not installed. No silent degradation.
"""
import os
import hashlib
import time
import logging

logger = logging.getLogger(__name__)

# Try to import JWT library
try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False
    logger.error("PyJWT not installed - JWT verification disabled")

# Try to import secp256k1 library
try:
    from coincurve import PublicKey
    HAS_COINCURVE = True
except ImportError:
    HAS_COINCURVE = False
    logger.error("coincurve not installed - signature verification disabled")

# SECURITY: No default API_SECRET - must be set via environment
API_SECRET = os.getenv("API_SECRET")
if not API_SECRET:
    logger.critical("API_SECRET environment variable not set - JWT signing disabled")


def hmac_token(payload: dict, ttl_secs: int = 86400) -> str:
    """
    Create an HMAC-signed JWT token.
    
    SECURITY: Fails if API_SECRET not set.
    """
    if not API_SECRET:
        raise RuntimeError("API_SECRET not configured - cannot sign tokens")
    if not HAS_JWT:
        raise RuntimeError("PyJWT not installed - cannot sign tokens")
    
    now = int(time.time())
    body = {**payload, "iat": now, "exp": now + ttl_secs}
    return jwt.encode(body, API_SECRET, algorithm="HS256")


def verify_hmac_token(token: str) -> dict | None:
    """
    Verify an HMAC-signed JWT token.
    
    SECURITY: Fails closed if API_SECRET not set or JWT library missing.
    """
    if not API_SECRET:
        logger.error("Cannot verify token: API_SECRET not configured")
        return None
    if not HAS_JWT:
        logger.error("Cannot verify token: PyJWT not installed")
        return None
    
    try:
        return jwt.decode(token, API_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None


def sha256_hex(data: str | bytes) -> str:
    """Compute SHA-256 hash and return as hex string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Compute SHA-256 hash and return as bytes."""
    return hashlib.sha256(data).digest()


def verify_secp256k1_signature(
    message: bytes,
    pubkey_hex: str,
    signature_hex: str,
) -> tuple[bool, str]:
    """
    Verify a secp256k1 signature using coincurve.
    
    SECURITY: Fails closed if coincurve not installed.
    
    Args:
        message: The raw message bytes that were signed
        pubkey_hex: Hex-encoded public key (33 bytes compressed or 65 bytes uncompressed)
        signature_hex: Hex-encoded signature (64 bytes compact or 65 bytes with recovery id)
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not HAS_COINCURVE:
        return False, "SECURITY: coincurve library not installed - verification failed"
    
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
) -> tuple[bool, str]:
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
) -> tuple[bool, str]:
    """
    Verify the binding signature in the login flow.
    The binding hash is signed directly (already a hash).
    
    SECURITY: Fails closed if coincurve not installed.
    """
    if not HAS_COINCURVE:
        return False, "SECURITY: coincurve library not installed - verification failed"
    
    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        pubkey = PublicKey(pubkey_bytes)
        
        sig_bytes = bytes.fromhex(signature_hex)
        if len(sig_bytes) == 65:
            sig_bytes = sig_bytes[:64]
        elif len(sig_bytes) != 64:
            return False, f"Invalid signature length: {len(sig_bytes)}"
        
        # For binding signatures, we sign the hash directly (it's already hashed)
        is_valid = pubkey.verify(sig_bytes, binding_hash)
        
        if is_valid:
            return True, "Binding signature verified"
        else:
            return False, "Binding signature invalid"
            
    except Exception as e:
        return False, f"Binding signature verification error: {e}"


# SECURITY: No backwards-compat stubs that skip verification
def verify_secp256k1_signature_stub(message: str, pubkey_hex: str, signature_hex: str) -> bool:
    """
    DEPRECATED: Use verify_secp256k1_signature() instead.
    
    SECURITY: This now fails closed if coincurve is not installed.
    """
    if not HAS_COINCURVE:
        logger.error("SECURITY: coincurve not installed - signature verification FAILED")
        return False
    
    is_valid, _ = verify_secp256k1_signature(message.encode('utf-8'), pubkey_hex, signature_hex)
    return is_valid


def is_crypto_available() -> dict:
    """Check which crypto libraries are available."""
    return {
        "jwt": HAS_JWT,
        "coincurve": HAS_COINCURVE,
        "api_secret_configured": bool(API_SECRET),
    }
