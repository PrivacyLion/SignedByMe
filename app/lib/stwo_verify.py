"""
Real STWO Proof Verification
Uses the compiled Rust verifier binary for cryptographically sound verification
"""
import subprocess
import json
import os
from pathlib import Path
from typing import Tuple

# Path to the verifier binary (built by GitHub Actions)
VERIFIER_PATH = Path(__file__).resolve().parents[2] / "bin" / "stwo_verifier"


def has_real_verifier() -> bool:
    """Check if the real STWO verifier binary is available"""
    return VERIFIER_PATH.exists() and os.access(VERIFIER_PATH, os.X_OK)


def verify_stwo_proof(proof_json: str) -> Tuple[bool, str]:
    """
    Verify an STWO proof using the real Rust verifier.
    
    Args:
        proof_json: JSON string of the proof to verify
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not has_real_verifier():
        return False, "Real STWO verifier not available (binary not found)"
    
    try:
        result = subprocess.run(
            [str(VERIFIER_PATH)],
            input=proof_json,
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout for verification
        )
        
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        
        if result.returncode == 0 and stdout == "VALID":
            return True, "Proof cryptographically verified"
        elif result.returncode == 1 and stdout == "INVALID":
            return False, "Proof verification failed (invalid proof)"
        else:
            return False, f"Verifier error: {stderr or stdout or 'Unknown error'}"
            
    except subprocess.TimeoutExpired:
        return False, "Verification timed out"
    except Exception as e:
        return False, f"Verification failed: {str(e)}"


def verify_proof_dict(proof: dict) -> Tuple[bool, str]:
    """
    Verify an STWO proof from a dictionary.
    
    Args:
        proof: Proof dictionary
        
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        proof_json = json.dumps(proof)
        return verify_stwo_proof(proof_json)
    except json.JSONDecodeError as e:
        return False, f"Invalid proof format: {str(e)}"


def is_real_stwo_proof(proof: dict) -> bool:
    """Check if a proof is a real STWO proof (vs the mock version)"""
    return proof.get("version", "").startswith("stwo-real-")


# Legacy/mock verification for backwards compatibility
def verify_mock_proof(proof_json: str) -> Tuple[bool, str]:
    """
    Verify a mock STWO proof (for backwards compatibility).
    This is NOT cryptographically sound - just checks structure.
    """
    try:
        proof = json.loads(proof_json)
        
        # Check basic structure
        if not proof.get("valid", False):
            return False, "Proof marked as invalid"
        
        if "public_inputs" not in proof:
            return False, "Missing public inputs"
        
        if not proof.get("proof_hash"):
            return False, "Missing proof hash"
        
        # Check expiry
        import time
        expires_at = proof.get("public_inputs", {}).get("expires_at")
        if expires_at and time.time() > expires_at:
            return False, "Proof expired"
        
        return True, "Mock proof structure valid (NOT cryptographically verified)"
        
    except json.JSONDecodeError:
        return False, "Invalid JSON"
    except Exception as e:
        return False, f"Verification error: {str(e)}"


def verify_any_proof(proof_json: str) -> Tuple[bool, str]:
    """
    Verify any STWO proof - uses real verifier if available and proof is real,
    falls back to mock verification for legacy proofs.
    """
    try:
        proof = json.loads(proof_json)
    except json.JSONDecodeError:
        return False, "Invalid JSON"
    
    # Check if it's a real STWO proof
    if is_real_stwo_proof(proof):
        if has_real_verifier():
            return verify_stwo_proof(proof_json)
        else:
            return False, "Real STWO proof requires verifier binary (not available)"
    else:
        # Legacy mock proof
        return verify_mock_proof(proof_json)
