// membership_verifier.rs
// CLI tool to verify membership proofs (v2 - with session_id and nullifier)
// Used by the API server on the VPS

use std::io::{self, Read};
use std::process::ExitCode;

use btcdid_core::membership::{verify_membership, MembershipProof};

/// Input JSON format:
/// {
///     "proof": "base64...",
///     "root": "0xabc123...",
///     "binding_hash": "hex32bytes...",
///     "session_id": "hex32bytes...",
///     "purpose_id": 1,
///     "known_nullifiers": ["hex32bytes...", ...]  // optional
/// }
#[derive(serde::Deserialize)]
struct VerifyRequest {
    proof: String,        // base64-encoded proof
    root: String,         // hex with optional 0x prefix
    binding_hash: String, // hex 32 bytes
    session_id: String,   // hex 32 bytes
    purpose_id: u8,
    #[serde(default)]
    known_nullifiers: Vec<String>, // Optional: already-used nullifiers
}

/// Output JSON format:
/// {
///     "valid": true,
///     "nullifier": "hex32bytes..."  // Present if valid
/// }
#[derive(serde::Serialize)]
struct VerifyResponse {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    nullifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn main() -> ExitCode {
    // Read JSON from stdin
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        let resp = VerifyResponse {
            valid: false,
            nullifier: None,
            error: Some(format!("Error reading stdin: {}", e)),
        };
        println!("{}", serde_json::to_string(&resp).unwrap());
        return ExitCode::from(2);
    }

    let input = input.trim();
    if input.is_empty() {
        let resp = VerifyResponse {
            valid: false,
            nullifier: None,
            error: Some("Empty input. Provide JSON via stdin.".into()),
        };
        println!("{}", serde_json::to_string(&resp).unwrap());
        return ExitCode::from(2);
    }

    // Parse request
    let req: VerifyRequest = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(e) => {
            let resp = VerifyResponse {
                valid: false,
                nullifier: None,
                error: Some(format!("Error parsing JSON: {}", e)),
            };
            println!("{}", serde_json::to_string(&resp).unwrap());
            return ExitCode::from(2);
        }
    };

    // Parse proof from base64
    let proof = match MembershipProof::from_base64(&req.proof) {
        Ok(p) => p,
        Err(e) => {
            let resp = VerifyResponse {
                valid: false,
                nullifier: None,
                error: Some(format!("Error decoding proof: {}", e)),
            };
            println!("{}", serde_json::to_string(&resp).unwrap());
            return ExitCode::from(2);
        }
    };

    // Parse root
    let root = match parse_hex_32(&req.root) {
        Ok(r) => r,
        Err(e) => {
            let resp = VerifyResponse {
                valid: false,
                nullifier: None,
                error: Some(format!("Error parsing root: {}", e)),
            };
            println!("{}", serde_json::to_string(&resp).unwrap());
            return ExitCode::from(2);
        }
    };

    // Parse binding_hash
    let binding_hash = match parse_hex_32(&req.binding_hash) {
        Ok(b) => b,
        Err(e) => {
            let resp = VerifyResponse {
                valid: false,
                nullifier: None,
                error: Some(format!("Error parsing binding_hash: {}", e)),
            };
            println!("{}", serde_json::to_string(&resp).unwrap());
            return ExitCode::from(2);
        }
    };

    // Parse session_id
    let session_id = match parse_hex_32(&req.session_id) {
        Ok(s) => s,
        Err(e) => {
            let resp = VerifyResponse {
                valid: false,
                nullifier: None,
                error: Some(format!("Error parsing session_id: {}", e)),
            };
            println!("{}", serde_json::to_string(&resp).unwrap());
            return ExitCode::from(2);
        }
    };

    // Parse known nullifiers (optional)
    let known_nullifiers: Option<std::collections::HashSet<[u8; 32]>> = if req.known_nullifiers.is_empty() {
        None
    } else {
        let mut set = std::collections::HashSet::new();
        for hex_str in &req.known_nullifiers {
            match parse_hex_32(hex_str) {
                Ok(n) => { set.insert(n); }
                Err(e) => {
                    let resp = VerifyResponse {
                        valid: false,
                        nullifier: None,
                        error: Some(format!("Error parsing nullifier: {}", e)),
                    };
                    println!("{}", serde_json::to_string(&resp).unwrap());
                    return ExitCode::from(2);
                }
            }
        }
        Some(set)
    };

    // Extract nullifier from proof (for response)
    let nullifier_hex = proof.get_nullifier().map(|n| format!("0x{}", hex::encode(n)));

    // Verify
    match verify_membership(
        &proof,
        &root,
        &binding_hash,
        &session_id,
        req.purpose_id,
        known_nullifiers.as_ref(),
    ) {
        Ok(true) => {
            let resp = VerifyResponse {
                valid: true,
                nullifier: nullifier_hex,
                error: None,
            };
            println!("{}", serde_json::to_string(&resp).unwrap());
            ExitCode::SUCCESS
        }
        Ok(false) => {
            let resp = VerifyResponse {
                valid: false,
                nullifier: nullifier_hex,
                error: None,
            };
            println!("{}", serde_json::to_string(&resp).unwrap());
            ExitCode::from(1)
        }
        Err(e) => {
            let resp = VerifyResponse {
                valid: false,
                nullifier: None,
                error: Some(e),
            };
            println!("{}", serde_json::to_string(&resp).unwrap());
            ExitCode::from(2)
        }
    }
}
