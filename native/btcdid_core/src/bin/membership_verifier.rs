// membership_verifier.rs
// CLI tool to verify membership proofs
// Used by the API server on the VPS

use std::io::{self, Read};
use std::process::ExitCode;

use btcdid_core::membership::{verify_membership, MembershipProof};

/// Input JSON format:
/// {
///     "proof": "base64...",
///     "root": "0xabc123...",
///     "binding_hash": "hex32bytes...",
///     "purpose_id": 1
/// }
#[derive(serde::Deserialize)]
struct VerifyRequest {
    proof: String,        // base64-encoded proof
    root: String,         // hex with optional 0x prefix
    binding_hash: String, // hex 32 bytes
    purpose_id: u8,
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
        eprintln!("Error reading stdin: {}", e);
        return ExitCode::from(2);
    }

    let input = input.trim();
    if input.is_empty() {
        eprintln!("Error: Empty input. Provide JSON via stdin.");
        eprintln!("Format: {{\"proof\":\"base64\",\"root\":\"0x...\",\"binding_hash\":\"hex\",\"purpose_id\":1}}");
        return ExitCode::from(2);
    }

    // Parse request
    let req: VerifyRequest = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error parsing JSON: {}", e);
            return ExitCode::from(2);
        }
    };

    // Parse proof from base64
    let proof = match MembershipProof::from_base64(&req.proof) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error decoding proof: {}", e);
            return ExitCode::from(2);
        }
    };

    // Parse root
    let root = match parse_hex_32(&req.root) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error parsing root: {}", e);
            return ExitCode::from(2);
        }
    };

    // Parse binding_hash
    let binding_hash = match parse_hex_32(&req.binding_hash) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error parsing binding_hash: {}", e);
            return ExitCode::from(2);
        }
    };

    // Verify
    match verify_membership(&proof, &root, &binding_hash, req.purpose_id) {
        Ok(true) => {
            println!("VALID");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("INVALID");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("ERROR: {}", e);
            ExitCode::from(2)
        }
    }
}
