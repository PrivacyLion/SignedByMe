//! Poseidon2-M31 Hash CLI
//!
//! This binary is the SINGLE SOURCE OF TRUTH for Poseidon2 hashing.
//! Python API calls this via subprocess to ensure consistency.
//!
//! Usage:
//!   poseidon_hash pair <left_hex> <right_hex>
//!   poseidon_hash leaf_commit <secret_hex>
//!   poseidon_hash nullifier <secret_hex> <session_id_hex>
//!   poseidon_hash merkle_root <leaf1_hex> <leaf2_hex> ...
//!
//! All inputs are hex-encoded 32-byte values.
//! Output is hex-encoded result.

use std::env;
use std::process::exit;

// Import from the library
use btcdid_core::membership::poseidon2_m31::{
    M31, Poseidon2Params, LeafSecret, SessionId,
    poseidon2_hash_pair, compute_leaf_commitment, compute_nullifier,
    build_merkle_tree,
};

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn m31_to_hex(val: M31) -> String {
    // Return as 4-byte big-endian hex
    hex::encode(val.to_bytes_be())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: poseidon_hash <command> [args...]");
        eprintln!("Commands:");
        eprintln!("  pair <left_hex> <right_hex>           - Hash two values");
        eprintln!("  leaf_commit <secret_hex>              - Compute leaf commitment");
        eprintln!("  nullifier <secret_hex> <session_hex>  - Compute nullifier");
        eprintln!("  merkle_root <leaf1_hex> ...           - Build Merkle tree");
        exit(1);
    }
    
    let params = Poseidon2Params::new();
    let command = &args[1];
    
    match command.as_str() {
        "pair" => {
            if args.len() != 4 {
                eprintln!("Usage: poseidon_hash pair <left_hex> <right_hex>");
                exit(1);
            }
            let left = match parse_hex_32(&args[2]) {
                Ok(v) => v,
                Err(e) => { eprintln!("Error: {}", e); exit(1); }
            };
            let right = match parse_hex_32(&args[3]) {
                Ok(v) => v,
                Err(e) => { eprintln!("Error: {}", e); exit(1); }
            };
            
            // Convert to M31 elements
            let left_m31 = M31::from_bytes_be(&left[..4]);
            let right_m31 = M31::from_bytes_be(&right[..4]);
            
            let result = poseidon2_hash_pair(&params, left_m31, right_m31);
            println!("{}", m31_to_hex(result));
        }
        
        "leaf_commit" => {
            if args.len() != 3 {
                eprintln!("Usage: poseidon_hash leaf_commit <secret_hex>");
                exit(1);
            }
            let secret_bytes = match parse_hex_32(&args[2]) {
                Ok(v) => v,
                Err(e) => { eprintln!("Error: {}", e); exit(1); }
            };
            
            let secret = LeafSecret::from_bytes(&secret_bytes);
            let result = compute_leaf_commitment(&params, &secret);
            println!("{}", m31_to_hex(result));
        }
        
        "nullifier" => {
            if args.len() != 4 {
                eprintln!("Usage: poseidon_hash nullifier <secret_hex> <session_hex>");
                exit(1);
            }
            let secret_bytes = match parse_hex_32(&args[2]) {
                Ok(v) => v,
                Err(e) => { eprintln!("Error: {}", e); exit(1); }
            };
            let session_bytes = match parse_hex_32(&args[3]) {
                Ok(v) => v,
                Err(e) => { eprintln!("Error: {}", e); exit(1); }
            };
            
            let secret = LeafSecret::from_bytes(&secret_bytes);
            let session = SessionId::from_bytes(&session_bytes);
            let result = compute_nullifier(&params, &secret, &session);
            println!("{}", m31_to_hex(result));
        }
        
        "merkle_root" => {
            if args.len() < 3 {
                eprintln!("Usage: poseidon_hash merkle_root <leaf1_hex> [leaf2_hex ...]");
                exit(1);
            }
            
            let mut leaves: Vec<M31> = Vec::new();
            for i in 2..args.len() {
                let leaf_bytes = match parse_hex_32(&args[i]) {
                    Ok(v) => v,
                    Err(e) => { eprintln!("Error parsing leaf {}: {}", i - 1, e); exit(1); }
                };
                // Use first 4 bytes as M31
                leaves.push(M31::from_bytes_be(&leaf_bytes[..4]));
            }
            
            let root = build_merkle_tree(&params, &leaves);
            println!("{}", m31_to_hex(root));
        }
        
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Use: pair, leaf_commit, nullifier, merkle_root");
            exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pair_deterministic() {
        let params = Poseidon2Params::new();
        let a = M31::new(123);
        let b = M31::new(456);
        
        let h1 = poseidon2_hash_pair(&params, a, b);
        let h2 = poseidon2_hash_pair(&params, a, b);
        
        assert_eq!(h1, h2);
    }
}
