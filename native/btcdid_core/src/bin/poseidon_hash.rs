//! Poseidon2-M31 Hash CLI
//!
//! This binary is the SINGLE SOURCE OF TRUTH for Poseidon2 hashing.
//! Python API calls this via subprocess to ensure consistency.
//!
//! Uses Plonky3's verified Poseidon2 implementation with Xoroshiro128Plus(seed=1)
//! round constants, matching their test vectors exactly.
//!
//! Usage:
//!   poseidon_hash pair <left_hex> <right_hex>
//!   poseidon_hash leaf_commit <secret_hex>
//!   poseidon_hash nullifier <secret_hex> <session_id_hex>
//!   poseidon_hash merkle_root <leaf1_hex> <leaf2_hex> ...
//!
//! All inputs are hex-encoded. Outputs are hex-encoded M31 values (4 bytes).

use std::env;
use std::process::exit;

use btcdid_core::membership::poseidon2_m31::{
    LeafSecret, SessionId, Nullifier,
    poseidon2_hash_pair, compute_leaf_commitment, compute_nullifier,
    build_merkle_tree, m31_to_bytes, m31_from_bytes,
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

fn parse_hex_4(s: &str) -> Result<[u8; 4], String> {
    let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() < 4 {
        return Err(format!("Expected at least 4 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes[..4]);
    Ok(arr)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        exit(1);
    }
    
    let command = &args[1];
    
    match command.as_str() {
        "pair" => {
            if args.len() != 4 {
                eprintln!("Usage: poseidon_hash pair <left_hex> <right_hex>");
                eprintln!("  Inputs: 4-byte hex values (M31 elements)");
                exit(1);
            }
            let left_bytes = match parse_hex_4(&args[2]) {
                Ok(v) => v,
                Err(e) => { eprintln!("Error: {}", e); exit(1); }
            };
            let right_bytes = match parse_hex_4(&args[3]) {
                Ok(v) => v,
                Err(e) => { eprintln!("Error: {}", e); exit(1); }
            };
            
            let left = m31_from_bytes(&left_bytes);
            let right = m31_from_bytes(&right_bytes);
            
            let result = poseidon2_hash_pair(left, right);
            println!("{}", hex::encode(m31_to_bytes(result)));
        }
        
        "leaf_commit" => {
            if args.len() != 3 {
                eprintln!("Usage: poseidon_hash leaf_commit <secret_hex>");
                eprintln!("  Input: 32-byte hex secret");
                exit(1);
            }
            let secret_bytes = match parse_hex_32(&args[2]) {
                Ok(v) => v,
                Err(e) => { eprintln!("Error: {}", e); exit(1); }
            };
            
            let secret = LeafSecret::from_bytes(&secret_bytes);
            let result = compute_leaf_commitment(&secret);
            println!("{}", hex::encode(m31_to_bytes(result)));
        }
        
        "nullifier" => {
            if args.len() != 4 {
                eprintln!("Usage: poseidon_hash nullifier <secret_hex> <session_hex>");
                eprintln!("  Inputs: 32-byte hex values");
                eprintln!("  Output: 16-byte hex (4 M31 elements = 124 bits)");
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
            let result = compute_nullifier(&secret, &session);
            // Output 16 bytes (4 M31 elements)
            println!("{}", hex::encode(result.to_bytes()));
        }
        
        "merkle_root" => {
            if args.len() < 3 {
                eprintln!("Usage: poseidon_hash merkle_root <leaf1_hex> [leaf2_hex ...]");
                eprintln!("  Inputs: 4-byte hex M31 values");
                exit(1);
            }
            
            let mut leaves = Vec::new();
            for i in 2..args.len() {
                let leaf_bytes = match parse_hex_4(&args[i]) {
                    Ok(v) => v,
                    Err(e) => { eprintln!("Error parsing leaf {}: {}", i - 1, e); exit(1); }
                };
                leaves.push(m31_from_bytes(&leaf_bytes));
            }
            
            let root = build_merkle_tree(&leaves);
            println!("{}", hex::encode(m31_to_bytes(root)));
        }
        
        "help" | "--help" | "-h" => {
            print_usage();
        }
        
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage();
            exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Poseidon2-M31 Hash CLI (Plonky3 verified parameters)");
    eprintln!();
    eprintln!("Usage: poseidon_hash <command> [args...]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  pair <left_hex> <right_hex>           Hash two M31 values → 4 bytes");
    eprintln!("  leaf_commit <secret_hex>              Compute leaf commitment → 4 bytes");
    eprintln!("  nullifier <secret_hex> <session_hex>  Compute nullifier → 16 bytes");
    eprintln!("  merkle_root <leaf1_hex> ...           Build Merkle tree root → 4 bytes");
    eprintln!();
    eprintln!("Output sizes:");
    eprintln!("  pair, leaf_commit, merkle_root: 4 bytes (1 M31, 31 bits)");
    eprintln!("  nullifier: 16 bytes (4 M31 elements, 124 bits)");
    eprintln!();
    eprintln!("State Layout (WIDTH=16):");
    eprintln!("  Position 0: Domain separator (capacity)");
    eprintln!("  Positions 1-15: Rate elements (inputs + padding)");
    eprintln!("  Single output: Position 1");
    eprintln!("  Nullifier output: Positions 1-4");
    eprintln!();
    eprintln!("Domains:");
    eprintln!("  LEAF: 0x4C454146  NULLIFIER: 0x4E554C4C  MERKLE: 0x4D45524B");
}
