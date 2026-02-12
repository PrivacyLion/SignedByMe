//! sbm-tree: Enterprise Merkle tree builder for SignedByMe
//!
//! Builds depth-20 Poseidon Merkle trees from commitment files.
//! Outputs root.json + witnesses/*.json for enterprise membership proofs.
//!
//! Usage:
//!   sbm-tree build --client-id acme_corp --purpose issuer_batch \
//!       --commitments commitments.csv --output ./output
//!
//!   sbm-tree verify --witness witness.json --commitment 0x... --root 0x...

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

// Use btcdid_core's membership module
use btcdid_core::membership::poseidon::FieldElement;
use btcdid_core::membership::merkle::{MerkleTree, MerklePath, verify_merkle_path};

const TREE_DEPTH: usize = 20;
const HASH_ALG: &str = "poseidon";
const WITNESS_VERSION: u32 = 1;

#[derive(Parser)]
#[command(name = "sbm-tree")]
#[command(about = "Enterprise Merkle tree builder for SignedByMe")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a Merkle tree from commitments
    Build {
        /// Enterprise client ID
        #[arg(long)]
        client_id: String,
        
        /// Tree purpose (issuer_batch, allowlist, revocation)
        #[arg(long)]
        purpose: String,
        
        /// Path to commitments file (one hex per line)
        #[arg(long)]
        commitments: PathBuf,
        
        /// Output directory
        #[arg(long)]
        output: PathBuf,
        
        /// Tree depth (default: 20)
        #[arg(long, default_value_t = TREE_DEPTH)]
        depth: usize,
    },
    
    /// Verify a witness against a commitment
    Verify {
        /// Path to witness JSON
        #[arg(long)]
        witness: PathBuf,
        
        /// Leaf commitment (hex)
        #[arg(long)]
        commitment: String,
        
        /// Expected root (hex, optional)
        #[arg(long)]
        root: Option<String>,
    },
}

#[derive(Serialize)]
struct RootJson {
    root_id: String,
    client_id: String,
    purpose: String,
    purpose_id: u8,
    root: String,
    hash_alg: String,
    depth: usize,
    not_before: u64,
    expires_at: u64,
    description: String,
    member_count: usize,
}

#[derive(Serialize, Deserialize)]
struct WitnessJson {
    version: u32,
    client_id: String,
    root_id: String,
    purpose_id: u8,
    hash_alg: String,
    depth: usize,
    not_before: u64,
    expires_at: u64,
    leaf_index: usize,
    siblings: Vec<String>,
    path_bits: Vec<u8>,
}

#[derive(Serialize)]
struct MappingEntry {
    leaf_index: usize,
    commitment: String,
    witness_file: String,
}

fn purpose_to_id(purpose: &str) -> u8 {
    match purpose {
        "none" => 0,
        "allowlist" => 1,
        "issuer_batch" => 2,
        "revocation" => 3,
        _ => 0,
    }
}

fn parse_hex_fe(s: &str) -> Result<FieldElement, String> {
    let s = s.trim();
    let hex = if s.starts_with("0x") || s.starts_with("0X") {
        &s[2..]
    } else {
        s
    };
    
    // Pad to 64 chars
    let padded = format!("{:0>64}", hex);
    let bytes = hex::decode(&padded).map_err(|e| format!("Invalid hex: {}", e))?;
    
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(FieldElement::from_bytes_be(&arr))
}

fn fe_to_hex(fe: &FieldElement) -> String {
    format!("0x{}", hex::encode(fe.to_bytes_be()))
}

fn load_commitments(path: &PathBuf) -> Result<Vec<FieldElement>, String> {
    let file = File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
    let reader = BufReader::new(file);
    
    let mut commitments = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Read error: {}", e))?;
        let line = line.trim();
        
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        match parse_hex_fe(line) {
            Ok(fe) => commitments.push(fe),
            Err(e) => eprintln!("Warning: Line {}: {}", line_num + 1, e),
        }
    }
    
    Ok(commitments)
}

fn build_tree(
    client_id: String,
    purpose: String,
    commitments_path: PathBuf,
    output_path: PathBuf,
    depth: usize,
) -> Result<(), String> {
    if depth != TREE_DEPTH {
        eprintln!("WARNING: Using depth={} (production requires depth={})", depth, TREE_DEPTH);
        eprintln!("         Roots with depth!={} will be REJECTED by the API", TREE_DEPTH);
    }
    
    // Load commitments
    println!("Loading commitments from {:?}...", commitments_path);
    let commitments = load_commitments(&commitments_path)?;
    
    if commitments.is_empty() {
        return Err("No valid commitments found".into());
    }
    
    println!("Loaded {} commitments", commitments.len());
    
    // Check size limit
    let max_leaves = 1usize << depth;
    if commitments.len() > max_leaves {
        return Err(format!("Too many commitments: {} > {} (2^{})", 
            commitments.len(), max_leaves, depth));
    }
    
    // Build tree
    println!("Building depth-{} Merkle tree (padding with zeros)...", depth);
    println!("This may take a while for depth=20...");
    
    let tree = MerkleTree::with_depth(commitments.clone(), depth);
    println!("Root: {}", fe_to_hex(&tree.root));
    
    // Create output directories
    fs::create_dir_all(&output_path).map_err(|e| format!("Cannot create output dir: {}", e))?;
    let witnesses_dir = output_path.join("witnesses");
    fs::create_dir_all(&witnesses_dir).map_err(|e| format!("Cannot create witnesses dir: {}", e))?;
    
    // Generate root.json
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let root_id = format!("{}-{}-{}", client_id, purpose, now);
    let purpose_id = purpose_to_id(&purpose);
    
    let root_json = RootJson {
        root_id: root_id.clone(),
        client_id: client_id.clone(),
        purpose: purpose.clone(),
        purpose_id,
        root: fe_to_hex(&tree.root),
        hash_alg: HASH_ALG.into(),
        depth,
        not_before: now,
        expires_at: now + 365 * 86400, // 1 year
        description: format!("{} tree with {} members", purpose, commitments.len()),
        member_count: commitments.len(),
    };
    
    let root_path = output_path.join("root.json");
    let root_file = File::create(&root_path).map_err(|e| format!("Cannot create root.json: {}", e))?;
    serde_json::to_writer_pretty(root_file, &root_json)
        .map_err(|e| format!("Cannot write root.json: {}", e))?;
    println!("Wrote {:?}", root_path);
    
    // Generate witnesses + mapping
    println!("Generating {} witnesses...", commitments.len());
    let mut mapping = Vec::new();
    
    for (i, commitment) in commitments.iter().enumerate() {
        let path = tree.get_path(i);
        
        // Verify path is correct
        if !verify_merkle_path(commitment, &path, &tree.root) {
            return Err(format!("Path verification failed for leaf {}!", i));
        }
        
        let witness = WitnessJson {
            version: WITNESS_VERSION,
            client_id: client_id.clone(),
            root_id: root_id.clone(),
            purpose_id,
            hash_alg: HASH_ALG.into(),
            depth,
            not_before: root_json.not_before,
            expires_at: root_json.expires_at,
            leaf_index: i,
            siblings: path.siblings.iter().map(|s| fe_to_hex(&s.hash)).collect(),
            path_bits: path.siblings.iter().map(|s| if s.is_right { 1 } else { 0 }).collect(),
        };
        
        let witness_filename = format!("witness_{:06}.json", i);
        let witness_path = witnesses_dir.join(&witness_filename);
        let witness_file = File::create(&witness_path)
            .map_err(|e| format!("Cannot create witness: {}", e))?;
        serde_json::to_writer_pretty(witness_file, &witness)
            .map_err(|e| format!("Cannot write witness: {}", e))?;
        
        mapping.push(MappingEntry {
            leaf_index: i,
            commitment: fe_to_hex(commitment),
            witness_file: witness_filename,
        });
        
        if (i + 1) % 1000 == 0 {
            println!("  Generated {}/{} witnesses", i + 1, commitments.len());
        }
    }
    
    println!("Wrote {} witnesses to {:?}", commitments.len(), witnesses_dir);
    
    // Write mapping file
    let mapping_path = output_path.join("mapping.json");
    let mapping_file = File::create(&mapping_path)
        .map_err(|e| format!("Cannot create mapping.json: {}", e))?;
    serde_json::to_writer_pretty(mapping_file, &mapping)
        .map_err(|e| format!("Cannot write mapping.json: {}", e))?;
    println!("Wrote {:?}", mapping_path);
    
    // Summary
    println!("\n=== Summary ===");
    println!("Root ID: {}", root_id);
    println!("Root: {}", fe_to_hex(&tree.root));
    println!("Members: {}", commitments.len());
    println!("Depth: {}", depth);
    println!("\nTo publish root:");
    println!("  curl -X POST https://api.signedby.me/v1/roots \\");
    println!("    -H 'X-API-Key: YOUR_API_KEY' \\");
    println!("    -H 'Content-Type: application/json' \\");
    println!("    -d @{:?}", root_path);
    
    Ok(())
}

fn verify_witness(
    witness_path: PathBuf,
    commitment_hex: String,
    expected_root: Option<String>,
) -> Result<(), String> {
    // Load witness
    let file = File::open(&witness_path)
        .map_err(|e| format!("Cannot open witness: {}", e))?;
    let witness: WitnessJson = serde_json::from_reader(file)
        .map_err(|e| format!("Cannot parse witness: {}", e))?;
    
    // Parse commitment
    let commitment = parse_hex_fe(&commitment_hex)?;
    
    // Reconstruct path
    let mut siblings = Vec::new();
    for (sib_hex, &is_right) in witness.siblings.iter().zip(witness.path_bits.iter()) {
        siblings.push(btcdid_core::membership::merkle::PathSibling {
            hash: parse_hex_fe(sib_hex)?,
            is_right: is_right == 1,
        });
    }
    let path = MerklePath { siblings };
    
    // Compute root
    let computed_root = path.compute_root(&commitment);
    
    println!("Commitment: {}", commitment_hex);
    println!("Computed root: {}", fe_to_hex(&computed_root));
    
    if let Some(expected) = expected_root {
        let expected_fe = parse_hex_fe(&expected)?;
        if computed_root == expected_fe {
            println!("✓ Verification PASSED");
            Ok(())
        } else {
            println!("✗ Verification FAILED");
            println!("  Expected: {}", expected);
            Err("Root mismatch".into())
        }
    } else {
        println!("(No expected root provided, showing computed value only)");
        Ok(())
    }
}

fn main() {
    let cli = Cli::parse();
    
    let result = match cli.command {
        Commands::Build { client_id, purpose, commitments, output, depth } => {
            build_tree(client_id, purpose, commitments, output, depth)
        }
        Commands::Verify { witness, commitment, root } => {
            verify_witness(witness, commitment, root)
        }
    };
    
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
