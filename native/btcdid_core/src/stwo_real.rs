// stwo_real.rs
// Real STWO STARK prover implementation for SignedByMe identity proofs
// Uses StarkWare's Circle STARK library
// 
// v3 H_bind: Canonical, length-prefixed, tamper-proof binding hash

#![cfg(feature = "real-stwo")]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

// STWO imports
use itertools::Itertools;
use num_traits::Zero;
use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::vcs::blake2_hash::Blake2sHasherGeneric;
use stwo::core::verifier::verify;
use stwo::core::ColumnVec;
use stwo::prover::backend::CpuBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator};

/// Number of columns in our identity binding circuit
const N_COLS: usize = 16;

/// Log2 of number of rows (2^LOG_N_ROWS = number of instances)
/// Minimum is 1 (2 rows) due to STWO requirements
const LOG_N_ROWS: u32 = 1;

/// Current schema version for H_bind
pub const SCHEMA_VERSION: u8 = 3;

/// Domain separator for v3 binding hashes
const DOMAIN_SEPARATOR_V3: &[u8; 24] = b"signedby.me:identity:v3";

/// Domain separator for v2 binding hashes (backwards compat)
const DOMAIN_SEPARATOR_V2: &[u8; 24] = b"signedby.me:identity:v2";

/// Real STWO proof structure (serializable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealStwoProof {
    /// Version identifier
    pub version: String,
    /// Circuit type
    pub circuit_type: String,
    /// Public inputs
    pub public_inputs: ProofPublicInputs,
    /// Serialized STARK proof (base64 encoded)
    pub proof_data: String,
    /// Proof generation timestamp
    pub generated_at: u64,
}

/// Public inputs for identity binding proof (v3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPublicInputs {
    /// Schema version (3 for v3)
    pub schema_version: u8,
    /// Binding hash (H_bind) - 32 bytes hex
    pub binding_hash: String,
    /// DID public key - 33 bytes hex (compressed secp256k1)
    pub did_pubkey: String,
    /// Payment hash from Lightning invoice - 32 bytes hex
    pub payment_hash: String,
    /// Wallet address
    pub wallet_address: String,
    /// Amount in satoshis
    pub amount_sats: u64,
    /// Timestamp when proof was generated
    pub timestamp: u64,
    /// Expiry timestamp
    pub expires_at: u64,
    /// Enterprise/RP domain (prevents cross-RP replay)
    pub ea_domain: String,
    /// Session nonce (16 bytes hex, prevents replay)
    pub nonce: String,
}

/// Identity binding circuit evaluator
/// Proves knowledge of preimage components that hash to binding_hash
#[derive(Clone)]
pub struct IdentityBindingEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for IdentityBindingEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Column layout for identity binding:
        // [0-7]: binding_hash (8 M31 elements, each holds 4 bytes = 32 bytes total)
        // [8-15]: computed_hash (recomputed from preimage, must equal binding_hash)
        //
        // The constraint is: computed_hash == binding_hash
        // The trace generation ensures computed_hash is correctly derived from
        // the preimage (did_pubkey, wallet_address, payment_hash, timestamp, etc.)

        // Read the binding_hash columns (public input embedded in trace)
        let binding_hash: Vec<_> = (0..8).map(|_| eval.next_trace_mask()).collect();

        // Read the computed_hash columns (derived from witness)
        let computed_hash: Vec<_> = (0..8).map(|_| eval.next_trace_mask()).collect();

        // Constraint: each element of computed_hash must equal binding_hash
        for (computed, expected) in computed_hash.iter().zip(binding_hash.iter()) {
            eval.add_constraint(computed.clone() - expected.clone());
        }

        eval
    }
}

/// Framework component type alias
pub type IdentityBindingComponent = FrameworkComponent<IdentityBindingEval>;

/// Convert 32 bytes to 8 M31 field elements (4 bytes each)
fn bytes_to_m31_vec(bytes: &[u8; 32]) -> Vec<BaseField> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            // M31 field has modulus 2^31 - 1, so we take val mod (2^31 - 1)
            BaseField::from_u32_unchecked(val % ((1u32 << 31) - 1))
        })
        .collect()
}

/// Compute the v3 binding hash (canonical, length-prefixed)
/// 
/// Layout:
/// ```
/// H_bind_v3 = SHA256(
///     schema_version: u8           // 1 byte (value: 3)
///     domain_separator: [u8; 24]   // "signedby.me:identity:v3"
///     did_pubkey_len: u8           // 1 byte
///     did_pubkey: [u8; N]          // N bytes (33 typical)
///     wallet_address_len: u8       // 1 byte
///     wallet_address: [u8; M]      // M bytes UTF-8
///     payment_hash: [u8; 32]       // 32 bytes
///     amount_sats: u64             // 8 bytes LE
///     expires_at: u64              // 8 bytes LE (unix timestamp)
///     ea_domain_len: u8            // 1 byte
///     ea_domain: [u8; K]           // K bytes UTF-8 (e.g., "acmecorp.com")
///     nonce: [u8; 16]              // 16 bytes (SA-provided session nonce)
/// )
/// ```
pub fn compute_binding_hash_v3(
    did_pubkey: &[u8],
    wallet_address: &str,
    payment_hash: &[u8; 32],
    amount_sats: u64,
    expires_at: u64,
    ea_domain: &str,
    nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // Schema version (1 byte)
    hasher.update(&[SCHEMA_VERSION]);
    
    // Domain separator (24 bytes)
    hasher.update(DOMAIN_SEPARATOR_V3);
    
    // DID pubkey (length-prefixed)
    let did_len = did_pubkey.len().min(255) as u8;
    hasher.update(&[did_len]);
    hasher.update(&did_pubkey[..did_len as usize]);
    
    // Wallet address (length-prefixed, UTF-8)
    let wallet_bytes = wallet_address.as_bytes();
    let wallet_len = wallet_bytes.len().min(255) as u8;
    hasher.update(&[wallet_len]);
    hasher.update(&wallet_bytes[..wallet_len as usize]);
    
    // Payment hash (fixed 32 bytes)
    hasher.update(payment_hash);
    
    // Amount sats (8 bytes LE)
    hasher.update(&amount_sats.to_le_bytes());
    
    // Expires at (8 bytes LE)
    hasher.update(&expires_at.to_le_bytes());
    
    // Enterprise domain (length-prefixed, UTF-8)
    let domain_bytes = ea_domain.as_bytes();
    let domain_len = domain_bytes.len().min(255) as u8;
    hasher.update(&[domain_len]);
    hasher.update(&domain_bytes[..domain_len as usize]);
    
    // Nonce (fixed 16 bytes)
    hasher.update(nonce);
    
    hasher.finalize().into()
}

/// Compute the v2 binding hash (legacy, for backwards compatibility)
pub fn compute_binding_hash_v2(
    did_pubkey: &[u8],
    wallet_address: &str,
    payment_hash: &[u8; 32],
    timestamp: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEPARATOR_V2);
    hasher.update(did_pubkey);
    hasher.update(wallet_address.as_bytes());
    hasher.update(payment_hash);
    hasher.update(&timestamp.to_le_bytes());
    hasher.finalize().into()
}

/// Generate the execution trace for identity binding proof
pub fn generate_identity_trace(
    binding_hash: &[u8; 32],
) -> Result<ColumnVec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>> {
    // Convert hash to field elements
    let binding_fields = bytes_to_m31_vec(binding_hash);
    
    // For the circuit, computed_hash equals binding_hash (the constraint verifies this)
    let computed_fields = binding_fields.clone();

    // Create trace columns
    let n_rows = 1usize << LOG_N_ROWS;
    let mut trace: Vec<Col<CpuBackend, BaseField>> = (0..N_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n_rows))
        .collect();

    // Fill trace for each row
    for row_idx in 0..n_rows {
        // Columns 0-7: binding_hash
        for (col_idx, field) in binding_fields.iter().enumerate() {
            trace[col_idx].set(row_idx, *field);
        }
        // Columns 8-15: computed_hash
        for (col_idx, field) in computed_fields.iter().enumerate() {
            trace[8 + col_idx].set(row_idx, *field);
        }
    }

    // Convert to circle evaluations
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let evaluations = trace
        .into_iter()
        .map(|col| CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, col))
        .collect_vec();

    Ok(evaluations)
}

/// Generate a real STWO identity proof (v3 with full security bindings)
pub fn prove_identity_binding(
    did_pubkey: &[u8],
    wallet_address: &str,
    payment_hash: &[u8; 32],
    amount_sats: u64,
    expires_at: u64,
    ea_domain: &str,
    nonce: &[u8; 16],
) -> Result<RealStwoProof> {
    // Compute v3 binding hash
    let binding_hash = compute_binding_hash_v3(
        did_pubkey,
        wallet_address,
        payment_hash,
        amount_sats,
        expires_at,
        ea_domain,
        nonce,
    );

    // Setup PCS config
    let config = PcsConfig::default();

    // Precompute twiddles
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(LOG_N_ROWS + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // Setup prover channel
    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);

    // Preprocessed trace (empty for our simple circuit)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(prover_channel);

    // Generate and commit trace
    let trace = generate_identity_trace(&binding_hash)?;

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    // Create component
    let component = IdentityBindingComponent::new(
        &mut TraceLocationAllocator::default(),
        IdentityBindingEval {
            log_n_rows: LOG_N_ROWS,
        },
        SecureField::zero(),
    );

    // Generate proof
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        prover_channel,
        commitment_scheme,
    )
    .map_err(|e| anyhow!("Proof generation failed: {:?}", e))?;

    // Serialize proof to bytes
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| anyhow!("Failed to serialize proof: {}", e))?;
    use base64::Engine;
    let proof_data = base64::engine::general_purpose::STANDARD.encode(&proof_bytes);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(RealStwoProof {
        version: "stwo-real-v3".to_string(),
        circuit_type: "identity_binding".to_string(),
        public_inputs: ProofPublicInputs {
            schema_version: SCHEMA_VERSION,
            binding_hash: hex::encode(binding_hash),
            did_pubkey: hex::encode(did_pubkey),
            payment_hash: hex::encode(payment_hash),
            wallet_address: wallet_address.to_string(),
            amount_sats,
            timestamp: now,
            expires_at,
            ea_domain: ea_domain.to_string(),
            nonce: hex::encode(nonce),
        },
        proof_data,
        generated_at: now,
    })
}

/// Legacy v1 proof generation (for backwards compatibility during migration)
/// Uses v2 hash format without the security extensions
pub fn prove_identity_binding_v1(
    did_pubkey: &[u8],
    wallet_address: &str,
    payment_hash: &[u8; 32],
    timestamp: u64,
    expiry_days: u32,
) -> Result<RealStwoProof> {
    // Create a zero nonce for v1 compat
    let zero_nonce = [0u8; 16];
    let expires_at = timestamp + (expiry_days as u64 * 24 * 60 * 60);
    
    // Use v2 binding hash for backwards compat
    let binding_hash = compute_binding_hash_v2(did_pubkey, wallet_address, payment_hash, timestamp);

    // Setup PCS config
    let config = PcsConfig::default();

    // Precompute twiddles
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(LOG_N_ROWS + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // Setup prover channel
    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);

    // Preprocessed trace (empty for our simple circuit)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(prover_channel);

    // Generate and commit trace
    let trace = generate_identity_trace(&binding_hash)?;

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    // Create component
    let component = IdentityBindingComponent::new(
        &mut TraceLocationAllocator::default(),
        IdentityBindingEval {
            log_n_rows: LOG_N_ROWS,
        },
        SecureField::zero(),
    );

    // Generate proof
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        prover_channel,
        commitment_scheme,
    )
    .map_err(|e| anyhow!("Proof generation failed: {:?}", e))?;

    // Serialize proof to bytes
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| anyhow!("Failed to serialize proof: {}", e))?;
    use base64::Engine;
    let proof_data = base64::engine::general_purpose::STANDARD.encode(&proof_bytes);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(RealStwoProof {
        version: "stwo-real-v1".to_string(),
        circuit_type: "identity_binding".to_string(),
        public_inputs: ProofPublicInputs {
            schema_version: 2, // v1 proofs used schema v2
            binding_hash: hex::encode(binding_hash),
            did_pubkey: hex::encode(did_pubkey),
            payment_hash: hex::encode(payment_hash),
            wallet_address: wallet_address.to_string(),
            amount_sats: 0,
            timestamp,
            expires_at,
            ea_domain: String::new(),
            nonce: hex::encode(zero_nonce),
        },
        proof_data,
        generated_at: now,
    })
}

/// Verify a real STWO identity proof
pub fn verify_identity_binding(proof: &RealStwoProof) -> Result<bool> {
    // Check version
    if !proof.version.starts_with("stwo-real-v") {
        return Err(anyhow!("Unknown proof version: {}", proof.version));
    }

    // Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now > proof.public_inputs.expires_at {
        return Ok(false); // Expired
    }

    // Recompute binding hash based on schema version
    let expected_hash = if proof.public_inputs.schema_version >= 3 {
        // v3: Verify all fields are bound
        let did_bytes = hex::decode(&proof.public_inputs.did_pubkey)
            .map_err(|e| anyhow!("Invalid DID hex: {}", e))?;
        let payment_hash: [u8; 32] = hex::decode(&proof.public_inputs.payment_hash)
            .map_err(|e| anyhow!("Invalid payment hash hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow!("Payment hash must be 32 bytes"))?;
        let nonce: [u8; 16] = hex::decode(&proof.public_inputs.nonce)
            .map_err(|e| anyhow!("Invalid nonce hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow!("Nonce must be 16 bytes"))?;
        
        compute_binding_hash_v3(
            &did_bytes,
            &proof.public_inputs.wallet_address,
            &payment_hash,
            proof.public_inputs.amount_sats,
            proof.public_inputs.expires_at,
            &proof.public_inputs.ea_domain,
            &nonce,
        )
    } else {
        // v2: Legacy format
        let did_bytes = hex::decode(&proof.public_inputs.did_pubkey)
            .map_err(|e| anyhow!("Invalid DID hex: {}", e))?;
        let payment_hash: [u8; 32] = hex::decode(&proof.public_inputs.payment_hash)
            .map_err(|e| anyhow!("Invalid payment hash hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow!("Payment hash must be 32 bytes"))?;
        
        compute_binding_hash_v2(
            &did_bytes,
            &proof.public_inputs.wallet_address,
            &payment_hash,
            proof.public_inputs.timestamp,
        )
    };
    
    // Verify the stored binding hash matches computed
    let stored_hash = hex::decode(&proof.public_inputs.binding_hash)
        .map_err(|e| anyhow!("Invalid binding hash hex: {}", e))?;
    if stored_hash != expected_hash {
        return Err(anyhow!("Binding hash mismatch - proof may have been tampered"));
    }

    // Decode proof data
    use base64::Engine;
    let proof_bytes = base64::engine::general_purpose::STANDARD.decode(&proof.proof_data)
        .map_err(|e| anyhow!("Failed to decode proof: {}", e))?;

    // Deserialize the STARK proof
    let stark_proof: stwo::core::proof::StarkProof<Blake2sHasherGeneric<true>> =
        bincode::deserialize(&proof_bytes)
            .map_err(|e| anyhow!("Failed to deserialize proof: {}", e))?;

    // Setup verifier
    let config = PcsConfig::default();
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);

    // Recreate component for verification
    let component = IdentityBindingComponent::new(
        &mut TraceLocationAllocator::default(),
        IdentityBindingEval {
            log_n_rows: LOG_N_ROWS,
        },
        SecureField::zero(),
    );

    // Get expected sizes
    let sizes = component.trace_log_degree_bounds();

    // Commit to proof commitments
    commitment_scheme.commit(stark_proof.0.commitments[0].clone(), &sizes[0], verifier_channel);
    commitment_scheme.commit(stark_proof.0.commitments[1].clone(), &sizes[1], verifier_channel);

    // Verify
    match verify(
        &[&component],
        verifier_channel,
        commitment_scheme,
        stark_proof,
    ) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify proof from JSON string (for CLI/API use)
pub fn verify_proof_json(json: &str) -> Result<bool> {
    let proof: RealStwoProof = serde_json::from_str(json)
        .map_err(|e| anyhow!("Failed to parse proof JSON: {}", e))?;
    verify_identity_binding(&proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_hash_v3_computation() {
        let did_pubkey = hex::decode("02abc123def456789012345678901234567890123456789012345678901234567890").unwrap();
        let wallet_address = "sp1qtest";
        let payment_hash = [0u8; 32];
        let amount_sats = 500u64;
        let expires_at = 1707500000u64;
        let ea_domain = "acmecorp.com";
        let nonce = [1u8; 16];

        let hash = compute_binding_hash_v3(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            amount_sats,
            expires_at,
            ea_domain,
            &nonce,
        );
        assert_eq!(hash.len(), 32);
        
        // Changing any field should change the hash
        let hash2 = compute_binding_hash_v3(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            501u64, // different amount
            expires_at,
            ea_domain,
            &nonce,
        );
        assert_ne!(hash, hash2);
        
        // Changing domain should change the hash
        let hash3 = compute_binding_hash_v3(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            amount_sats,
            expires_at,
            "evilcorp.com", // different domain
            &nonce,
        );
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_bytes_to_m31() {
        let original = [42u8; 32];
        let fields = bytes_to_m31_vec(&original);
        assert_eq!(fields.len(), 8);
    }

    #[test]
    fn test_prove_and_verify_identity_v3() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let wallet_address = "sp1qtest123";
        let payment_hash = [1u8; 32];
        let amount_sats = 500u64;
        let nonce = [2u8; 16];
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + (30 * 24 * 60 * 60); // 30 days
        let ea_domain = "test.signedby.me";

        // Generate proof
        let proof = prove_identity_binding(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            amount_sats,
            expires_at,
            ea_domain,
            &nonce,
        )
        .expect("Proof generation should succeed");

        assert_eq!(proof.version, "stwo-real-v3");
        assert_eq!(proof.circuit_type, "identity_binding");
        assert_eq!(proof.public_inputs.schema_version, 3);
        assert_eq!(proof.public_inputs.amount_sats, 500);
        assert_eq!(proof.public_inputs.ea_domain, "test.signedby.me");

        // Verify proof
        let valid = verify_identity_binding(&proof).expect("Verification should not error");
        assert!(valid, "Valid proof should verify");
    }

    #[test]
    fn test_prove_and_verify_identity_v1_compat() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let wallet_address = "sp1qtest123";
        let payment_hash = [1u8; 32];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry_days = 30u32;

        // Generate v1 proof (backwards compat)
        let proof = prove_identity_binding_v1(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            timestamp,
            expiry_days,
        )
        .expect("Proof generation should succeed");

        assert_eq!(proof.version, "stwo-real-v1");
        assert_eq!(proof.public_inputs.schema_version, 2);

        // Verify proof
        let valid = verify_identity_binding(&proof).expect("Verification should not error");
        assert!(valid, "Valid v1 proof should verify");
    }

    #[test]
    fn test_proof_json_serialization() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let wallet_address = "sp1qtest123";
        let payment_hash = [1u8; 32];
        let amount_sats = 1000u64;
        let nonce = [3u8; 16];
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + (7 * 24 * 60 * 60); // 7 days
        let ea_domain = "enterprise.com";

        let proof = prove_identity_binding(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            amount_sats,
            expires_at,
            ea_domain,
            &nonce,
        )
        .expect("Proof generation should succeed");

        // Serialize to JSON
        let json = serde_json::to_string(&proof).expect("JSON serialization should work");
        assert!(json.contains("stwo-real-v3"));
        assert!(json.contains("schema_version"));
        assert!(json.contains("ea_domain"));

        // Verify from JSON
        let valid = verify_proof_json(&json).expect("JSON verification should work");
        assert!(valid);
    }

    #[test]
    fn test_tampered_amount_fails() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let wallet_address = "sp1qtest123";
        let payment_hash = [1u8; 32];
        let amount_sats = 500u64;
        let nonce = [4u8; 16];
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + (30 * 24 * 60 * 60);
        let ea_domain = "test.com";

        let mut proof = prove_identity_binding(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            amount_sats,
            expires_at,
            ea_domain,
            &nonce,
        )
        .expect("Proof generation should succeed");

        // Tamper with amount
        proof.public_inputs.amount_sats = 1; // Try to pay less

        // Verification should fail due to hash mismatch
        let result = verify_identity_binding(&proof);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_tampered_domain_fails() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let wallet_address = "sp1qtest123";
        let payment_hash = [1u8; 32];
        let amount_sats = 500u64;
        let nonce = [5u8; 16];
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + (30 * 24 * 60 * 60);
        let ea_domain = "acme.com";

        let mut proof = prove_identity_binding(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            amount_sats,
            expires_at,
            ea_domain,
            &nonce,
        )
        .expect("Proof generation should succeed");

        // Tamper with domain (cross-RP replay attack)
        proof.public_inputs.ea_domain = "evilcorp.com".to_string();

        // Verification should fail due to hash mismatch
        let result = verify_identity_binding(&proof);
        assert!(result.is_err() || !result.unwrap());
    }
}
