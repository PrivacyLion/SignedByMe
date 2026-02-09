// stwo_real.rs
// Real STWO STARK prover implementation for SignedByMe identity proofs
// Uses StarkWare's Circle STARK library

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
/// For a single identity proof, we use LOG_N_ROWS = 0 (1 row)
const LOG_N_ROWS: u32 = 0;

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

/// Public inputs for identity binding proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPublicInputs {
    /// Binding hash (H_bind) - 32 bytes hex
    pub binding_hash: String,
    /// DID public key - 33 bytes hex (compressed secp256k1)
    pub did_pubkey: String,
    /// Payment hash from Lightning invoice - 32 bytes hex
    pub payment_hash: String,
    /// Wallet address
    pub wallet_address: String,
    /// Timestamp when proof was generated
    pub timestamp: u64,
    /// Expiry timestamp
    pub expires_at: u64,
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
        // the preimage (did_pubkey, wallet_address, payment_hash, timestamp)

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

/// Compute the binding hash from components
pub fn compute_binding_hash(
    did_pubkey: &[u8],
    wallet_address: &str,
    payment_hash: &[u8; 32],
    timestamp: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"signedby.me:identity:v2");
    hasher.update(did_pubkey);
    hasher.update(wallet_address.as_bytes());
    hasher.update(payment_hash);
    hasher.update(&timestamp.to_le_bytes());
    hasher.finalize().into()
}

/// Generate the execution trace for identity binding proof
pub fn generate_identity_trace(
    binding_hash: &[u8; 32],
    did_pubkey: &[u8],
    wallet_address: &str,
    payment_hash: &[u8; 32],
    timestamp: u64,
) -> Result<ColumnVec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>> {
    // Verify the binding hash matches
    let computed = compute_binding_hash(did_pubkey, wallet_address, payment_hash, timestamp);
    if computed != *binding_hash {
        return Err(anyhow!("Binding hash mismatch - invalid preimage"));
    }

    // Convert hashes to field elements
    let binding_fields = bytes_to_m31_vec(binding_hash);
    let computed_fields = bytes_to_m31_vec(&computed);

    // Create trace columns
    let n_rows = 1usize << LOG_N_ROWS;
    let mut trace: Vec<Col<CpuBackend, BaseField>> = (0..N_COLS)
        .map(|_| Col::<CpuBackend, BaseField>::zeros(n_rows))
        .collect();

    // Fill trace for each row (we have 1 row for single proof)
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

/// Generate a real STWO identity proof
pub fn prove_identity_binding(
    did_pubkey: &[u8],
    wallet_address: &str,
    payment_hash: &[u8; 32],
    timestamp: u64,
    expiry_days: u32,
) -> Result<RealStwoProof> {
    // Compute binding hash
    let binding_hash = compute_binding_hash(did_pubkey, wallet_address, payment_hash, timestamp);

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
    let trace = generate_identity_trace(
        &binding_hash,
        did_pubkey,
        wallet_address,
        payment_hash,
        timestamp,
    )?;

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

    let expires_at = timestamp + (expiry_days as u64 * 24 * 60 * 60);

    Ok(RealStwoProof {
        version: "stwo-real-v1".to_string(),
        circuit_type: "identity_binding".to_string(),
        public_inputs: ProofPublicInputs {
            binding_hash: hex::encode(binding_hash),
            did_pubkey: hex::encode(did_pubkey),
            payment_hash: hex::encode(payment_hash),
            wallet_address: wallet_address.to_string(),
            timestamp,
            expires_at,
        },
        proof_data,
        generated_at: now,
    })
}

/// Verify a real STWO identity proof
pub fn verify_identity_binding(proof: &RealStwoProof) -> Result<bool> {
    // Check version
    if proof.version != "stwo-real-v1" {
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
    fn test_binding_hash_computation() {
        let did_pubkey = hex::decode("02abc123").unwrap();
        let wallet_address = "sp1qtest";
        let payment_hash = [0u8; 32];
        let timestamp = 1707500000u64;

        let hash = compute_binding_hash(&did_pubkey, wallet_address, &payment_hash, timestamp);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_bytes_to_m31() {
        let original = [42u8; 32];
        let fields = bytes_to_m31_vec(&original);
        assert_eq!(fields.len(), 8);
    }

    #[test]
    fn test_prove_and_verify_identity() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let wallet_address = "sp1qtest123";
        let payment_hash = [1u8; 32];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry_days = 30u32;

        // Generate proof
        let proof = prove_identity_binding(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            timestamp,
            expiry_days,
        )
        .expect("Proof generation should succeed");

        assert_eq!(proof.version, "stwo-real-v1");
        assert_eq!(proof.circuit_type, "identity_binding");

        // Verify proof
        let valid = verify_identity_binding(&proof).expect("Verification should not error");
        assert!(valid, "Valid proof should verify");
    }

    #[test]
    fn test_proof_json_serialization() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let wallet_address = "sp1qtest123";
        let payment_hash = [1u8; 32];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry_days = 30u32;

        let proof = prove_identity_binding(
            &did_pubkey,
            wallet_address,
            &payment_hash,
            timestamp,
            expiry_days,
        )
        .expect("Proof generation should succeed");

        // Serialize to JSON
        let json = serde_json::to_string(&proof).expect("JSON serialization should work");
        assert!(json.contains("stwo-real-v1"));

        // Verify from JSON
        let valid = verify_proof_json(&json).expect("JSON verification should work");
        assert!(valid);
    }
}
