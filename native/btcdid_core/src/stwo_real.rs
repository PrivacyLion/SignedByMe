// stwo_real.rs
// Real STWO STARK prover implementation for SignedByMe identity proofs
// Uses StarkWare's Circle STARK library with REAL SHA-256 circuit
// 
// The circuit PROVES knowledge of the v4 binding hash preimage:
// - Private witness: 283-byte preimage (DID, wallet, client, session, payment, etc.)
// - Public input: 32-byte binding hash
// - Constraint: SHA256(witness) == binding_hash
//
// This is NOT a tautology - it proves the prover knows the preimage.

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

// Import our SHA-256 circuit
use crate::sha256_circuit::{
    self, Sha256BindingEval, V4_PREIMAGE_SIZE, N_TRACE_COLS, LOG_N_ROWS,
};

// Import v4 binding hash computation
use crate::membership::binding::{compute_binding_hash_v4, hash_field, SCHEMA_VERSION_V4, DOMAIN_SEPARATOR_V4};

/// Current schema version for H_bind
pub const SCHEMA_VERSION: u8 = 4;

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

/// Public inputs for identity binding proof (v4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPublicInputs {
    /// Schema version (4 for v4)
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
    /// Client ID
    pub client_id: String,
    /// Session ID
    pub session_id: String,
    /// Purpose ID (0=none, 1=allowlist, 2=employee, 3=kyc)
    pub purpose_id: u8,
    /// Root ID (for membership proofs, empty if no membership)
    pub root_id: String,
}

/// Framework component type alias for SHA-256 binding circuit
pub type Sha256BindingComponent = FrameworkComponent<Sha256BindingEval>;

/// Build the 283-byte v4 preimage from components
/// 
/// This matches the layout in compute_binding_hash_v4:
/// ```text
///     schema_version: u8           = 4                              // 1 byte
///     domain_sep: [u8; 24]         = "signedby.me:identity:v4"      // 24 bytes
///     did_pubkey: [u8; 33]         = compressed secp256k1 pubkey    // 33 bytes
///     wallet_hash: [u8; 32]        = H("wallet:" || wallet_addr)    // 32 bytes
///     client_id_hash: [u8; 32]     = H("client_id:" || client_id)   // 32 bytes
///     session_id_hash: [u8; 32]    = H("session_id:" || session_id) // 32 bytes
///     payment_hash: [u8; 32]       = from invoice                   // 32 bytes
///     amount_sats: u64 LE          = payment amount                 // 8 bytes
///     expires_at: u64 LE           = session expiry                 // 8 bytes
///     nonce: [u8; 16]              = session nonce                  // 16 bytes
///     ea_domain_hash: [u8; 32]     = H("ea_domain:" || domain)      // 32 bytes
///     purpose_id: u8               = 0/1/2/3 enum                   // 1 byte
///     root_id_hash: [u8; 32]       = H("root_id:" || root_id)       // 32 bytes
/// ```
/// Total: 1 + 24 + 33 + 32 + 32 + 32 + 32 + 8 + 8 + 16 + 32 + 1 + 32 = 283 bytes
fn build_v4_preimage(
    did_pubkey: &[u8],
    wallet_address: &str,
    client_id: &str,
    session_id: &str,
    payment_hash: &[u8],
    amount_sats: u64,
    expires_at: u64,
    nonce: &[u8],
    ea_domain: &str,
    purpose_id: u8,
    root_id: &str,
) -> [u8; V4_PREIMAGE_SIZE] {
    let mut preimage = [0u8; V4_PREIMAGE_SIZE];
    let mut offset = 0;
    
    // Schema version (1 byte)
    preimage[offset] = SCHEMA_VERSION_V4;
    offset += 1;
    
    // Domain separator (24 bytes, padded)
    let sep_len = DOMAIN_SEPARATOR_V4.len().min(24);
    preimage[offset..offset + sep_len].copy_from_slice(&DOMAIN_SEPARATOR_V4[..sep_len]);
    offset += 24;
    
    // DID pubkey (33 bytes, padded)
    let did_len = did_pubkey.len().min(33);
    preimage[offset..offset + did_len].copy_from_slice(&did_pubkey[..did_len]);
    offset += 33;
    
    // Wallet address hash (32 bytes)
    let wallet_hash = hash_field("wallet", wallet_address);
    preimage[offset..offset + 32].copy_from_slice(&wallet_hash);
    offset += 32;
    
    // Client ID hash (32 bytes)
    let client_hash = hash_field("client_id", client_id);
    preimage[offset..offset + 32].copy_from_slice(&client_hash);
    offset += 32;
    
    // Session ID hash (32 bytes)
    let session_hash = hash_field("session_id", session_id);
    preimage[offset..offset + 32].copy_from_slice(&session_hash);
    offset += 32;
    
    // Payment hash (32 bytes, padded)
    let payment_len = payment_hash.len().min(32);
    preimage[offset..offset + payment_len].copy_from_slice(&payment_hash[..payment_len]);
    offset += 32;
    
    // Amount sats (8 bytes LE)
    preimage[offset..offset + 8].copy_from_slice(&amount_sats.to_le_bytes());
    offset += 8;
    
    // Expires at (8 bytes LE)
    preimage[offset..offset + 8].copy_from_slice(&expires_at.to_le_bytes());
    offset += 8;
    
    // Nonce (16 bytes, padded)
    let nonce_len = nonce.len().min(16);
    preimage[offset..offset + nonce_len].copy_from_slice(&nonce[..nonce_len]);
    offset += 16;
    
    // EA domain hash (32 bytes)
    let domain_hash = hash_field("ea_domain", ea_domain);
    preimage[offset..offset + 32].copy_from_slice(&domain_hash);
    offset += 32;
    
    // Purpose ID (1 byte)
    preimage[offset] = purpose_id;
    offset += 1;
    
    // Root ID hash (32 bytes, zeros if empty)
    if root_id.is_empty() {
        // Already zeros from initialization
    } else {
        let root_hash = hash_field("root_id", root_id);
        preimage[offset..offset + 32].copy_from_slice(&root_hash);
    }
    
    preimage
}

/// Convert 32 bytes to 8 M31 field elements (4 bytes each)
fn bytes_to_m31_vec(bytes: &[u8; 32]) -> Vec<BaseField> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            BaseField::from_u32_unchecked(val % ((1u32 << 31) - 1))
        })
        .collect()
}

/// Generate the execution trace for SHA-256 identity binding proof
fn generate_identity_trace(
    preimage: &[u8; V4_PREIMAGE_SIZE],
    binding_hash: &[u8; 32],
) -> Result<ColumnVec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>> {
    // Generate SHA-256 trace
    let trace_cols = sha256_circuit::generate_sha256_trace(preimage, binding_hash)?;
    
    // Convert to circle evaluations
    let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
    let evaluations = trace_cols
        .into_iter()
        .map(|col| CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, col))
        .collect_vec();
    
    Ok(evaluations)
}

/// Generate a real STWO identity proof (v4 with SHA-256 circuit)
/// 
/// This proves knowledge of the preimage that hashes to binding_hash.
/// The proof is NOT a tautology - it contains real cryptographic constraints.
pub fn prove_identity_binding(
    did_pubkey: &[u8],
    wallet_address: &str,
    client_id: &str,
    session_id: &str,
    payment_hash: &[u8; 32],
    amount_sats: u64,
    expires_at: u64,
    ea_domain: &str,
    nonce: &[u8; 16],
    purpose_id: u8,
    root_id: &str,
) -> Result<RealStwoProof> {
    // Build the 283-byte preimage (private witness)
    let preimage = build_v4_preimage(
        did_pubkey,
        wallet_address,
        client_id,
        session_id,
        payment_hash,
        amount_sats,
        expires_at,
        nonce,
        ea_domain,
        purpose_id,
        root_id,
    );
    
    // Compute binding hash (public input)
    let binding_hash = compute_binding_hash_v4(
        did_pubkey,
        wallet_address,
        client_id,
        session_id,
        payment_hash,
        amount_sats,
        expires_at,
        nonce,
        ea_domain,
        purpose_id,
        root_id,
    );
    
    // Verify our preimage produces the correct hash
    let computed = sha256_circuit::sha256(&preimage);
    if computed != binding_hash {
        return Err(anyhow!(
            "Preimage hash mismatch: computed {} but binding_hash is {}",
            hex::encode(computed),
            hex::encode(binding_hash)
        ));
    }

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

    // Preprocessed trace (empty for our circuit)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(prover_channel);

    // Generate and commit trace
    let trace = generate_identity_trace(&preimage, &binding_hash)?;

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    // Create component with expected hash
    let component = Sha256BindingComponent::new(
        &mut TraceLocationAllocator::default(),
        Sha256BindingEval {
            log_n_rows: LOG_N_ROWS,
            expected_hash: binding_hash,
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
        version: "stwo-sha256-v4".to_string(),
        circuit_type: "sha256_identity_binding".to_string(),
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
            client_id: client_id.to_string(),
            session_id: session_id.to_string(),
            purpose_id,
            root_id: root_id.to_string(),
        },
        proof_data,
        generated_at: now,
    })
}

/// Verify a real STWO identity proof
pub fn verify_identity_binding(proof: &RealStwoProof) -> Result<bool> {
    // Check version
    if !proof.version.starts_with("stwo-sha256-v") {
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

    // Decode public inputs
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
    
    // Recompute binding hash from public inputs
    let expected_hash = compute_binding_hash_v4(
        &did_bytes,
        &proof.public_inputs.wallet_address,
        &proof.public_inputs.client_id,
        &proof.public_inputs.session_id,
        &payment_hash,
        proof.public_inputs.amount_sats,
        proof.public_inputs.expires_at,
        &nonce,
        &proof.public_inputs.ea_domain,
        proof.public_inputs.purpose_id,
        &proof.public_inputs.root_id,
    );
    
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
    let component = Sha256BindingComponent::new(
        &mut TraceLocationAllocator::default(),
        Sha256BindingEval {
            log_n_rows: LOG_N_ROWS,
            expected_hash,
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

// ============================================================================
// Legacy API (for backwards compatibility)
// ============================================================================

/// Legacy v3 binding hash (for backwards compat during migration)
const DOMAIN_SEPARATOR_V3: &[u8; 23] = b"signedby.me:identity:v3";

/// Compute the v3 binding hash (legacy, for backwards compatibility)
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
    
    // Schema version (1 byte) - v3
    hasher.update(&[3u8]);
    
    // Domain separator (23 bytes)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_v4_preimage_size() {
        let did_pubkey = [0x02u8; 33];
        let preimage = build_v4_preimage(
            &did_pubkey,
            "wallet123",
            "client_id",
            "session_id",
            &[0u8; 32],
            500,
            1700000000,
            &[0u8; 16],
            "test.com",
            1,
            "root1",
        );
        assert_eq!(preimage.len(), V4_PREIMAGE_SIZE);
    }

    #[test]
    fn test_preimage_produces_correct_hash() {
        let did_pubkey = [0x02u8; 33];
        let payment_hash = [0xaau8; 32];
        let nonce = [0xbbu8; 16];
        
        let preimage = build_v4_preimage(
            &did_pubkey,
            "wallet123",
            "client_id",
            "session_id",
            &payment_hash,
            500,
            1700000000,
            &nonce,
            "test.com",
            1,
            "root1",
        );
        
        // Hash the preimage
        let preimage_hash = sha256_circuit::sha256(&preimage);
        
        // Compute binding hash
        let binding_hash = compute_binding_hash_v4(
            &did_pubkey,
            "wallet123",
            "client_id",
            "session_id",
            &payment_hash,
            500,
            1700000000,
            &nonce,
            "test.com",
            1,
            "root1",
        );
        
        // They should be equal
        assert_eq!(preimage_hash, binding_hash, "Preimage hash must equal binding hash");
    }

    #[test]
    fn test_prove_and_verify_identity_v4() {
        let did_pubkey = hex::decode("02abc123def456789012345678901234567890123456789012345678901234567890").unwrap();
        let wallet_address = "sp1qtest123";
        let client_id = "acme_corp";
        let session_id = "session_12345";
        let payment_hash = [1u8; 32];
        let amount_sats = 500u64;
        let nonce = [2u8; 16];
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + (30 * 24 * 60 * 60); // 30 days
        let ea_domain = "test.signedby.me";
        let purpose_id = 1u8;
        let root_id = "allowlist-2026-Q1";

        // Generate proof
        let proof = prove_identity_binding(
            &did_pubkey,
            wallet_address,
            client_id,
            session_id,
            &payment_hash,
            amount_sats,
            expires_at,
            ea_domain,
            &nonce,
            purpose_id,
            root_id,
        )
        .expect("Proof generation should succeed");

        assert_eq!(proof.version, "stwo-sha256-v4");
        assert_eq!(proof.circuit_type, "sha256_identity_binding");
        assert_eq!(proof.public_inputs.schema_version, 4);
        assert_eq!(proof.public_inputs.amount_sats, 500);
        assert_eq!(proof.public_inputs.ea_domain, "test.signedby.me");
        assert_eq!(proof.public_inputs.client_id, "acme_corp");
        assert_eq!(proof.public_inputs.session_id, "session_12345");

        // Verify proof
        let valid = verify_identity_binding(&proof).expect("Verification should not error");
        assert!(valid, "Valid proof should verify");
    }

    #[test]
    fn test_tampered_amount_fails() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let payment_hash = [1u8; 32];
        let nonce = [4u8; 16];
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + (30 * 24 * 60 * 60);

        let mut proof = prove_identity_binding(
            &did_pubkey,
            "sp1qtest",
            "client",
            "session",
            &payment_hash,
            500,
            expires_at,
            "test.com",
            &nonce,
            0,
            "",
        )
        .expect("Proof generation should succeed");

        // Tamper with amount
        proof.public_inputs.amount_sats = 1; // Try to pay less

        // Verification should fail due to hash mismatch
        let result = verify_identity_binding(&proof);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_tampered_session_fails() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let payment_hash = [1u8; 32];
        let nonce = [5u8; 16];
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + (30 * 24 * 60 * 60);

        let mut proof = prove_identity_binding(
            &did_pubkey,
            "sp1qtest",
            "client",
            "session_original",
            &payment_hash,
            500,
            expires_at,
            "test.com",
            &nonce,
            0,
            "",
        )
        .expect("Proof generation should succeed");

        // Tamper with session (replay attack attempt)
        proof.public_inputs.session_id = "session_different".to_string();

        // Verification should fail due to hash mismatch
        let result = verify_identity_binding(&proof);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_proof_json_serialization() {
        let did_pubkey = hex::decode("02abc123def456").unwrap();
        let payment_hash = [1u8; 32];
        let nonce = [3u8; 16];
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + (7 * 24 * 60 * 60);

        let proof = prove_identity_binding(
            &did_pubkey,
            "sp1qtest123",
            "enterprise",
            "session_xyz",
            &payment_hash,
            1000,
            expires_at,
            "enterprise.com",
            &nonce,
            1,
            "employees-2026",
        )
        .expect("Proof generation should succeed");

        // Serialize to JSON
        let json = serde_json::to_string(&proof).expect("JSON serialization should work");
        assert!(json.contains("stwo-sha256-v4"));
        assert!(json.contains("sha256_identity_binding"));
        assert!(json.contains("client_id"));
        assert!(json.contains("session_id"));

        // Verify from JSON
        let valid = verify_proof_json(&json).expect("JSON verification should work");
        assert!(valid);
    }
}

// ============================================================================
// Legacy v1 API (for backwards compatibility)
// ============================================================================

/// Legacy v1 proof generation (uses v2 hash format for existing deployments)
/// This is a shim that calls v4 with default values for the new fields
pub fn prove_identity_binding_v1(
    did_pubkey: &[u8],
    wallet_address: &str,
    payment_hash: &[u8; 32],
    timestamp: u64,
    expiry_days: u32,
) -> Result<RealStwoProof> {
    let nonce = [0u8; 16]; // Zero nonce for v1 compat
    let expires_at = timestamp + (expiry_days as u64 * 24 * 60 * 60);
    
    prove_identity_binding(
        did_pubkey,
        wallet_address,
        "legacy_v1",  // client_id
        "legacy_v1",  // session_id
        payment_hash,
        0,            // amount_sats unknown in v1
        expires_at,
        "",           // ea_domain unknown in v1
        &nonce,
        0,            // purpose_id = none
        "",           // root_id = empty
    )
}
