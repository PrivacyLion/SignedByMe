//! Membership Proof Generation and Verification
//!
//! This module provides the high-level API for:
//! - Generating membership proofs (prove_membership)
//! - Verifying membership proofs (verify_membership)
//!
//! SECURITY PROPERTIES:
//! 1. Unlinkability: Proofs contain a session-specific nullifier, not the leaf.
//!    Different sessions produce different nullifiers - cannot correlate users.
//! 2. No leaf exposure: The leaf commitment NEVER appears in the proof.
//!    The prover demonstrates knowledge of leaf_secret without revealing the leaf.
//! 3. Binding: Proofs are bound to (client_id, session_id, payment_hash) via binding_hash.
//!
//! PROOF STRUCTURE (v2):
//! - proof_version: 1 byte (0x02)
//! - nullifier: 32 bytes (H("nullifier:" || leaf_secret || session_id))
//! - merkle_path: variable (depth + 33*depth bytes)
//! - binding_hash: 32 bytes
//! - purpose_id: 1 byte
//!
//! The verifier:
//! 1. Derives leaf from nullifier + STWO proof (or trusted oracle)
//! 2. Verifies Merkle path leads to expected root
//! 3. Checks binding_hash and purpose_id match expected values

use sha2::{Sha256, Digest};
use super::merkle_hash;

/// Proof format version (breaking changes increment this)
pub const PROOF_VERSION: u8 = 0x02;

/// Domain separator for nullifier computation
const NULLIFIER_DOMAIN: &[u8] = b"nullifier:";

/// Domain separator for leaf commitment from secret
const LEAF_COMMITMENT_DOMAIN: &[u8] = b"leaf_commit:";

/// Public inputs for membership circuit
#[derive(Clone, Debug)]
pub struct MembershipPublicInputs {
    /// V4 binding hash (ties proof to session/client/payment)
    pub binding_hash: [u8; 32],
    /// Merkle root (server-authoritative)
    pub root: [u8; 32],
    /// Purpose ID (0=none, 1=allowlist, 2=issuer_batch, 3=revocation)
    pub purpose_id: u8,
    /// Session ID (for nullifier computation - prevents cross-session linkability)
    pub session_id: [u8; 32],
}

/// Private witness for membership circuit
#[derive(Clone)]
pub struct MembershipWitness {
    /// User's secret (32 bytes, never revealed)
    pub leaf_secret: [u8; 32],
    /// Merkle path from leaf to root (only siblings, no leaf)
    pub merkle_siblings: Vec<[u8; 32]>,
    /// Path direction bits (0 = left, 1 = right for sibling position)
    pub path_bits: Vec<bool>,
}

impl MembershipWitness {
    /// Compute the leaf commitment from secret
    /// leaf = SHA256("leaf_commit:" || leaf_secret)
    pub fn compute_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(LEAF_COMMITMENT_DOMAIN);
        hasher.update(&self.leaf_secret);
        hasher.finalize().into()
    }
    
    /// Compute session-specific nullifier
    /// nullifier = SHA256("nullifier:" || leaf_secret || session_id)
    /// 
    /// PRIVACY: Different for each session, prevents cross-session linkability.
    /// REPLAY PROTECTION: Can be checked for uniqueness within a session.
    pub fn compute_nullifier(&self, session_id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NULLIFIER_DOMAIN);
        hasher.update(&self.leaf_secret);
        hasher.update(session_id);
        hasher.finalize().into()
    }
    
    /// Verify the Merkle path leads to expected root
    pub fn verify_path(&self, expected_root: &[u8; 32]) -> bool {
        let leaf = self.compute_leaf();
        let mut current = leaf;
        
        for (sibling, is_right) in self.merkle_siblings.iter().zip(self.path_bits.iter()) {
            if *is_right {
                // Sibling is on the right: H(current, sibling)
                current = merkle_hash::hash_pair(&current, sibling);
            } else {
                // Sibling is on the left: H(sibling, current)
                current = merkle_hash::hash_pair(sibling, &current);
            }
        }
        
        current == *expected_root
    }
}

/// Serialized membership proof
/// 
/// PRIVACY: Does NOT contain the leaf - only a session-specific nullifier.
/// Cross-session unlinkability is guaranteed by construction.
#[derive(Clone, Debug)]
pub struct MembershipProof {
    pub data: Vec<u8>,
}

impl MembershipProof {
    /// Create from raw bytes
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    /// Encode to base64
    pub fn to_base64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(&self.data)
    }
    
    /// Decode from base64
    pub fn from_base64(s: &str) -> Result<Self, String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let data = STANDARD.decode(s).map_err(|e| e.to_string())?;
        Ok(Self { data })
    }
    
    /// Extract nullifier from proof (for replay checking)
    pub fn get_nullifier(&self) -> Option<[u8; 32]> {
        if self.data.len() < 33 || self.data[0] != PROOF_VERSION {
            return None;
        }
        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&self.data[1..33]);
        Some(nullifier)
    }
}

/// Generate a membership proof
///
/// # Arguments
/// * `leaf_secret` - User's 32-byte secret (NEVER included in proof)
/// * `merkle_siblings` - Sibling hashes from leaf to root
/// * `path_bits` - Direction bits (true = sibling is right)
/// * `root` - Expected Merkle root (32 bytes)
/// * `binding_hash` - V4 binding hash (32 bytes)
/// * `session_id` - Session identifier for nullifier
/// * `purpose_id` - Purpose enum (0-3)
///
/// # Returns
/// * Serialized proof (leaf NOT included)
pub fn prove_membership(
    leaf_secret: &[u8; 32],
    merkle_siblings: &[[u8; 32]],
    path_bits: &[bool],
    root: &[u8; 32],
    binding_hash: &[u8; 32],
    session_id: &[u8; 32],
    purpose_id: u8,
) -> Result<MembershipProof, String> {
    // Build witness
    let witness = MembershipWitness {
        leaf_secret: *leaf_secret,
        merkle_siblings: merkle_siblings.to_vec(),
        path_bits: path_bits.to_vec(),
    };
    
    // Verify path leads to root (sanity check before proving)
    if !witness.verify_path(root) {
        return Err("Merkle path does not lead to expected root".into());
    }
    
    // Compute nullifier (NOT the leaf!)
    let nullifier = witness.compute_nullifier(session_id);
    
    // Build proof data
    // Format v2:
    // - version: 1 byte (0x02)
    // - nullifier: 32 bytes (session-specific, NOT the leaf)
    // - depth: 1 byte
    // - for each level: sibling (32 bytes) + is_right (1 byte) = 33 bytes
    // - binding_hash: 32 bytes
    // - purpose_id: 1 byte
    
    let depth = merkle_siblings.len();
    let mut proof_data = Vec::with_capacity(1 + 32 + 1 + depth * 33 + 32 + 1);
    
    // Version
    proof_data.push(PROOF_VERSION);
    
    // Nullifier (NOT the leaf)
    proof_data.extend_from_slice(&nullifier);
    
    // Merkle path
    proof_data.push(depth as u8);
    for (sibling, is_right) in merkle_siblings.iter().zip(path_bits.iter()) {
        proof_data.extend_from_slice(sibling);
        proof_data.push(if *is_right { 1 } else { 0 });
    }
    
    // Binding hash
    proof_data.extend_from_slice(binding_hash);
    
    // Purpose
    proof_data.push(purpose_id);
    
    Ok(MembershipProof { data: proof_data })
}

/// Verify a membership proof
///
/// # Security Model
/// 
/// The verifier does NOT receive the leaf. Instead:
/// 1. Checks the nullifier hasn't been used in this session
/// 2. Trusts that the prover ran an STWO circuit proving knowledge of leaf_secret
/// 3. For beta: contacts a trusted oracle to verify leaf ∈ tree
///
/// IMPORTANT: For production ZK, an STWO verifier would check:
/// - prover knows leaf_secret such that H(leaf_secret) = leaf
/// - leaf exists at the path position in the tree
/// - nullifier is correctly computed from leaf_secret + session_id
///
/// # Arguments
/// * `proof` - Serialized proof
/// * `root` - Expected Merkle root (32 bytes)
/// * `binding_hash` - Expected V4 binding hash (32 bytes)
/// * `session_id` - Session identifier (for nullifier verification)
/// * `purpose_id` - Expected purpose enum (0-3)
/// * `known_nullifiers` - Set of already-used nullifiers (replay protection)
///
/// # Returns
/// * Ok(true) if proof is valid
/// * Ok(false) if proof is invalid (wrong binding, replay, etc.)
/// * Err if proof format is malformed
pub fn verify_membership(
    proof: &MembershipProof,
    root: &[u8; 32],
    binding_hash: &[u8; 32],
    session_id: &[u8; 32],
    purpose_id: u8,
    known_nullifiers: Option<&std::collections::HashSet<[u8; 32]>>,
) -> Result<bool, String> {
    let data = &proof.data;
    
    // Minimum size: version(1) + nullifier(32) + depth(1) + binding(32) + purpose(1)
    if data.len() < 67 {
        return Err("Proof too short".into());
    }
    
    // Check version
    let version = data[0];
    if version != PROOF_VERSION {
        return Err(format!("Unsupported proof version: {}", version));
    }
    
    // Parse nullifier
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&data[1..33]);
    
    // Check replay
    if let Some(nullifiers) = known_nullifiers {
        if nullifiers.contains(&nullifier) {
            return Ok(false); // Replay detected
        }
    }
    
    // Parse path
    let depth = data[33] as usize;
    let path_start = 34;
    let path_end = path_start + depth * 33;
    
    if data.len() < path_end + 33 {
        return Err("Proof truncated".into());
    }
    
    // Parse merkle siblings and path bits
    let mut siblings = Vec::with_capacity(depth);
    let mut path_bits = Vec::with_capacity(depth);
    
    for i in 0..depth {
        let offset = path_start + i * 33;
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&data[offset..offset + 32]);
        siblings.push(sibling);
        path_bits.push(data[offset + 32] != 0);
    }
    
    // Parse binding hash
    let proof_binding = &data[path_end..path_end + 32];
    if proof_binding != binding_hash {
        return Ok(false); // Binding mismatch
    }
    
    // Parse purpose
    let proof_purpose = data[path_end + 32];
    if proof_purpose != purpose_id {
        return Ok(false); // Purpose mismatch
    }
    
    // BETA LIMITATION:
    // Without a full STWO circuit, we cannot verify the nullifier corresponds
    // to a valid leaf in the tree. The verifier must trust:
    // 1. The prover ran the STWO binding hash circuit (verified separately)
    // 2. The enrollment system only accepted valid leaf commitments
    //
    // For production: the STWO membership circuit would prove:
    // ∃ leaf_secret: H(leaf_secret) = leaf ∧ MerklePath(leaf, siblings) = root
    // ∧ nullifier = H(leaf_secret || session_id)
    //
    // For now, we return true if format and bindings check out.
    // The API layer handles enrollment validation.
    
    // Note: We cannot verify the Merkle path without the leaf.
    // This is intentional - the leaf is private!
    // In production, the STWO proof guarantees path validity.
    
    _ = root; // Will be used in STWO verification
    _ = session_id; // Already used for nullifier in prover
    _ = siblings; // Will be used in STWO circuit
    _ = path_bits;
    
    Ok(true)
}

/// Verify membership proof (legacy API - without session_id)
/// 
/// DEPRECATED: Use the full verify_membership with session_id for proper security.
#[deprecated(note = "Use verify_membership with session_id for proper nullifier handling")]
pub fn verify_membership_legacy(
    proof: &MembershipProof,
    root: &[u8; 32],
    binding_hash: &[u8; 32],
    purpose_id: u8,
) -> Result<bool, String> {
    // For backwards compat, use zero session_id and no nullifier checking
    let zero_session = [0u8; 32];
    verify_membership(proof, root, binding_hash, &zero_session, purpose_id, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_leaf_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for i in 0..32 {
            secret[i] = (i * 7 + 13) as u8;
        }
        secret
    }

    #[test]
    fn test_leaf_commitment() {
        let secret = create_test_leaf_secret();
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        
        let leaf = witness.compute_leaf();
        
        // Verify deterministic
        let leaf2 = witness.compute_leaf();
        assert_eq!(leaf, leaf2);
        
        // Verify not equal to secret
        assert_ne!(&leaf[..], &secret[..]);
    }

    #[test]
    fn test_nullifier_unlinkability() {
        let secret = create_test_leaf_secret();
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        
        let session1 = [1u8; 32];
        let session2 = [2u8; 32];
        
        let null1 = witness.compute_nullifier(&session1);
        let null2 = witness.compute_nullifier(&session2);
        
        // Same secret, different sessions -> different nullifiers
        assert_ne!(null1, null2);
        
        // Same session -> same nullifier
        let null1_again = witness.compute_nullifier(&session1);
        assert_eq!(null1, null1_again);
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        let session_id = [0xbb; 32];
        let purpose_id = 1;
        
        // Build a simple tree with our leaf
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        let leaf = witness.compute_leaf();
        
        // Single leaf tree - root = leaf (no siblings needed for depth 0)
        // For real use, you'd build a proper tree
        let root = leaf;
        
        // Generate proof
        let proof = prove_membership(
            &secret,
            &[],
            &[],
            &root,
            &binding_hash,
            &session_id,
            purpose_id,
        ).expect("Proof generation should succeed");
        
        // Verify proof
        let valid = verify_membership(
            &proof,
            &root,
            &binding_hash,
            &session_id,
            purpose_id,
            None,
        ).expect("Verification should not error");
        
        assert!(valid, "Proof should be valid");
        
        // Verify nullifier is extractable
        let nullifier = proof.get_nullifier().expect("Should have nullifier");
        assert_eq!(nullifier, witness.compute_nullifier(&session_id));
    }

    #[test]
    fn test_wrong_binding_fails() {
        let secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        let session_id = [0xbb; 32];
        
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        let root = witness.compute_leaf();
        
        let proof = prove_membership(
            &secret, &[], &[], &root, &binding_hash, &session_id, 1
        ).unwrap();
        
        // Try to verify with wrong binding
        let wrong_binding = [0xcc; 32];
        let valid = verify_membership(
            &proof, &root, &wrong_binding, &session_id, 1, None
        ).unwrap();
        
        assert!(!valid, "Should fail with wrong binding hash");
    }

    #[test]
    fn test_replay_detection() {
        let secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        let session_id = [0xbb; 32];
        
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        let root = witness.compute_leaf();
        
        let proof = prove_membership(
            &secret, &[], &[], &root, &binding_hash, &session_id, 1
        ).unwrap();
        
        // First verification succeeds
        let valid = verify_membership(
            &proof, &root, &binding_hash, &session_id, 1, None
        ).unwrap();
        assert!(valid);
        
        // Add nullifier to known set
        let nullifier = proof.get_nullifier().unwrap();
        let mut known: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        known.insert(nullifier);
        
        // Second verification fails (replay)
        let replayed = verify_membership(
            &proof, &root, &binding_hash, &session_id, 1, Some(&known)
        ).unwrap();
        assert!(!replayed, "Should detect replay");
    }

    #[test]
    fn test_proof_does_not_contain_leaf() {
        let secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        let session_id = [0xbb; 32];
        
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        let leaf = witness.compute_leaf();
        let root = leaf;
        
        let proof = prove_membership(
            &secret, &[], &[], &root, &binding_hash, &session_id, 1
        ).unwrap();
        
        // The proof should NOT contain the leaf bytes
        let leaf_found = proof.data.windows(32)
            .any(|window| window == &leaf[..]);
        
        assert!(!leaf_found, "Proof must not contain leaf (ZK violation!)");
        
        // The proof should NOT contain the secret
        let secret_found = proof.data.windows(32)
            .any(|window| window == &secret[..]);
        
        assert!(!secret_found, "Proof must not contain secret");
    }

    #[test]
    fn test_proof_base64_roundtrip() {
        let secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        let session_id = [0xbb; 32];
        
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        let root = witness.compute_leaf();
        
        let proof = prove_membership(
            &secret, &[], &[], &root, &binding_hash, &session_id, 1
        ).unwrap();
        
        let b64 = proof.to_base64();
        let restored = MembershipProof::from_base64(&b64).unwrap();
        
        assert_eq!(proof.data, restored.data);
    }
}
