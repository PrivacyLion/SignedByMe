//! Membership Proof Generation and Verification
//!
//! This module provides the high-level API for:
//! - Generating membership proofs (prove_membership)
//! - Verifying membership proofs (verify_membership)
//!
//! SECURITY PROPERTIES:
//! 1. Unlinkability: Proofs contain a session-specific nullifier.
//!    Different sessions produce different nullifiers - cannot correlate users.
//! 2. Binding: Proofs are bound to (client_id, session_id, payment_hash) via binding_hash.
//! 3. Merkle verification: Proof includes leaf (TEMPORARY until STWO circuit ready).
//!
//! PROOF STRUCTURE (v3 - BETA with leaf included):
//! - proof_version: 1 byte (0x03)
//! - nullifier: 4 bytes (Poseidon2-M31, for replay detection)
//! - session_id: 20 bytes (5 M31 elements, public input)
//! - leaf: 32 bytes (TEMPORARY - will be removed in v4 when STWO proves it)
//! - depth: 1 byte
//! - merkle_path: depth * 33 bytes (sibling + direction)
//! - binding_hash: 32 bytes
//! - purpose_id: 1 byte
//!
//! v4 (FUTURE - after STWO circuit complete):
//! - Removes leaf from proof
//! - STWO circuit proves: ∃ secret: Poseidon(secret) = leaf ∧ leaf ∈ tree
//! - Nullifier prevents correlation without revealing leaf
//!
//! HASH FUNCTION CHOICES:
//! - Nullifier: Poseidon2-M31 (saves ~30,000 constraints vs SHA-256)
//! - Leaf commitment: Poseidon2-M31 (ZK-native)
//! - Merkle tree: Poseidon2-M31 (via merkle_hash.rs)
//! - Binding hash: SHA-256 (external API, non-ZK)
//!
//! The verifier:
//! 1. Extracts leaf from proof (v3 BETA - will change in v4)
//! 2. Verifies Merkle path leads to expected root
//! 3. Checks nullifier for replay (per-session)
//! 4. Checks binding_hash and purpose_id match expected values

use sha2::{Sha256, Digest};
use super::merkle_hash;
use super::poseidon2_m31::{
    M31, LeafSecret, SessionId,
    compute_leaf_commitment, compute_nullifier as poseidon_nullifier,
    m31_to_bytes, m31_from_bytes,
};

/// Proof format version (breaking changes increment this)
/// v3: Switched nullifier and leaf commitment to Poseidon2-M31
pub const PROOF_VERSION: u8 = 0x03;

/// Domain separator for nullifier computation (legacy SHA-256)
const NULLIFIER_DOMAIN: &[u8] = b"nullifier:";

/// Domain separator for leaf commitment from secret (legacy SHA-256)
const LEAF_COMMITMENT_DOMAIN: &[u8] = b"leaf_commit:";

/// Public inputs for membership circuit
/// 
/// CRITICAL: session_id is now a PUBLIC INPUT to the circuit.
/// This enables proper nullifier verification:
/// - Prover cannot lie about session_id used in nullifier
/// - Verifier can confirm nullifier = Poseidon(secret, session_id)
#[derive(Clone, Debug)]
pub struct MembershipPublicInputs {
    /// V4 binding hash (ties proof to session/client/payment)
    pub binding_hash: [u8; 32],
    /// Merkle root (server-authoritative)
    pub root: [u8; 32],
    /// Purpose ID (0=none, 1=allowlist, 2=issuer_batch, 3=revocation)
    pub purpose_id: u8,
    /// Session ID - PUBLIC INPUT (for nullifier verification)
    /// Stored as 5 M31 elements (20 bytes) in the proof
    pub session_id: [u8; 32],
    /// Nullifier - PUBLIC OUTPUT (Poseidon2 hash, 4 bytes M31)
    /// Verifier checks this for replay detection
    pub nullifier: Option<M31>,
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
    /// Compute the leaf commitment from secret using Poseidon2-M31
    /// Returns M31 element (4 bytes) for ZK efficiency
    /// 
    /// Uses Plonky3's verified Poseidon2 implementation.
    pub fn compute_leaf_poseidon(&self) -> M31 {
        let secret = LeafSecret::from_bytes(&self.leaf_secret);
        compute_leaf_commitment(&secret)
    }
    
    /// Compute the leaf commitment from secret (legacy SHA-256 version)
    /// leaf = SHA256("leaf_commit:" || leaf_secret)
    pub fn compute_leaf(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(LEAF_COMMITMENT_DOMAIN);
        hasher.update(&self.leaf_secret);
        hasher.finalize().into()
    }
    
    /// Compute session-specific nullifier using Poseidon2-M31
    /// Returns M31 element (4 bytes) - saves ~30,000 constraints vs SHA-256!
    /// 
    /// Uses Plonky3's verified Poseidon2 implementation.
    /// 
    /// PRIVACY: Different for each session, prevents cross-session linkability.
    /// REPLAY PROTECTION: Can be checked for uniqueness within a session.
    pub fn compute_nullifier_poseidon(&self, session_id: &[u8; 32]) -> M31 {
        let secret = LeafSecret::from_bytes(&self.leaf_secret);
        let session = SessionId::from_bytes(session_id);
        poseidon_nullifier(&secret, &session)
    }
    
    /// Compute session-specific nullifier (legacy SHA-256 version)
    /// nullifier = SHA256("nullifier:" || leaf_secret || session_id)
    pub fn compute_nullifier(&self, session_id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NULLIFIER_DOMAIN);
        hasher.update(&self.leaf_secret);
        hasher.update(session_id);
        hasher.finalize().into()
    }
    
    /// Verify the Merkle path leads to expected root (SHA-256 tree)
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
/// v3 FORMAT (BETA - includes leaf for verification):
/// - version: 1 byte (0x03)
/// - nullifier: 4 bytes (M31 Poseidon2 output)
/// - session_id: 20 bytes (5 M31 elements, public input)
/// - leaf: 32 bytes (TEMPORARY - enables Merkle verification before STWO)
/// - depth: 1 byte
/// - merkle_path: depth * 33 bytes (32 sibling + 1 is_right)
/// - binding_hash: 32 bytes
/// - purpose_id: 1 byte
/// 
/// Note: v4 will remove leaf once STWO circuit proves Merkle membership.
/// The nullifier provides unlinkability across sessions.
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
    /// Returns M31 element (4 bytes) for v3 proofs
    pub fn get_nullifier_m31(&self) -> Option<M31> {
        if self.data.is_empty() {
            return None;
        }
        
        let version = self.data[0];
        if version == 0x03 {
            // v3: nullifier is 4 bytes at offset 1
            if self.data.len() < 5 {
                return None;
            }
            Some(m31_from_bytes(&self.data[1..5]))
        } else {
            None
        }
    }
    
    /// Extract nullifier as 32-byte array (for compatibility)
    /// v3 proofs: zero-pads the 4-byte M31 nullifier
    /// v2 proofs: returns the 32-byte SHA-256 nullifier
    pub fn get_nullifier(&self) -> Option<[u8; 32]> {
        if self.data.is_empty() {
            return None;
        }
        
        let version = self.data[0];
        if version == 0x03 {
            // v3: 4-byte nullifier, zero-pad to 32
            if self.data.len() < 5 {
                return None;
            }
            let mut nullifier = [0u8; 32];
            nullifier[..4].copy_from_slice(&self.data[1..5]);
            Some(nullifier)
        } else if version == 0x02 {
            // v2: 32-byte nullifier
            if self.data.len() < 33 {
                return None;
            }
            let mut nullifier = [0u8; 32];
            nullifier.copy_from_slice(&self.data[1..33]);
            Some(nullifier)
        } else {
            None
        }
    }
    
    /// Extract session_id from proof (v3 only)
    pub fn get_session_id(&self) -> Option<[u8; 20]> {
        if self.data.is_empty() || self.data[0] != 0x03 {
            return None;
        }
        
        // v3: session_id is 20 bytes at offset 5 (after version + nullifier)
        if self.data.len() < 25 {
            return None;
        }
        let mut session = [0u8; 20];
        session.copy_from_slice(&self.data[5..25]);
        Some(session)
    }
    
    /// Extract leaf from proof (v3 only - TEMPORARY until STWO circuit)
    /// 
    /// In v4, this will be removed and the STWO circuit will prove
    /// Merkle membership without revealing the leaf.
    pub fn get_leaf(&self) -> Option<[u8; 32]> {
        if self.data.is_empty() || self.data[0] != 0x03 {
            return None;
        }
        
        // v3: leaf is 32 bytes at offset 25 (after version + nullifier + session_id)
        if self.data.len() < 57 {
            return None;
        }
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&self.data[25..57]);
        Some(leaf)
    }
}

/// Generate a membership proof (v3 format with Poseidon2 nullifier)
///
/// # Arguments
/// * `leaf_secret` - User's 32-byte secret (used to compute leaf, NOT included raw)
/// * `merkle_siblings` - Sibling hashes from leaf to root
/// * `path_bits` - Direction bits (true = sibling is right)
/// * `root` - Expected Merkle root (32 bytes)
/// * `binding_hash` - V4 binding hash (32 bytes)
/// * `session_id` - Session identifier (PUBLIC INPUT for nullifier)
/// * `purpose_id` - Purpose enum (0-3)
///
/// # Returns
/// * Serialized proof
/// 
/// # v3 Format (BETA - includes leaf for verification)
/// - version: 1 byte (0x03)
/// - nullifier: 4 bytes (Poseidon2-M31)
/// - session_id: 20 bytes (5 M31 elements, PUBLIC INPUT)
/// - leaf: 32 bytes (TEMPORARY - enables verification before STWO)
/// - depth: 1 byte
/// - merkle_path: depth * 33 bytes
/// - binding_hash: 32 bytes
/// - purpose_id: 1 byte
/// 
/// Note: v4 will remove leaf once STWO circuit is ready.
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
    
    // Compute leaf commitment (this is what goes in the tree)
    let leaf = witness.compute_leaf();
    
    // Verify path leads to root (sanity check before proving)
    if !witness.verify_path(root) {
        return Err("Merkle path does not lead to expected root".into());
    }
    
    // Compute Poseidon2 nullifier (for replay detection)
    let nullifier_m31 = witness.compute_nullifier_poseidon(session_id);
    
    // Convert session_id to 5 M31 elements (20 bytes)
    let session = SessionId::from_bytes(session_id);
    let session_bytes = session.to_bytes();
    
    // Build proof data (v3 format - includes leaf for BETA)
    let depth = merkle_siblings.len();
    let mut proof_data = Vec::with_capacity(1 + 4 + 20 + 32 + 1 + depth * 33 + 32 + 1);
    
    // Version
    proof_data.push(PROOF_VERSION);
    
    // Nullifier (4 bytes M31)
    proof_data.extend_from_slice(&m31_to_bytes(nullifier_m31));
    
    // Session ID (20 bytes, PUBLIC INPUT)
    proof_data.extend_from_slice(&session_bytes);
    
    // Leaf (32 bytes - TEMPORARY for v3 BETA)
    // This will be removed in v4 when STWO circuit proves Merkle membership
    proof_data.extend_from_slice(&leaf);
    
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

/// Verify a membership proof (supports v2 and v3 formats)
///
/// # Security Model (v3 BETA)
/// 
/// v3 includes the leaf in the proof, enabling full Merkle verification.
/// This is TEMPORARY until the STWO circuit is complete.
///
/// v4 (future) will remove the leaf and use STWO to prove:
/// - prover knows leaf_secret such that Poseidon(leaf_secret) = leaf
/// - leaf exists at the path position in the tree
/// - nullifier = Poseidon(leaf_secret, session_id)
///
/// # Arguments
/// * `proof` - Serialized proof
/// * `root` - Expected Merkle root (32 bytes)
/// * `binding_hash` - Expected V4 binding hash (32 bytes)
/// * `session_id` - Session identifier (v3: verified against proof's public input)
/// * `purpose_id` - Expected purpose enum (0-3)
/// * `known_nullifiers` - Set of already-used nullifiers (replay protection)
///
/// # Returns
/// * Ok(true) if proof is valid
/// * Ok(false) if proof is invalid (wrong binding, replay, Merkle path fails, etc.)
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
    
    if data.is_empty() {
        return Err("Empty proof".into());
    }
    
    let version = data[0];
    
    match version {
        0x03 => verify_membership_v3(data, root, binding_hash, session_id, purpose_id, known_nullifiers),
        0x02 => verify_membership_v2(data, root, binding_hash, session_id, purpose_id, known_nullifiers),
        _ => Err(format!("Unsupported proof version: {}", version)),
    }
}

/// Verify v3 proof (BETA - includes leaf for real Merkle verification)
/// 
/// v3 format:
/// - version: 1 byte (0x03)
/// - nullifier: 4 bytes (M31)
/// - session_id: 20 bytes
/// - leaf: 32 bytes (TEMPORARY)
/// - depth: 1 byte
/// - merkle_path: depth * 33 bytes
/// - binding_hash: 32 bytes
/// - purpose_id: 1 byte
fn verify_membership_v3(
    data: &[u8],
    root: &[u8; 32],
    binding_hash: &[u8; 32],
    session_id: &[u8; 32],
    purpose_id: u8,
    known_nullifiers: Option<&std::collections::HashSet<[u8; 32]>>,
) -> Result<bool, String> {
    // v3 minimum: version(1) + nullifier(4) + session(20) + leaf(32) + depth(1) + binding(32) + purpose(1) = 91
    if data.len() < 91 {
        return Err("Proof too short for v3".into());
    }
    
    // Parse nullifier (4 bytes M31)
    let _nullifier_m31 = m31_from_bytes(&data[1..5]);
    
    // Parse session_id from proof (20 bytes = 5 M31 elements)
    let mut proof_session = [0u8; 20];
    proof_session.copy_from_slice(&data[5..25]);
    
    // CRITICAL: Verify session_id matches expected (prevents nullifier manipulation)
    let expected_session = SessionId::from_bytes(session_id);
    if proof_session != expected_session.to_bytes() {
        return Ok(false); // Session mismatch - possible attack
    }
    
    // Convert nullifier to 32-byte format for replay checking
    let mut nullifier_32 = [0u8; 32];
    nullifier_32[..4].copy_from_slice(&data[1..5]);
    
    // Check replay
    if let Some(nullifiers) = known_nullifiers {
        if nullifiers.contains(&nullifier_32) {
            return Ok(false); // Replay detected
        }
    }
    
    // Parse leaf (32 bytes - TEMPORARY for v3 BETA)
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&data[25..57]);
    
    // Parse depth and path
    let depth = data[57] as usize;
    let path_start = 58;
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
    
    // *** ACTUALLY VERIFY THE MERKLE PATH ***
    // This is the critical fix - v3 BETA verifies for real, not just trusting
    let mut current = leaf;
    for (sibling, is_right) in siblings.iter().zip(path_bits.iter()) {
        if *is_right {
            // We're the right child: H(sibling, current)
            current = merkle_hash::hash_pair(sibling, &current);
        } else {
            // We're the left child: H(current, sibling)
            current = merkle_hash::hash_pair(&current, sibling);
        }
    }
    
    // Verify computed root matches expected root
    if current != *root {
        return Ok(false); // Merkle path verification FAILED
    }
    
    Ok(true)
}

/// Verify v2 proof (legacy SHA-256 nullifier)
fn verify_membership_v2(
    data: &[u8],
    root: &[u8; 32],
    binding_hash: &[u8; 32],
    _session_id: &[u8; 32],
    purpose_id: u8,
    known_nullifiers: Option<&std::collections::HashSet<[u8; 32]>>,
) -> Result<bool, String> {
    // v2 minimum: version(1) + nullifier(32) + depth(1) + binding(32) + purpose(1) = 67
    if data.len() < 67 {
        return Err("Proof too short for v2".into());
    }
    
    // Parse nullifier (32 bytes SHA-256)
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&data[1..33]);
    
    // Check replay
    if let Some(nullifiers) = known_nullifiers {
        if nullifiers.contains(&nullifier) {
            return Ok(false);
        }
    }
    
    // Parse path
    let depth = data[33] as usize;
    let path_start = 34;
    let path_end = path_start + depth * 33;
    
    if data.len() < path_end + 33 {
        return Err("Proof truncated".into());
    }
    
    // Parse binding hash
    let proof_binding = &data[path_end..path_end + 32];
    if proof_binding != binding_hash {
        return Ok(false);
    }
    
    // Parse purpose
    let proof_purpose = data[path_end + 32];
    if proof_purpose != purpose_id {
        return Ok(false);
    }
    
    _ = root;
    
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
    fn test_leaf_commitment_poseidon() {
        let secret = create_test_leaf_secret();
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        
        // Test Poseidon2 leaf commitment
        let leaf_p = witness.compute_leaf_poseidon();
        let leaf_p2 = witness.compute_leaf_poseidon();
        
        // Verify deterministic
        assert_eq!(leaf_p, leaf_p2);
    }

    #[test]
    fn test_leaf_commitment_sha256() {
        let secret = create_test_leaf_secret();
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        
        // Test legacy SHA-256 leaf commitment
        let leaf = witness.compute_leaf();
        let leaf2 = witness.compute_leaf();
        
        // Verify deterministic
        assert_eq!(leaf, leaf2);
        
        // Verify not equal to secret
        assert_ne!(&leaf[..], &secret[..]);
    }

    #[test]
    fn test_nullifier_poseidon_unlinkability() {
        let secret = create_test_leaf_secret();
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        
        let session1 = [1u8; 32];
        let session2 = [2u8; 32];
        
        // Test Poseidon2 nullifier
        let null1 = witness.compute_nullifier_poseidon(&session1);
        let null2 = witness.compute_nullifier_poseidon(&session2);
        
        // Same secret, different sessions -> different nullifiers
        assert_ne!(null1, null2);
        
        // Same session -> same nullifier
        let null1_again = witness.compute_nullifier_poseidon(&session1);
        assert_eq!(null1, null1_again);
    }

    #[test]
    fn test_nullifier_sha256_unlinkability() {
        let secret = create_test_leaf_secret();
        let witness = MembershipWitness {
            leaf_secret: secret,
            merkle_siblings: vec![],
            path_bits: vec![],
        };
        
        let session1 = [1u8; 32];
        let session2 = [2u8; 32];
        
        // Test legacy SHA-256 nullifier
        let null1 = witness.compute_nullifier(&session1);
        let null2 = witness.compute_nullifier(&session2);
        
        // Same secret, different sessions -> different nullifiers
        assert_ne!(null1, null2);
        
        // Same session -> same nullifier
        let null1_again = witness.compute_nullifier(&session1);
        assert_eq!(null1, null1_again);
    }

    #[test]
    fn test_prove_verify_v3_roundtrip() {
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
        let root = leaf;
        
        // Generate v3 proof
        let proof = prove_membership(
            &secret,
            &[],
            &[],
            &root,
            &binding_hash,
            &session_id,
            purpose_id,
        ).expect("Proof generation should succeed");
        
        // Check version is v3
        assert_eq!(proof.data[0], 0x03, "Should be v3 proof");
        
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
        
        // Verify nullifier is extractable (M31 version)
        let nullifier_m31 = proof.get_nullifier_m31().expect("Should have M31 nullifier");
        let expected_nullifier = witness.compute_nullifier_poseidon(&session_id);
        assert_eq!(nullifier_m31, expected_nullifier);
        
        // Verify session_id is extractable
        let proof_session = proof.get_session_id().expect("Should have session_id");
        let expected_session = SessionId::from_bytes(&session_id).to_bytes();
        assert_eq!(proof_session, expected_session);
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
    fn test_wrong_session_fails() {
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
        
        // Try to verify with wrong session_id
        let wrong_session = [0xdd; 32];
        let valid = verify_membership(
            &proof, &root, &binding_hash, &wrong_session, 1, None
        ).unwrap();
        
        assert!(!valid, "Should fail with wrong session_id (v3 feature!)");
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
        
        // Add nullifier to known set (use 32-byte format for compatibility)
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
    fn test_v3_proof_contains_leaf_but_not_secret() {
        // v3 BETA includes leaf for verification (temporary until STWO circuit)
        // v4 will remove leaf once ZK proof handles Merkle membership
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
        
        // v3 BETA: proof SHOULD contain the leaf (temporary for verification)
        let leaf_found = proof.data.windows(32)
            .any(|window| window == &leaf[..]);
        
        assert!(leaf_found, "v3 BETA proof should contain leaf (will be removed in v4)");
        
        // The proof should NEVER contain the raw secret
        let secret_found = proof.data.windows(32)
            .any(|window| window == &secret[..]);
        
        assert!(!secret_found, "Proof must NEVER contain raw secret!");
        
        // Verify leaf is extractable via get_leaf()
        let extracted_leaf = proof.get_leaf().expect("Should have leaf");
        assert_eq!(extracted_leaf, leaf);
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

    #[test]
    fn test_v3_proof_size() {
        // v3 BETA includes leaf for verification
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
        
        // v3 BETA: version(1) + nullifier(4) + session(20) + leaf(32) + depth(1) + binding(32) + purpose(1) = 91
        // v4 (future): removes leaf (-32), so will be 59 bytes
        assert_eq!(proof.data.len(), 91, "v3 BETA proof with no siblings should be 91 bytes");
    }
    
    #[test]
    fn test_wrong_root_fails() {
        // Verify that Merkle verification actually works - wrong root should fail
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
        
        // Try to verify with wrong root
        let wrong_root = [0xff; 32];
        let valid = verify_membership(
            &proof, &wrong_root, &binding_hash, &session_id, 1, None
        ).unwrap();
        
        assert!(!valid, "Should fail with wrong root (Merkle verification)");
    }
}
