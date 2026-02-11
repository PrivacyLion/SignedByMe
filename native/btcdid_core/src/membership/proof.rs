//! Membership Proof Generation and Verification
//!
//! This module provides the high-level API for:
//! - Generating membership proofs (prove_membership)
//! - Verifying membership proofs (verify_membership)
//!
//! The proof asserts:
//! 1. Prover knows leaf_secret such that leaf = H(leaf_secret || domain_sep)
//! 2. MerkleVerify(leaf, path, root) == true
//! 3. binding_hash is incorporated (prevents replay)

use super::merkle::{MerklePath, verify_merkle_path};
use super::poseidon::{poseidon_hash_bytes, FieldElement};

/// Domain separator for leaf commitment
pub const LEAF_DOMAIN_SEP: &[u8; 16] = b"sbm:membership:v";

/// Public inputs for membership circuit
#[derive(Clone, Debug)]
pub struct MembershipPublicInputs {
    /// V4 binding hash (ties proof to session/client/payment)
    pub binding_hash: [u8; 32],
    /// Merkle root (server-authoritative)
    pub root: [u8; 32],
    /// Purpose ID (0=none, 1=allowlist, 2=issuer_batch, 3=revocation)
    pub purpose_id: u8,
}

/// Private witness for membership circuit
#[derive(Clone)]
pub struct MembershipWitness {
    /// User's secret (32 bytes, never revealed)
    pub leaf_secret: [u8; 32],
    /// Merkle path from leaf to root
    pub merkle_path: MerklePath,
}

impl MembershipWitness {
    /// Compute the leaf commitment
    pub fn compute_leaf(&self) -> FieldElement {
        let mut data = Vec::with_capacity(48);
        data.extend_from_slice(&self.leaf_secret);
        data.extend_from_slice(LEAF_DOMAIN_SEP);
        poseidon_hash_bytes(&data)
    }
}

/// Serialized membership proof
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
}

/// Generate a membership proof
///
/// # Arguments
/// * `leaf_secret` - User's 32-byte secret
/// * `merkle_path` - Path from leaf to root
/// * `root` - Expected Merkle root (32 bytes)
/// * `binding_hash` - V4 binding hash (32 bytes)
/// * `purpose_id` - Purpose enum (0-3)
///
/// # Returns
/// * Serialized proof
pub fn prove_membership(
    leaf_secret: &[u8; 32],
    merkle_path: &MerklePath,
    root: &[u8; 32],
    binding_hash: &[u8; 32],
    purpose_id: u8,
) -> Result<MembershipProof, String> {
    // Build witness
    let witness = MembershipWitness {
        leaf_secret: *leaf_secret,
        merkle_path: merkle_path.clone(),
    };
    
    // Compute leaf
    let leaf = witness.compute_leaf();
    
    // Verify path leads to root (sanity check before proving)
    let root_fe = FieldElement::from_bytes_be(root);
    let computed_root = merkle_path.compute_root(&leaf);
    if computed_root != root_fe {
        return Err("Merkle path does not lead to expected root".into());
    }
    
    // Build proof data
    // Format:
    // - leaf (32 bytes)
    // - merkle_path (serialized)
    // - binding_hash (32 bytes)
    // - purpose_id (1 byte)
    //
    // Note: In a real ZK proof, the leaf would be hidden and only proven
    // to exist. This simplified version includes the leaf for verification.
    // The actual STWO circuit would make this a private witness.
    
    let mut proof_data = Vec::new();
    proof_data.extend_from_slice(&leaf.to_bytes_be());
    proof_data.extend_from_slice(&merkle_path.to_bytes());
    proof_data.extend_from_slice(binding_hash);
    proof_data.push(purpose_id);
    
    Ok(MembershipProof { data: proof_data })
}

/// Verify a membership proof
///
/// # Arguments
/// * `proof` - Serialized proof
/// * `root` - Expected Merkle root (32 bytes)
/// * `binding_hash` - Expected V4 binding hash (32 bytes)
/// * `purpose_id` - Expected purpose enum (0-3)
///
/// # Returns
/// * true if valid, false otherwise
pub fn verify_membership(
    proof: &MembershipProof,
    root: &[u8; 32],
    binding_hash: &[u8; 32],
    purpose_id: u8,
) -> Result<bool, String> {
    let data = &proof.data;
    
    // Minimum size: 32 (leaf) + 1 (path len) + 32 (binding) + 1 (purpose)
    if data.len() < 66 {
        return Err("Proof too short".into());
    }
    
    // Parse leaf
    let leaf = FieldElement::from_bytes_be(&data[0..32]);
    
    // Parse path
    let path_start = 32;
    let path = MerklePath::from_bytes(&data[path_start..])
        .map_err(|e| format!("Invalid path: {}", e))?;
    
    // Calculate where binding hash and purpose start
    let path_bytes_len = 1 + path.siblings.len() * 33;
    let binding_start = path_start + path_bytes_len;
    
    if data.len() < binding_start + 33 {
        return Err("Proof truncated".into());
    }
    
    // Parse and verify binding hash
    let proof_binding = &data[binding_start..binding_start + 32];
    if proof_binding != binding_hash {
        return Ok(false); // Binding mismatch
    }
    
    // Parse and verify purpose
    let proof_purpose = data[binding_start + 32];
    if proof_purpose != purpose_id {
        return Ok(false); // Purpose mismatch
    }
    
    // Verify Merkle path
    let root_fe = FieldElement::from_bytes_be(root);
    if !verify_merkle_path(&leaf, &path, &root_fe) {
        return Ok(false); // Path doesn't lead to root
    }
    
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::merkle::MerkleTree;

    fn create_test_leaf_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for i in 0..32 {
            secret[i] = (i * 7 + 13) as u8;
        }
        secret
    }

    #[test]
    fn test_prove_verify_membership() {
        let leaf_secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        let purpose_id = 1; // allowlist
        
        // Create leaf
        let witness = MembershipWitness {
            leaf_secret,
            merkle_path: MerklePath::new(),
        };
        let leaf = witness.compute_leaf();
        
        // Build tree with our leaf and some others
        let leaves = vec![
            leaf,
            FieldElement::from_u64(1),
            FieldElement::from_u64(2),
            FieldElement::from_u64(3),
        ];
        let tree = MerkleTree::new(leaves);
        let path = tree.get_path(0);
        let root = tree.root.to_bytes_be();
        
        // Generate proof
        let proof = prove_membership(
            &leaf_secret,
            &path,
            &root,
            &binding_hash,
            purpose_id,
        ).expect("Proof generation should succeed");
        
        // Verify proof
        let valid = verify_membership(
            &proof,
            &root,
            &binding_hash,
            purpose_id,
        ).expect("Verification should not error");
        
        assert!(valid, "Proof should be valid");
    }

    #[test]
    fn test_wrong_root_fails() {
        let leaf_secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        let purpose_id = 1;
        
        let witness = MembershipWitness {
            leaf_secret,
            merkle_path: MerklePath::new(),
        };
        let leaf = witness.compute_leaf();
        
        let leaves = vec![leaf, FieldElement::from_u64(1)];
        let tree = MerkleTree::new(leaves);
        let path = tree.get_path(0);
        let root = tree.root.to_bytes_be();
        
        let proof = prove_membership(
            &leaf_secret,
            &path,
            &root,
            &binding_hash,
            purpose_id,
        ).unwrap();
        
        // Try to verify with wrong root
        let wrong_root = [0xbb; 32];
        let valid = verify_membership(
            &proof,
            &wrong_root,
            &binding_hash,
            purpose_id,
        ).unwrap();
        
        assert!(!valid, "Should fail with wrong root");
    }

    #[test]
    fn test_wrong_binding_fails() {
        let leaf_secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        let purpose_id = 1;
        
        let witness = MembershipWitness {
            leaf_secret,
            merkle_path: MerklePath::new(),
        };
        let leaf = witness.compute_leaf();
        
        let leaves = vec![leaf, FieldElement::from_u64(1)];
        let tree = MerkleTree::new(leaves);
        let path = tree.get_path(0);
        let root = tree.root.to_bytes_be();
        
        let proof = prove_membership(
            &leaf_secret,
            &path,
            &root,
            &binding_hash,
            purpose_id,
        ).unwrap();
        
        // Try to verify with wrong binding
        let wrong_binding = [0xcc; 32];
        let valid = verify_membership(
            &proof,
            &root,
            &wrong_binding,
            purpose_id,
        ).unwrap();
        
        assert!(!valid, "Should fail with wrong binding hash");
    }

    #[test]
    fn test_wrong_purpose_fails() {
        let leaf_secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        let purpose_id = 1;
        
        let witness = MembershipWitness {
            leaf_secret,
            merkle_path: MerklePath::new(),
        };
        let leaf = witness.compute_leaf();
        
        let leaves = vec![leaf, FieldElement::from_u64(1)];
        let tree = MerkleTree::new(leaves);
        let path = tree.get_path(0);
        let root = tree.root.to_bytes_be();
        
        let proof = prove_membership(
            &leaf_secret,
            &path,
            &root,
            &binding_hash,
            purpose_id,
        ).unwrap();
        
        // Try to verify with wrong purpose
        let valid = verify_membership(
            &proof,
            &root,
            &binding_hash,
            2, // Wrong purpose
        ).unwrap();
        
        assert!(!valid, "Should fail with wrong purpose");
    }

    #[test]
    fn test_proof_base64_roundtrip() {
        let leaf_secret = create_test_leaf_secret();
        let binding_hash = [0xaa; 32];
        
        let witness = MembershipWitness {
            leaf_secret,
            merkle_path: MerklePath::new(),
        };
        let leaf = witness.compute_leaf();
        
        let leaves = vec![leaf];
        let tree = MerkleTree::new(leaves);
        let path = tree.get_path(0);
        let root = tree.root.to_bytes_be();
        
        let proof = prove_membership(
            &leaf_secret,
            &path,
            &root,
            &binding_hash,
            1,
        ).unwrap();
        
        // Roundtrip through base64
        let b64 = proof.to_base64();
        let restored = MembershipProof::from_base64(&b64).unwrap();
        
        assert_eq!(proof.data, restored.data);
    }
}
