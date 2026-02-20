//! Merkle Tree Hash Implementation using Poseidon2-M31
//!
//! This module provides the Merkle tree operations used by:
//! - Rust native library (direct calls)
//! - Python API server (via poseidon_hash CLI)
//! - Verifier binary (direct calls)
//!
//! ⚠️  ALL HASHING USES POSEIDON2-M31 FROM poseidon2_m31.rs ⚠️
//! This is the single source of truth. Do not implement hashing here.
//!
//! # API Layers
//!
//! ## Native M31 API (preferred for new code)
//! - `hash_pair_m31(left: M31, right: M31) -> M31`
//! - `build_tree_m31(leaves: &[M31]) -> M31`
//! - `verify_proof_m31(...) -> bool`
//!
//! ## Byte Array API (compatibility layer)
//! - `hash_pair(&[u8; 32], &[u8; 32]) -> [u8; 32]`
//! - `build_tree(&[[u8; 32]]) -> [u8; 32]`
//! - `verify_proof(...) -> bool`
//!
//! The byte array API converts to/from M31 internally.
//! M31 values are stored in the first 4 bytes (big-endian), rest is zero.

use super::poseidon2_m31::{
    M31, poseidon2_hash_pair, build_merkle_tree, verify_merkle_proof,
    get_merkle_path, m31_to_bytes, m31_from_bytes,
    LeafSecret, compute_leaf_commitment,
};

// =============================================================================
// Native M31 API (preferred)
// =============================================================================

/// Hash two M31 children to create a parent node
///
/// Uses Poseidon2 with MERKLE domain separator.
/// This is the native, efficient API.
#[inline]
pub fn hash_pair_m31(left: M31, right: M31) -> M31 {
    poseidon2_hash_pair(left, right)
}

/// Build a Merkle tree from M31 leaves, return root
///
/// Pads to power of 2 with M31::ZERO.
#[inline]
pub fn build_tree_m31(leaves: &[M31]) -> M31 {
    build_merkle_tree(leaves)
}

/// Verify a Merkle proof with M31 values
#[inline]
pub fn verify_proof_m31(
    leaf: M31,
    siblings: &[M31],
    path_bits: &[bool],
    root: M31,
) -> bool {
    verify_merkle_proof(leaf, siblings, path_bits, root)
}

/// Get Merkle path for a leaf at given index
#[inline]
pub fn get_path_m31(leaves: &[M31], index: usize) -> (Vec<M31>, Vec<bool>) {
    get_merkle_path(leaves, index)
}

/// Compute leaf commitment from secret bytes
/// 
/// Input: 32-byte secret
/// Output: M31 leaf commitment
#[inline]
pub fn leaf_commitment_m31(secret: &[u8; 32]) -> M31 {
    let leaf_secret = LeafSecret::from_bytes(secret);
    compute_leaf_commitment(&leaf_secret)
}

// =============================================================================
// Byte Array API (compatibility layer)
// =============================================================================

/// Convert [u8; 32] to M31 (uses first 4 bytes)
fn bytes32_to_m31(bytes: &[u8; 32]) -> M31 {
    m31_from_bytes(&bytes[..4])
}

/// Convert M31 to [u8; 32] (zero-pads remaining 28 bytes)
fn m31_to_bytes32(val: M31) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[..4].copy_from_slice(&m31_to_bytes(val));
    result
}

/// Hash two children to create a parent node (byte array API)
/// 
/// ⚠️  Converts [u8; 32] → M31 → Poseidon2 → M31 → [u8; 32]
/// Only the first 4 bytes of input are used (M31 = 31 bits).
/// Output has hash in first 4 bytes, remaining 28 bytes are zero.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let left_m31 = bytes32_to_m31(left);
    let right_m31 = bytes32_to_m31(right);
    let result = hash_pair_m31(left_m31, right_m31);
    m31_to_bytes32(result)
}

/// Hash a leaf value to create leaf commitment (byte array API)
///
/// ⚠️  This computes a Poseidon2 leaf commitment, NOT a raw hash.
/// Input: 32-byte leaf secret
/// Output: Leaf commitment (M31 in first 4 bytes, zero-padded)
pub fn hash_leaf(value: &[u8; 32]) -> [u8; 32] {
    let commitment = leaf_commitment_m31(value);
    m31_to_bytes32(commitment)
}

/// Verify a Merkle proof (byte array API)
///
/// ⚠️  Converts all inputs to M31 internally.
/// `leaf_index` determines path direction bits.
pub fn verify_proof(
    leaf: &[u8; 32],
    leaf_index: usize,
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    let leaf_m31 = bytes32_to_m31(leaf);
    let root_m31 = bytes32_to_m31(root);
    
    // Convert siblings and compute path bits from index
    let siblings_m31: Vec<M31> = siblings.iter().map(bytes32_to_m31).collect();
    let mut path_bits = Vec::with_capacity(siblings.len());
    let mut idx = leaf_index;
    for _ in 0..siblings.len() {
        path_bits.push(idx % 2 == 1); // true if we're right child
        idx /= 2;
    }
    
    verify_proof_m31(leaf_m31, &siblings_m31, &path_bits, root_m31)
}

/// Build a Merkle tree from leaves and return the root (byte array API)
///
/// ⚠️  Converts all leaves to M31 internally.
/// Root is returned as M31 in first 4 bytes, zero-padded.
pub fn build_tree(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    
    let leaves_m31: Vec<M31> = leaves.iter().map(bytes32_to_m31).collect();
    let root = build_tree_m31(&leaves_m31);
    m31_to_bytes32(root)
}

/// Get Merkle path for a leaf (byte array API)
///
/// Returns (siblings, path_bits) where path_bits[i] = true means
/// we're the right child at level i.
pub fn get_path(leaves: &[[u8; 32]], index: usize) -> (Vec<[u8; 32]>, Vec<bool>) {
    let leaves_m31: Vec<M31> = leaves.iter().map(bytes32_to_m31).collect();
    let (siblings_m31, path_bits) = get_path_m31(&leaves_m31, index);
    let siblings: Vec<[u8; 32]> = siblings_m31.iter().map(|m| m31_to_bytes32(*m)).collect();
    (siblings, path_bits)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use p3_mersenne_31::Mersenne31;
    
    #[test]
    fn test_hash_pair_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        
        let h1 = hash_pair(&left, &right);
        let h2 = hash_pair(&left, &right);
        
        assert_eq!(h1, h2);
    }
    
    #[test]
    fn test_hash_pair_order_matters() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        
        let h1 = hash_pair(&a, &b);
        let h2 = hash_pair(&b, &a);
        
        assert_ne!(h1, h2);
    }
    
    #[test]
    fn test_m31_api_matches_byte_api() {
        let a = Mersenne31::from_canonical_u32(12345);
        let b = Mersenne31::from_canonical_u32(67890);
        
        // M31 API
        let result_m31 = hash_pair_m31(a, b);
        
        // Byte API (convert M31 to bytes first)
        let a_bytes = m31_to_bytes32(a);
        let b_bytes = m31_to_bytes32(b);
        let result_bytes = hash_pair(&a_bytes, &b_bytes);
        
        // Should match
        assert_eq!(m31_to_bytes32(result_m31), result_bytes);
    }
    
    #[test]
    fn test_build_tree_single_leaf() {
        let leaf = [42u8; 32];
        let root = build_tree(&[leaf]);
        // Single leaf: root = leaf (no hashing needed)
        // But we convert to M31 and back, so only first 4 bytes matter
        let expected = m31_to_bytes32(bytes32_to_m31(&leaf));
        assert_eq!(root, expected);
    }
    
    #[test]
    fn test_build_tree_two_leaves() {
        let leaves = [[1u8; 32], [2u8; 32]];
        let root = build_tree(&leaves);
        let expected = hash_pair(&leaves[0], &leaves[1]);
        assert_eq!(root, expected);
    }
    
    #[test]
    fn test_verify_proof_basic() {
        // Create 4 leaves
        let leaves: Vec<[u8; 32]> = (1u8..=4).map(|i| {
            let mut arr = [0u8; 32];
            arr[0] = i;
            arr
        }).collect();
        
        let root = build_tree(&leaves);
        
        // Get path for each leaf and verify
        for i in 0..4 {
            let (siblings, _) = get_path(&leaves, i);
            assert!(
                verify_proof(&leaves[i], i, &siblings, &root),
                "Proof for leaf {} should verify", i
            );
        }
    }
    
    #[test]
    fn test_verify_proof_wrong_leaf_fails() {
        let leaves = [[1u8; 32], [2u8; 32]];
        let root = build_tree(&leaves);
        let (siblings, _) = get_path(&leaves, 0);
        
        let wrong_leaf = [99u8; 32];
        assert!(!verify_proof(&wrong_leaf, 0, &siblings, &root));
    }
    
    #[test]
    fn test_m31_tree_operations() {
        // Direct M31 API test
        let leaves: Vec<M31> = (1..=4)
            .map(|i| Mersenne31::from_canonical_u32(i))
            .collect();
        
        let root = build_tree_m31(&leaves);
        
        for (i, leaf) in leaves.iter().enumerate() {
            let (siblings, path_bits) = get_path_m31(&leaves, i);
            assert!(
                verify_proof_m31(*leaf, &siblings, &path_bits, root),
                "M31 proof for leaf {} should verify", i
            );
        }
    }
    
    #[test]
    fn test_hash_leaf_is_commitment() {
        // hash_leaf should compute Poseidon2 leaf commitment
        let secret = [0x42u8; 32];
        
        let commitment_via_hash_leaf = hash_leaf(&secret);
        let commitment_via_direct = m31_to_bytes32(leaf_commitment_m31(&secret));
        
        assert_eq!(commitment_via_hash_leaf, commitment_via_direct);
    }
}
