//! Merkle Tree Hash Implementation
//!
//! Uses SHA-256 for Merkle tree node hashing.
//! 
//! IMPORTANT: We use SHA-256 (not Poseidon) for consistency across:
//! - Rust native library
//! - Python API server
//! - Verifier binary
//!
//! The domain separator "merkle:" ensures these hashes are distinct
//! from other SHA-256 uses in the system.

use sha2::{Digest, Sha256};

/// Domain separator for Merkle tree internal nodes
const MERKLE_DOMAIN: &[u8] = b"merkle:";

/// Domain separator for leaf hashes
const LEAF_DOMAIN: &[u8] = b"leaf:";

/// Hash two children to create a parent node
/// 
/// Uses: SHA256("merkle:" || left || right)
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MERKLE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Hash a leaf value
///
/// Uses: SHA256("leaf:" || value)
pub fn hash_leaf(value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(value);
    hasher.finalize().into()
}

/// Verify a Merkle proof
///
/// Given a leaf, its index, sibling hashes, and expected root,
/// verify the proof is valid.
pub fn verify_proof(
    leaf: &[u8; 32],
    leaf_index: usize,
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    let mut current = *leaf;
    let mut index = leaf_index;
    
    for sibling in siblings {
        current = if index % 2 == 0 {
            // Current is left child
            hash_pair(&current, sibling)
        } else {
            // Current is right child
            hash_pair(sibling, &current)
        };
        index /= 2;
    }
    
    current == *root
}

/// Build a Merkle tree from leaves and return the root
pub fn build_tree(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    
    if leaves.len() == 1 {
        return leaves[0];
    }
    
    // Ensure power of 2
    let mut padded: Vec<[u8; 32]> = leaves.to_vec();
    let mut size = 1;
    while size < padded.len() {
        size *= 2;
    }
    padded.resize(size, [0u8; 32]);
    
    // Build tree bottom-up
    while padded.len() > 1 {
        let mut next_layer = Vec::with_capacity(padded.len() / 2);
        for chunk in padded.chunks(2) {
            next_layer.push(hash_pair(&chunk[0], &chunk[1]));
        }
        padded = next_layer;
    }
    
    padded[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    
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
    fn test_build_tree_single_leaf() {
        let leaf = [42u8; 32];
        let root = build_tree(&[leaf]);
        assert_eq!(root, leaf);
    }
    
    #[test]
    fn test_build_tree_two_leaves() {
        let leaves = [[1u8; 32], [2u8; 32]];
        let root = build_tree(&leaves);
        let expected = hash_pair(&leaves[0], &leaves[1]);
        assert_eq!(root, expected);
    }
    
    #[test]
    fn test_verify_proof() {
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        
        // Build expected structure:
        //        root
        //       /    \
        //     h01    h23
        //    / \    /  \
        //   0   1  2    3
        
        let h01 = hash_pair(&leaves[0], &leaves[1]);
        let h23 = hash_pair(&leaves[2], &leaves[3]);
        let root = hash_pair(&h01, &h23);
        
        // Verify leaf 0 (index 0)
        // siblings: [leaf[1], h23]
        assert!(verify_proof(&leaves[0], 0, &[leaves[1], h23], &root));
        
        // Verify leaf 1 (index 1)
        // siblings: [leaf[0], h23]
        assert!(verify_proof(&leaves[1], 1, &[leaves[0], h23], &root));
        
        // Verify leaf 2 (index 2)
        // siblings: [leaf[3], h01]
        assert!(verify_proof(&leaves[2], 2, &[leaves[3], h01], &root));
        
        // Verify leaf 3 (index 3)
        // siblings: [leaf[2], h01]
        assert!(verify_proof(&leaves[3], 3, &[leaves[2], h01], &root));
    }
    
    #[test]
    fn test_verify_proof_invalid() {
        let leaves = [[1u8; 32], [2u8; 32]];
        let root = hash_pair(&leaves[0], &leaves[1]);
        
        // Wrong leaf
        let wrong_leaf = [99u8; 32];
        assert!(!verify_proof(&wrong_leaf, 0, &[leaves[1]], &root));
        
        // Wrong sibling
        let wrong_sibling = [99u8; 32];
        assert!(!verify_proof(&leaves[0], 0, &[wrong_sibling], &root));
        
        // Wrong root
        let wrong_root = [99u8; 32];
        assert!(!verify_proof(&leaves[0], 0, &[leaves[1]], &wrong_root));
    }
}
