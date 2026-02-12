//! Merkle Tree Implementation
//!
//! Provides:
//! - Merkle tree construction from leaves
//! - Path generation for membership proofs
//! - Path verification

use super::poseidon::{poseidon_hash_pair, FieldElement};

/// A sibling in a Merkle path
#[derive(Clone, Debug)]
pub struct PathSibling {
    /// The sibling hash
    pub hash: FieldElement,
    /// True if sibling is on the right (current node is left)
    pub is_right: bool,
}

/// A complete Merkle path from leaf to root
#[derive(Clone, Debug)]
pub struct MerklePath {
    pub siblings: Vec<PathSibling>,
}

impl MerklePath {
    /// Create an empty path
    pub fn new() -> Self {
        Self { siblings: Vec::new() }
    }
    
    /// Compute root from leaf and path
    pub fn compute_root(&self, leaf: &FieldElement) -> FieldElement {
        let mut current = *leaf;
        
        for sibling in &self.siblings {
            if sibling.is_right {
                // sibling is on the right: H(current, sibling)
                current = poseidon_hash_pair(&current, &sibling.hash);
            } else {
                // sibling is on the left: H(sibling, current)
                current = poseidon_hash_pair(&sibling.hash, &current);
            }
        }
        
        current
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.siblings.len() as u8);
        
        for sibling in &self.siblings {
            out.extend_from_slice(&sibling.hash.to_bytes_be());
            out.push(if sibling.is_right { 1 } else { 0 });
        }
        
        out
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("empty path data");
        }
        
        let count = data[0] as usize;
        let mut offset = 1;
        let mut siblings = Vec::with_capacity(count);
        
        for _ in 0..count {
            if offset + 33 > data.len() {
                return Err("truncated path data");
            }
            
            let hash = FieldElement::from_bytes_be(&data[offset..offset + 32]);
            let is_right = data[offset + 32] != 0;
            
            siblings.push(PathSibling { hash, is_right });
            offset += 33;
        }
        
        Ok(Self { siblings })
    }
    
    /// Get the depth (number of levels)
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

impl Default for MerklePath {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a Merkle path
pub fn verify_merkle_path(
    leaf: &FieldElement,
    path: &MerklePath,
    expected_root: &FieldElement,
) -> bool {
    let computed_root = path.compute_root(leaf);
    computed_root == *expected_root
}

/// A Merkle tree built from leaves
pub struct MerkleTree {
    pub leaves: Vec<FieldElement>,
    pub root: FieldElement,
    layers: Vec<Vec<FieldElement>>,
}

impl MerkleTree {
    /// Build tree from leaf values (pads to next power of 2)
    pub fn new(leaves: Vec<FieldElement>) -> Self {
        let size = leaves.len().next_power_of_two();
        Self::with_size(leaves, size)
    }
    
    /// Build tree with specific depth (pads to 2^depth leaves)
    pub fn with_depth(leaves: Vec<FieldElement>, depth: usize) -> Self {
        let size = 1usize << depth;
        Self::with_size(leaves, size)
    }
    
    /// Build tree with specific target size
    fn with_size(leaves: Vec<FieldElement>, target_size: usize) -> Self {
        assert!(!leaves.is_empty(), "cannot build empty tree");
        assert!(leaves.len() <= target_size, "too many leaves for target size");
        
        // Pad to target size
        let mut padded = leaves.clone();
        padded.resize(target_size, FieldElement::ZERO);
        
        // Build layers bottom-up
        let mut layers = vec![padded];
        
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity(prev.len() / 2);
            
            for chunk in prev.chunks(2) {
                next.push(poseidon_hash_pair(&chunk[0], &chunk[1]));
            }
            
            layers.push(next);
        }
        
        let root = layers.last().unwrap()[0];
        
        Self { leaves, root, layers }
    }
    
    /// Get path for leaf at index
    pub fn get_path(&self, index: usize) -> MerklePath {
        let mut siblings = Vec::new();
        let mut idx = index;
        
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let is_right = idx % 2 == 0;
            
            siblings.push(PathSibling {
                hash: layer.get(sibling_idx).copied().unwrap_or(FieldElement::ZERO),
                is_right,
            });
            
            idx /= 2;
        }
        
        MerklePath { siblings }
    }
    
    /// Get the tree depth
    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }
    
    /// Get the number of leaves (including padding)
    pub fn padded_size(&self) -> usize {
        self.layers[0].len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaf = FieldElement::from_u64(42);
        let tree = MerkleTree::new(vec![leaf]);
        
        // Single leaf tree should have root = H(leaf, 0)
        let path = tree.get_path(0);
        assert!(verify_merkle_path(&leaf, &path, &tree.root));
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        let a = FieldElement::from_u64(1);
        let b = FieldElement::from_u64(2);
        let tree = MerkleTree::new(vec![a, b]);
        
        // Verify both paths
        let path_a = tree.get_path(0);
        let path_b = tree.get_path(1);
        
        assert!(verify_merkle_path(&a, &path_a, &tree.root));
        assert!(verify_merkle_path(&b, &path_b, &tree.root));
    }

    #[test]
    fn test_merkle_tree_round_trip() {
        let leaves: Vec<_> = (0..8)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();
        
        let tree = MerkleTree::new(leaves.clone());
        
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.get_path(i);
            assert!(
                verify_merkle_path(leaf, &path, &tree.root),
                "Failed for leaf {}", i
            );
        }
    }

    #[test]
    fn test_merkle_path_serialization() {
        let leaves: Vec<_> = (0..4)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();
        
        let tree = MerkleTree::new(leaves);
        let path = tree.get_path(0);
        
        let bytes = path.to_bytes();
        let restored = MerklePath::from_bytes(&bytes).unwrap();
        
        assert_eq!(path.siblings.len(), restored.siblings.len());
        for (a, b) in path.siblings.iter().zip(restored.siblings.iter()) {
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.is_right, b.is_right);
        }
    }

    #[test]
    fn test_wrong_leaf_fails() {
        let leaves: Vec<_> = (0..4)
            .map(|i| FieldElement::from_u64(i as u64))
            .collect();
        
        let tree = MerkleTree::new(leaves);
        let path = tree.get_path(0);
        
        // Try to verify with wrong leaf
        let wrong_leaf = FieldElement::from_u64(999);
        assert!(!verify_merkle_path(&wrong_leaf, &path, &tree.root));
    }

    #[test]
    fn test_witness_spec_vector() {
        // Canonical test vector for WITNESS_SPEC.md
        // 2 leaves padded to depth 20
        
        let leaf_0 = FieldElement::from_u64(1);
        let leaf_1 = FieldElement::from_u64(2);
        
        let tree = MerkleTree::new(vec![leaf_0, leaf_1]);
        let path = tree.get_path(0);
        
        println!("\n=== WITNESS_SPEC Test Vector ===");
        println!("leaf_0: 0x{:064x}", leaf_0.to_bytes_be().iter().fold(0u128, |acc, &b| (acc << 8) | b as u128));
        println!("leaf_1: 0x{:064x}", leaf_1.to_bytes_be().iter().fold(0u128, |acc, &b| (acc << 8) | b as u128));
        println!("root: 0x{:064x}", tree.root.to_bytes_be().iter().fold(0u128, |acc, &b| (acc << 8) | b as u128));
        println!("depth: {}", path.siblings.len());
        
        println!("\nsiblings (leaf→root):");
        for (i, s) in path.siblings.iter().enumerate() {
            let bytes = s.hash.to_bytes_be();
            print!("  [{}]: 0x", i);
            for b in &bytes { print!("{:02x}", b); }
            println!(" (is_right={})", s.is_right as u8);
        }
        
        println!("\npath_bits: {:?}", 
            path.siblings.iter().map(|s| s.is_right as u8).collect::<Vec<_>>()
        );
        
        // Verify
        assert!(verify_merkle_path(&leaf_0, &path, &tree.root));
        println!("\n✓ Verification passed");
    }
}
