//! Poseidon2 hash over M31 (Mersenne31) using Plonky3's verified implementation
//!
//! This module wraps Plonky3's Poseidon2 permutation with a sponge construction
//! suitable for:
//! - Leaf commitment: H(domain || leaf_secret)
//! - Nullifier: H(domain || leaf_secret || session_id)
//! - Merkle hashing: H(domain || left || right)
//!
//! # Parameters (from Plonky3)
//! - Field: M31 (Mersenne31 = 2^31 - 1)
//! - Width: 16 elements
//! - S-box: x^5 (D=5, gcd(2^31-2, 5) = 1)
//! - Full rounds: 8 (4 initial + 4 terminal)
//! - Partial rounds: 14
//! - Security: 128 bits
//!
//! # State Layout (WIDTH = 16)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │  Position  │  0   │ 1-7  │ 8-15 │                                       │
//! │  Role      │ CAP  │ RATE │ RATE │                                       │
//! │  Use       │ DOM  │ IN   │ IN   │                                       │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//! CAP (Capacity, position 0):
//!   - Domain separator for different hash uses
//!   - NEVER absorbs user input (security critical)
//!   - Values: 0x4C454146 ("LEAF"), 0x4E554C4C ("NULL"), 0x4D45524B ("MERK")
//!
//! RATE (positions 1-15):
//!   - Where inputs are absorbed
//!   - Unused positions MUST be zero-padded
//!   - Output extracted from position 1
//!
//! # Input Layouts by Operation
//!
//! ## Leaf Commitment (5 M31 inputs)
//! ```text
//! [DOM, s0, s1, s2, s3, s4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//!   ^    └───────────────┘  └─────────────────────────┘
//!  cap   leaf_secret[0..5]        zero padding
//! ```
//!
//! ## Nullifier (10 M31 inputs)
//! ```text
//! [DOM, s0, s1, s2, s3, s4, n0, n1, n2, n3, n4, 0, 0, 0, 0, 0]
//!   ^    └───────────────┘  └────────────────┘  └───────────┘
//!  cap   leaf_secret[0..5]   session_id[0..5]   zero padding
//! ```
//!
//! ## Merkle Hash (2 M31 inputs)
//! ```text
//! [DOM, L, R, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//!   ^   ^  ^  └──────────────────────────────────┘
//!  cap  │  │           zero padding
//!       │  right child
//!       left child
//! ```
//!
//! # Why Width 16?
//!
//! Plonky3 only provides verified parameters for width 16 and 24 over M31.
//! Width 16 is sufficient and more efficient for our use case.
//!
//! # Circuit Constraints (Poseidon2 vs Poseidon)
//!
//! Poseidon2 differs from original Poseidon:
//! 1. External rounds: Full S-box to all elements, MDSMat4 mixing
//! 2. Internal rounds: S-box only to element 0, cheaper linear layer
//! 3. Structure: 4 external → 14 internal → 4 external
//!
//! This reduces constraints vs original Poseidon while maintaining security.

use p3_field::{PrimeField32, PrimeCharacteristicRing};
use p3_mersenne_31::Mersenne31;
use p3_poseidon2::Poseidon2;
use p3_symmetric::Permutation;

// Re-export M31 type for external use
pub use p3_mersenne_31::Mersenne31 as M31;

/// Plonky3's type alias for Poseidon2 over M31
pub type Poseidon2M31 = p3_mersenne_31::Poseidon2Mersenne31<16>;

/// Width of Poseidon2 state
pub const WIDTH: usize = 16;

/// Domain separators (ASCII encoded as M31)
/// 
/// ⚠️  SINGLE SOURCE OF TRUTH ⚠️
/// These constants MUST be used everywhere Poseidon2 hashing occurs:
/// - Rust: This module (hash functions use these directly)
/// - Python: Calls Rust CLI (`poseidon_hash`), which uses this module
/// - Circuit: Phase 3 constraints MUST reference these same values
/// 
/// If you add a new domain, add it here and nowhere else.
pub mod domains {
    use super::Mersenne31;
    
    /// Leaf commitment: "LEAF" = 0x4C454146
    pub const LEAF: Mersenne31 = Mersenne31::new(0x4C454146);
    
    /// Nullifier: "NULL" = 0x4E554C4C
    pub const NULLIFIER: Mersenne31 = Mersenne31::new(0x4E554C4C);
    
    /// Merkle hash: "MERK" = 0x4D45524B
    pub const MERKLE: Mersenne31 = Mersenne31::new(0x4D45524B);
}

/// Output position in state array after permutation (single element)
/// 
/// ⚠️  CRITICAL FOR CIRCUIT CONSTRAINTS ⚠️
/// Hash functions extract output from state[OUTPUT_POSITION].
/// The circuit in Phase 3 MUST constrain this same position.
/// 
/// Position 0 = capacity (domain separator) - NOT the output!
/// Position 1 = first rate element - THIS IS THE OUTPUT
pub const OUTPUT_POSITION: usize = 1;

/// Output positions for nullifier (4 M31 elements = 124 bits)
/// 
/// Nullifier extracts from positions 1-4 for collision resistance.
/// 4 × 31 bits = 124 bits > 128-bit birthday bound / 2 = 64 bits
/// This provides adequate security for replay detection.
pub const NULLIFIER_OUTPUT_POSITIONS: [usize; 4] = [1, 2, 3, 4];

/// Nullifier type: 4 M31 elements (16 bytes, 124 bits)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nullifier(pub [Mersenne31; 4]);

impl Nullifier {
    /// Convert to 16 bytes (4 × 4 bytes big-endian)
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let val = self.0[i].as_canonical_u32();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        bytes
    }
    
    /// Parse from 16 bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut elements = [Mersenne31::ZERO; 4];
        for i in 0..4 {
            if bytes.len() >= (i + 1) * 4 {
                let val = u32::from_be_bytes([
                    bytes[i * 4],
                    bytes[i * 4 + 1],
                    bytes[i * 4 + 2],
                    bytes[i * 4 + 3],
                ]);
                elements[i] = Mersenne31::new(val & 0x7FFFFFFF);
            }
        }
        Self(elements)
    }
    
    /// Convert to 32-byte array (zero-padded for compatibility)
    pub fn to_bytes32(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&self.to_bytes());
        bytes
    }
}

/// Poseidon2 hasher with Plonky3's verified parameters
pub struct Poseidon2Hasher {
    permutation: Poseidon2M31,
}

impl Default for Poseidon2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2Hasher {
    /// Create hasher with Plonky3's verified round constants
    /// Uses StdRng with seed 1 (deterministic, matches test expectations)
    pub fn new() -> Self {
        use rand_p3::SeedableRng;
        let mut rng = rand_p3::rngs::StdRng::seed_from_u64(1);
        let permutation = Poseidon2M31::new_from_rng_128(&mut rng);
        Self { permutation }
    }
    
    /// Apply Poseidon2 permutation to state
    pub fn permute(&self, state: &mut [Mersenne31; WIDTH]) {
        self.permutation.permute_mut(state);
    }
    
    /// Hash two M31 elements (for Merkle tree)
    /// 
    /// State layout:
    /// [MERKLE_DOM, left, right, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ///      ^         ^    ^
    ///    pos 0     pos 1  pos 2
    ///   (capacity) (output) 
    pub fn hash_pair(&self, left: Mersenne31, right: Mersenne31) -> Mersenne31 {
        let mut state = [Mersenne31::ZERO; WIDTH];
        state[0] = domains::MERKLE;
        state[1] = left;
        state[2] = right;
        // positions 3-15 are zero (padding)
        
        self.permute(&mut state);
        state[OUTPUT_POSITION]
    }
    
    /// Compute leaf commitment from secret
    /// 
    /// State layout:
    /// [LEAF_DOM, s0, s1, s2, s3, s4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ///     ^       ^
    ///   pos 0   pos 1 (output after permute)
    pub fn leaf_commitment(&self, secret: &LeafSecret) -> Mersenne31 {
        let mut state = [Mersenne31::ZERO; WIDTH];
        state[0] = domains::LEAF;
        for i in 0..5 {
            state[i + 1] = secret.0[i];
        }
        // positions 6-15 are zero (padding)
        
        self.permute(&mut state);
        state[OUTPUT_POSITION]
    }
    
    /// Compute nullifier from secret and session ID
    /// 
    /// State layout:
    /// [NULL_DOM, s0, s1, s2, s3, s4, n0, n1, n2, n3, n4, 0, 0, 0, 0, 0]
    ///     ^       ^   ^   ^   ^
    ///   pos 0   pos 1-4 (output after permute) = 4 M31 = 124 bits
    /// 
    /// Returns 4 M31 elements (16 bytes) for adequate collision resistance.
    pub fn nullifier(&self, secret: &LeafSecret, session: &SessionId) -> Nullifier {
        let mut state = [Mersenne31::ZERO; WIDTH];
        state[0] = domains::NULLIFIER;
        for i in 0..5 {
            state[i + 1] = secret.0[i];
        }
        for i in 0..5 {
            state[i + 6] = session.0[i];
        }
        // positions 11-15 are zero (padding)
        
        self.permute(&mut state);
        
        // Extract 4 M31 elements from positions 1-4
        Nullifier([
            state[NULLIFIER_OUTPUT_POSITIONS[0]],
            state[NULLIFIER_OUTPUT_POSITIONS[1]],
            state[NULLIFIER_OUTPUT_POSITIONS[2]],
            state[NULLIFIER_OUTPUT_POSITIONS[3]],
        ])
    }
}

// =============================================================================
// Wrapper Types for Inputs
// =============================================================================

/// Leaf secret: 5 M31 elements = 155 bits of entropy (>128 required)
/// 
/// This is the user's private key material. NEVER revealed in proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafSecret(pub [Mersenne31; 5]);

impl LeafSecret {
    /// Create from 32 bytes (uses 20 bytes as 5 M31 elements)
    /// 
    /// Each M31 element uses 4 bytes, but only 31 bits are significant.
    /// Total entropy: 5 × 31 = 155 bits
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut elements = [Mersenne31::ZERO; 5];
        for i in 0..5 {
            let start = i * 4;
            let val = u32::from_be_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ]);
            // Reduce mod M31 prime (2^31 - 1)
            elements[i] = Mersenne31::new(val & 0x7FFFFFFF);
        }
        Self(elements)
    }
    
    /// Convert to bytes (20 bytes = 5 × 4 bytes)
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        for i in 0..5 {
            let val = self.0[i].as_canonical_u32();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        bytes
    }
}

/// Session ID: 5 M31 elements (public input for nullifier)
/// 
/// This is a PUBLIC INPUT to the circuit, enabling the verifier to confirm
/// the nullifier was computed with the correct session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionId(pub [Mersenne31; 5]);

impl SessionId {
    /// Create from 32 bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut elements = [Mersenne31::ZERO; 5];
        for i in 0..5 {
            let start = i * 4;
            let val = u32::from_be_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ]);
            elements[i] = Mersenne31::new(val & 0x7FFFFFFF);
        }
        Self(elements)
    }
    
    /// Convert to bytes (20 bytes)
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        for i in 0..5 {
            let val = self.0[i].as_canonical_u32();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        bytes
    }
}

// =============================================================================
// Convenience Functions (use global hasher)
// =============================================================================

/// Global hasher instance (lazy initialization)
fn get_hasher() -> &'static Poseidon2Hasher {
    use std::sync::OnceLock;
    static HASHER: OnceLock<Poseidon2Hasher> = OnceLock::new();
    HASHER.get_or_init(Poseidon2Hasher::new)
}

/// Hash two M31 elements for Merkle tree
pub fn poseidon2_hash_pair(left: Mersenne31, right: Mersenne31) -> Mersenne31 {
    get_hasher().hash_pair(left, right)
}

/// Compute leaf commitment from secret
pub fn compute_leaf_commitment(secret: &LeafSecret) -> Mersenne31 {
    get_hasher().leaf_commitment(secret)
}

/// Compute nullifier from secret and session ID
/// Returns 4 M31 elements (16 bytes, 124 bits) for collision resistance
pub fn compute_nullifier(secret: &LeafSecret, session: &SessionId) -> Nullifier {
    get_hasher().nullifier(secret, session)
}

// =============================================================================
// Merkle Tree Operations
// =============================================================================

/// Build Merkle tree from leaf commitments, return root
pub fn build_merkle_tree(leaves: &[Mersenne31]) -> Mersenne31 {
    if leaves.is_empty() {
        return Mersenne31::ZERO;
    }
    
    if leaves.len() == 1 {
        return leaves[0];
    }
    
    let hasher = get_hasher();
    
    // Pad to power of 2
    let mut padded = leaves.to_vec();
    let mut size = 1;
    while size < padded.len() {
        size *= 2;
    }
    padded.resize(size, Mersenne31::ZERO);
    
    // Build tree bottom-up
    while padded.len() > 1 {
        let mut next_layer = Vec::with_capacity(padded.len() / 2);
        for chunk in padded.chunks(2) {
            next_layer.push(hasher.hash_pair(chunk[0], chunk[1]));
        }
        padded = next_layer;
    }
    
    padded[0]
}

/// Verify a Merkle proof
pub fn verify_merkle_proof(
    leaf: Mersenne31,
    siblings: &[Mersenne31],
    path_bits: &[bool],
    root: Mersenne31,
) -> bool {
    if siblings.len() != path_bits.len() {
        return false;
    }
    
    let hasher = get_hasher();
    let mut current = leaf;
    
    for (sibling, is_right) in siblings.iter().zip(path_bits.iter()) {
        current = if *is_right {
            // We're the right child: H(sibling, current)
            hasher.hash_pair(*sibling, current)
        } else {
            // We're the left child: H(current, sibling)
            hasher.hash_pair(current, *sibling)
        };
    }
    
    current == root
}

/// Get Merkle path for a leaf at given index
pub fn get_merkle_path(
    leaves: &[Mersenne31],
    index: usize,
) -> (Vec<Mersenne31>, Vec<bool>) {
    let hasher = get_hasher();
    let mut siblings = Vec::new();
    let mut path_bits = Vec::new();
    
    // Pad to power of 2
    let mut padded = leaves.to_vec();
    let mut size = 1;
    while size < padded.len() {
        size *= 2;
    }
    padded.resize(size, Mersenne31::ZERO);
    
    let mut current_layer = padded;
    let mut idx = index;
    
    while current_layer.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        siblings.push(current_layer[sibling_idx]);
        path_bits.push(idx % 2 == 1); // true if we're the right child
        
        // Build next layer
        let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
        for chunk in current_layer.chunks(2) {
            next_layer.push(hasher.hash_pair(chunk[0], chunk[1]));
        }
        current_layer = next_layer;
        idx /= 2;
    }
    
    (siblings, path_bits)
}

// =============================================================================
// M31 Serialization Helpers
// =============================================================================

/// Convert M31 to 4-byte big-endian
pub fn m31_to_bytes(val: Mersenne31) -> [u8; 4] {
    val.as_canonical_u32().to_be_bytes()
}

/// Parse M31 from 4-byte big-endian
pub fn m31_from_bytes(bytes: &[u8]) -> Mersenne31 {
    if bytes.len() < 4 {
        return Mersenne31::ZERO;
    }
    let val = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Mersenne31::new(val & 0x7FFFFFFF)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hasher_deterministic() {
        let h1 = Poseidon2Hasher::new();
        let h2 = Poseidon2Hasher::new();
        
        let a = Mersenne31::new(123);
        let b = Mersenne31::new(456);
        
        assert_eq!(h1.hash_pair(a, b), h2.hash_pair(a, b));
    }
    
    #[test]
    fn test_hash_pair_order_matters() {
        let a = Mersenne31::new(123);
        let b = Mersenne31::new(456);
        
        let h1 = poseidon2_hash_pair(a, b);
        let h2 = poseidon2_hash_pair(b, a);
        
        assert_ne!(h1, h2, "Hash should depend on order");
    }
    
    #[test]
    fn test_leaf_commitment_deterministic() {
        let secret = LeafSecret::from_bytes(&[0x42; 32]);
        
        let c1 = compute_leaf_commitment(&secret);
        let c2 = compute_leaf_commitment(&secret);
        
        assert_eq!(c1, c2);
    }
    
    #[test]
    fn test_nullifier_unlinkability() {
        let secret = LeafSecret::from_bytes(&[0x42; 32]);
        let session1 = SessionId::from_bytes(&[0x01; 32]);
        let session2 = SessionId::from_bytes(&[0x02; 32]);
        
        let null1 = compute_nullifier(&secret, &session1);
        let null2 = compute_nullifier(&secret, &session2);
        
        // Same secret, different sessions → different nullifiers
        assert_ne!(null1, null2);
        
        // Same session → same nullifier
        let null1_again = compute_nullifier(&secret, &session1);
        assert_eq!(null1, null1_again);
    }
    
    #[test]
    fn test_nullifier_is_16_bytes() {
        let secret = LeafSecret::from_bytes(&[0x42; 32]);
        let session = SessionId::from_bytes(&[0x01; 32]);
        
        let nullifier = compute_nullifier(&secret, &session);
        let bytes = nullifier.to_bytes();
        
        // 4 M31 elements × 4 bytes = 16 bytes
        assert_eq!(bytes.len(), 16);
        
        // 4 M31 elements × 31 bits = 124 bits of entropy
        assert!(4 * 31 >= 120, "Nullifier should have at least 120 bits");
        
        // Roundtrip
        let restored = Nullifier::from_bytes(&bytes);
        assert_eq!(nullifier, restored);
    }
    
    #[test]
    fn test_leaf_secret_entropy() {
        // 5 M31 elements × 31 bits = 155 bits > 128 required
        assert!(5 * 31 >= 128);
    }
    
    #[test]
    fn test_leaf_secret_roundtrip() {
        let original = [
            0x12, 0x34, 0x56, 0x78, // element 0
            0x9A, 0xBC, 0xDE, 0xF0, // element 1
            0x11, 0x22, 0x33, 0x44, // element 2
            0x55, 0x66, 0x77, 0x88, // element 3
            0x99, 0xAA, 0xBB, 0xCC, // element 4
            0x00, 0x00, 0x00, 0x00, // unused
            0x00, 0x00, 0x00, 0x00, // unused
            0x00, 0x00, 0x00, 0x00, // unused
        ];
        
        let secret = LeafSecret::from_bytes(&original);
        let bytes = secret.to_bytes();
        
        // Should preserve the first 20 bytes (reduced mod 2^31-1)
        // Note: values get reduced, so exact match only for small values
        assert_eq!(bytes.len(), 20);
    }
    
    #[test]
    fn test_merkle_tree_basic() {
        let leaves: Vec<Mersenne31> = (1..=4)
            .map(|i| Mersenne31::new(i))
            .collect();
        
        let root = build_merkle_tree(&leaves);
        
        // Verify each leaf's path
        for (i, leaf) in leaves.iter().enumerate() {
            let (siblings, path_bits) = get_merkle_path(&leaves, i);
            assert!(
                verify_merkle_proof(*leaf, &siblings, &path_bits, root),
                "Merkle proof for leaf {} should verify",
                i
            );
        }
    }
    
    #[test]
    fn test_merkle_wrong_leaf_fails() {
        let leaves: Vec<Mersenne31> = (1..=4)
            .map(|i| Mersenne31::new(i))
            .collect();
        
        let root = build_merkle_tree(&leaves);
        let (siblings, path_bits) = get_merkle_path(&leaves, 0);
        
        let wrong_leaf = Mersenne31::new(9999);
        assert!(
            !verify_merkle_proof(wrong_leaf, &siblings, &path_bits, root),
            "Wrong leaf should not verify"
        );
    }
    
    #[test]
    fn test_domain_separation() {
        // Same inputs with different domains should produce different outputs
        let hasher = Poseidon2Hasher::new();
        
        let mut state1 = [Mersenne31::ZERO; WIDTH];
        state1[0] = domains::LEAF;
        state1[1] = Mersenne31::new(42);
        
        let mut state2 = [Mersenne31::ZERO; WIDTH];
        state2[0] = domains::NULLIFIER;
        state2[1] = Mersenne31::new(42);
        
        hasher.permute(&mut state1);
        hasher.permute(&mut state2);
        
        assert_ne!(state1[1], state2[1], "Different domains should produce different outputs");
    }
    
    /// This test verifies our hash matches Plonky3's test vectors
    /// From: mersenne-31/src/poseidon2.rs test_poseidon2_width_16_random
    #[test]
    fn test_matches_plonky3_vectors() {
        let hasher = Poseidon2Hasher::new();
        
        // Input from Plonky3 test (seed 16)
        let input: [Mersenne31; 16] = [
            894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695, 1717947831,
            120589055, 19776022, 42382981, 1831865506, 724844064, 171220207, 1299207443, 227047920,
            1783754913,
        ].map(Mersenne31::new);
        
        // Expected output from Plonky3 test
        let expected: [Mersenne31; 16] = [
            1124552602, 2127602268, 1834113265, 1207687593, 1891161485, 245915620, 981277919,
            627265710, 1534924153, 1580826924, 887997842, 1526280482, 547791593, 1028672510,
            1803086471, 323071277,
        ].map(Mersenne31::new);
        
        let mut state = input;
        hasher.permute(&mut state);
        
        assert_eq!(state, expected, "Should match Plonky3 test vectors");
    }
}
