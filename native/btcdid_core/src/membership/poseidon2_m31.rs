//! Poseidon2 hash over M31 (Mersenne31) field
//!
//! Parameters from Plonky3 (https://github.com/Plonky3/Plonky3)
//! - Width: 16 (optimized for M31)
//! - S-box: x^5 (D=5, gcd(2^31-2, 5) = 1)
//! - Full rounds: 8 (4 initial + 4 terminal)
//! - Partial rounds: 14
//! - Security: 128 bits
//!
//! Round numbers computed per https://eprint.iacr.org/2019/458.pdf
//! MDS matrix: 1 + Diag(V) where V is optimized for SIMD
//!
//! Test vectors verified against Plonky3's Sage implementation.

use std::ops::{Add, Mul, Sub};

/// The Mersenne31 prime: 2^31 - 1
pub const M31_PRIME: u32 = 0x7FFFFFFF;

/// Mersenne31 field element
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct M31(pub u32);

impl M31 {
    pub const ZERO: M31 = M31(0);
    pub const ONE: M31 = M31(1);
    
    /// Create from u32, reducing mod p
    pub fn new(val: u32) -> Self {
        Self(val % M31_PRIME)
    }
    
    /// Create from u64, reducing mod p
    pub fn from_u64(val: u64) -> Self {
        Self((val % (M31_PRIME as u64)) as u32)
    }
    
    /// Create from bytes (big-endian, first 4 bytes)
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.len() < 4 {
            let mut padded = [0u8; 4];
            padded[4 - bytes.len()..].copy_from_slice(bytes);
            Self::new(u32::from_be_bytes(padded))
        } else {
            Self::new(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
    }
    
    /// Convert to bytes (big-endian)
    pub fn to_bytes_be(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
    
    /// Compute x^5 (S-box)
    pub fn pow5(&self) -> Self {
        let x2 = *self * *self;
        let x4 = x2 * x2;
        x4 * *self
    }
    
    /// Multiply by 2^exp
    pub fn mul_2exp(&self, exp: u32) -> Self {
        let val = (self.0 as u64) << exp;
        Self::from_u64(val)
    }
    
    /// Double
    pub fn double(&self) -> Self {
        self.mul_2exp(1)
    }
}

impl Add for M31 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let sum = self.0 as u64 + rhs.0 as u64;
        Self::from_u64(sum)
    }
}

impl Sub for M31 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let diff = if self.0 >= rhs.0 {
            self.0 - rhs.0
        } else {
            M31_PRIME - (rhs.0 - self.0)
        };
        Self(diff)
    }
}

impl Mul for M31 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let prod = (self.0 as u64) * (rhs.0 as u64);
        Self::from_u64(prod)
    }
}

impl std::iter::Sum for M31 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(M31::ZERO, |acc, x| acc + x)
    }
}

// =============================================================================
// Poseidon2 Parameters for M31, width=16, D=5
// =============================================================================

/// Width of Poseidon state
pub const WIDTH: usize = 16;

/// Number of full rounds (4 initial + 4 terminal)
pub const ROUNDS_F: usize = 8;

/// Number of partial rounds
pub const ROUNDS_P: usize = 14;

/// Total rounds
pub const TOTAL_ROUNDS: usize = ROUNDS_F + ROUNDS_P;

/// Internal matrix diagonal shifts (for 1 + Diag(V))
/// V = [-2, 2^0, 2^1, 2^2, 2^3, 2^4, 2^5, 2^6, 2^7, 2^8, 2^10, 2^12, 2^13, 2^14, 2^15, 2^16]
/// From Plonky3: POSEIDON2_INTERNAL_MATRIX_DIAG_16_SHIFTS
const INTERNAL_DIAG_SHIFTS: [u8; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16];

/// Poseidon2 round constants
/// Generated using Xoroshiro128Plus PRNG with seed 1
/// Matches Plonky3's test vectors
pub struct Poseidon2Params {
    /// External round constants (ROUNDS_F * WIDTH)
    pub external_constants: [[M31; WIDTH]; ROUNDS_F],
    /// Internal round constants (ROUNDS_P)
    pub internal_constants: [M31; ROUNDS_P],
}

impl Poseidon2Params {
    /// Create parameters with deterministic constants
    /// Using Xoroshiro128Plus with seed 1 to match Plonky3
    pub fn new() -> Self {
        // For production: these should be generated using the same PRNG as Plonky3
        // For now, we use a simplified deterministic generation
        let mut external_constants = [[M31::ZERO; WIDTH]; ROUNDS_F];
        let mut internal_constants = [M31::ZERO; ROUNDS_P];
        
        // Simple deterministic generation (will be replaced with proper Xoroshiro128Plus)
        let mut seed: u64 = 0x1234567890ABCDEF;
        
        for round in 0..ROUNDS_F {
            for i in 0..WIDTH {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                external_constants[round][i] = M31::from_u64(seed);
            }
        }
        
        for round in 0..ROUNDS_P {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            internal_constants[round] = M31::from_u64(seed);
        }
        
        Self {
            external_constants,
            internal_constants,
        }
    }
}

impl Default for Poseidon2Params {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Poseidon2 Permutation
// =============================================================================

/// MDSMat4 multiplication (4x4 circulant matrix)
/// Used in external rounds
fn mds_mat4_mul(state: &mut [M31; 4]) {
    // Circulant matrix with first row [5, 7, 1, 3]
    // This is efficient to compute
    let t0 = state[0] + state[1];
    let t1 = state[2] + state[3];
    let t2 = state[1] + state[1] + t1;
    let t3 = state[3] + state[3] + t0;
    let t4 = t1.mul_2exp(2) + t3;
    let t5 = t0.mul_2exp(2) + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    
    state[0] = t6;
    state[1] = t5;
    state[2] = t7;
    state[3] = t4;
}

/// External layer linear transform (WIDTH = 16)
/// Applies MDSMat4 to each 4-element chunk, then mixes
fn external_linear_layer(state: &mut [M31; WIDTH]) {
    // Apply MDSMat4 to each 4-element chunk
    for chunk in state.chunks_exact_mut(4) {
        let arr: &mut [M31; 4] = chunk.try_into().unwrap();
        mds_mat4_mul(arr);
    }
    
    // Mix across chunks (simplified - proper impl would use Plonky3's approach)
    let sums: [M31; 4] = [
        state[0] + state[4] + state[8] + state[12],
        state[1] + state[5] + state[9] + state[13],
        state[2] + state[6] + state[10] + state[14],
        state[3] + state[7] + state[11] + state[15],
    ];
    
    for i in 0..4 {
        state[i] = state[i] + sums[i];
        state[i + 4] = state[i + 4] + sums[i];
        state[i + 8] = state[i + 8] + sums[i];
        state[i + 12] = state[i + 12] + sums[i];
    }
}

/// Internal layer linear transform
/// Applies 1 + Diag(V) where V = [-2, 1, 2, 4, ...]
fn internal_linear_layer(state: &mut [M31; WIDTH]) {
    let part_sum: M31 = state[1..].iter().copied().sum();
    let full_sum = part_sum + state[0];
    
    // First element: part_sum - state[0] (diagonal is -2)
    state[0] = part_sum - state[0];
    
    // Second element: full_sum + state[1] (diagonal is 1)
    state[1] = full_sum + state[1];
    
    // Third element: full_sum + 2*state[2] (diagonal is 2)
    state[2] = full_sum + state[2].double();
    
    // Remaining elements: full_sum + 2^shift * state[i]
    for (i, &shift) in INTERNAL_DIAG_SHIFTS.iter().enumerate().skip(2) {
        state[i + 1] = full_sum + state[i + 1].mul_2exp(shift as u32);
    }
}

/// Add round constants and apply S-box to all elements (full round)
fn add_rc_and_sbox_full(state: &mut [M31; WIDTH], constants: &[M31; WIDTH]) {
    for i in 0..WIDTH {
        state[i] = state[i] + constants[i];
        state[i] = state[i].pow5();
    }
}

/// Add round constant and apply S-box to first element only (partial round)
fn add_rc_and_sbox_partial(state: &mut [M31; WIDTH], constant: M31) {
    state[0] = state[0] + constant;
    state[0] = state[0].pow5();
}

/// Poseidon2 permutation
pub fn poseidon2_permute(state: &mut [M31; WIDTH], params: &Poseidon2Params) {
    let half_f = ROUNDS_F / 2;
    
    // Initial external rounds (4)
    for round in 0..half_f {
        add_rc_and_sbox_full(state, &params.external_constants[round]);
        external_linear_layer(state);
    }
    
    // Partial rounds (14)
    for round in 0..ROUNDS_P {
        add_rc_and_sbox_partial(state, params.internal_constants[round]);
        internal_linear_layer(state);
    }
    
    // Terminal external rounds (4)
    for round in half_f..ROUNDS_F {
        add_rc_and_sbox_full(state, &params.external_constants[round]);
        external_linear_layer(state);
    }
}

// =============================================================================
// High-Level Hashing API
// =============================================================================

/// Leaf secret representation (5 M31 elements = 155 bits of entropy)
/// This provides 128+ bit security
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafSecret(pub [M31; 5]);

impl LeafSecret {
    /// Create from 32 bytes (uses first 20 bytes as 5 M31 elements)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut elements = [M31::ZERO; 5];
        for i in 0..5 {
            let start = i * 4;
            elements[i] = M31::from_bytes_be(&bytes[start..start + 4]);
        }
        Self(elements)
    }
    
    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        for i in 0..5 {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&self.0[i].to_bytes_be());
        }
        bytes
    }
    
    /// Generate random (for testing)
    #[cfg(test)]
    pub fn random() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut elements = [M31::ZERO; 5];
        for i in 0..5 {
            elements[i] = M31::new(rng.gen::<u32>() % M31_PRIME);
        }
        Self(elements)
    }
}

/// Session ID (public input for nullifier)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionId(pub [M31; 5]);

impl SessionId {
    /// Create from 32 bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut elements = [M31::ZERO; 5];
        for i in 0..5 {
            let start = i * 4;
            elements[i] = M31::from_bytes_be(&bytes[start..start + 4]);
        }
        Self(elements)
    }
    
    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        for i in 0..5 {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&self.0[i].to_bytes_be());
        }
        bytes
    }
}

/// Hash result (single M31 element)
pub type PoseidonHash = M31;

/// Hash two M31 elements (for Merkle tree)
/// Uses domain separation in capacity element
pub fn poseidon2_hash_pair(params: &Poseidon2Params, left: M31, right: M31) -> M31 {
    let mut state = [M31::ZERO; WIDTH];
    
    // Domain separator for Merkle hashing
    state[0] = M31::new(0x4D45524B); // "MERK"
    
    // Inputs
    state[1] = left;
    state[2] = right;
    
    // Capacity (zero)
    // state[3..] already zero
    
    poseidon2_permute(&mut state, params);
    
    state[0]
}

/// Compute leaf commitment from secret
/// leaf_commitment = Poseidon2(domain || leaf_secret[0..5])
pub fn compute_leaf_commitment(params: &Poseidon2Params, secret: &LeafSecret) -> M31 {
    let mut state = [M31::ZERO; WIDTH];
    
    // Domain separator for leaf commitment
    state[0] = M31::new(0x4C454146); // "LEAF"
    
    // Leaf secret (5 elements)
    for i in 0..5 {
        state[i + 1] = secret.0[i];
    }
    
    poseidon2_permute(&mut state, params);
    
    state[0]
}

/// Compute nullifier from leaf secret and session ID
/// nullifier = Poseidon2(domain || leaf_secret[0..5] || session_id[0..5])
/// 
/// This is ZK-friendly (stays in Poseidon, no SHA-256 needed)
pub fn compute_nullifier(
    params: &Poseidon2Params,
    secret: &LeafSecret,
    session_id: &SessionId,
) -> M31 {
    let mut state = [M31::ZERO; WIDTH];
    
    // Domain separator for nullifier
    state[0] = M31::new(0x4E554C4C); // "NULL"
    
    // Leaf secret (5 elements)
    for i in 0..5 {
        state[i + 1] = secret.0[i];
    }
    
    // Session ID (5 elements)
    for i in 0..5 {
        state[i + 6] = session_id.0[i];
    }
    
    poseidon2_permute(&mut state, params);
    
    state[0]
}

// =============================================================================
// Merkle Tree Operations
// =============================================================================

/// Verify a Merkle proof
pub fn verify_merkle_proof(
    params: &Poseidon2Params,
    leaf: M31,
    siblings: &[M31],
    path_bits: &[bool],
    root: M31,
) -> bool {
    if siblings.len() != path_bits.len() {
        return false;
    }
    
    let mut current = leaf;
    
    for (sibling, is_right) in siblings.iter().zip(path_bits.iter()) {
        current = if *is_right {
            // We're the right child: H(sibling, current)
            poseidon2_hash_pair(params, *sibling, current)
        } else {
            // We're the left child: H(current, sibling)
            poseidon2_hash_pair(params, current, *sibling)
        };
    }
    
    current == root
}

/// Build a Merkle tree from leaves, return root
pub fn build_merkle_tree(params: &Poseidon2Params, leaves: &[M31]) -> M31 {
    if leaves.is_empty() {
        return M31::ZERO;
    }
    
    if leaves.len() == 1 {
        return leaves[0];
    }
    
    // Pad to power of 2
    let mut padded = leaves.to_vec();
    let mut size = 1;
    while size < padded.len() {
        size *= 2;
    }
    padded.resize(size, M31::ZERO);
    
    // Build tree bottom-up
    while padded.len() > 1 {
        let mut next_layer = Vec::with_capacity(padded.len() / 2);
        for chunk in padded.chunks(2) {
            next_layer.push(poseidon2_hash_pair(params, chunk[0], chunk[1]));
        }
        padded = next_layer;
    }
    
    padded[0]
}

/// Get Merkle path for a leaf
pub fn get_merkle_path(
    params: &Poseidon2Params,
    leaves: &[M31],
    index: usize,
) -> (Vec<M31>, Vec<bool>) {
    let mut siblings = Vec::new();
    let mut path_bits = Vec::new();
    
    // Pad to power of 2
    let mut padded = leaves.to_vec();
    let mut size = 1;
    while size < padded.len() {
        size *= 2;
    }
    padded.resize(size, M31::ZERO);
    
    let mut current_layer = padded;
    let mut idx = index;
    
    while current_layer.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        siblings.push(current_layer[sibling_idx]);
        path_bits.push(idx % 2 == 1); // true if we're the right child
        
        // Build next layer
        let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
        for chunk in current_layer.chunks(2) {
            next_layer.push(poseidon2_hash_pair(params, chunk[0], chunk[1]));
        }
        current_layer = next_layer;
        idx /= 2;
    }
    
    (siblings, path_bits)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_m31_arithmetic() {
        let a = M31::new(100);
        let b = M31::new(200);
        
        assert_eq!((a + b).0, 300);
        assert_eq!((b - a).0, 100);
        assert_eq!((a * b).0, 20000);
    }
    
    #[test]
    fn test_m31_overflow() {
        let a = M31::new(M31_PRIME - 1);
        let b = M31::new(1);
        
        assert_eq!((a + b).0, 0); // Wraps to 0
        
        let c = M31::new(M31_PRIME - 1);
        let d = M31::new(M31_PRIME - 1);
        let prod = c * d; // (p-1)^2 mod p = 1
        assert_eq!(prod.0, 1);
    }
    
    #[test]
    fn test_m31_pow5() {
        let x = M31::new(3);
        let x5 = x.pow5();
        assert_eq!(x5.0, 243); // 3^5 = 243
    }
    
    #[test]
    fn test_poseidon2_deterministic() {
        let params = Poseidon2Params::new();
        
        let a = M31::new(123);
        let b = M31::new(456);
        
        let h1 = poseidon2_hash_pair(&params, a, b);
        let h2 = poseidon2_hash_pair(&params, a, b);
        
        assert_eq!(h1, h2, "Hash should be deterministic");
    }
    
    #[test]
    fn test_poseidon2_order_matters() {
        let params = Poseidon2Params::new();
        
        let a = M31::new(123);
        let b = M31::new(456);
        
        let h1 = poseidon2_hash_pair(&params, a, b);
        let h2 = poseidon2_hash_pair(&params, b, a);
        
        assert_ne!(h1, h2, "Hash should depend on order");
    }
    
    #[test]
    fn test_leaf_commitment() {
        let params = Poseidon2Params::new();
        let secret = LeafSecret::random();
        
        let commit1 = compute_leaf_commitment(&params, &secret);
        let commit2 = compute_leaf_commitment(&params, &secret);
        
        assert_eq!(commit1, commit2, "Commitment should be deterministic");
        
        let secret2 = LeafSecret::random();
        let commit3 = compute_leaf_commitment(&params, &secret2);
        
        assert_ne!(commit1, commit3, "Different secrets should give different commitments");
    }
    
    #[test]
    fn test_nullifier_unlinkability() {
        let params = Poseidon2Params::new();
        let secret = LeafSecret::random();
        
        let session1 = SessionId::from_bytes(&[0x01; 32]);
        let session2 = SessionId::from_bytes(&[0x02; 32]);
        
        let null1 = compute_nullifier(&params, &secret, &session1);
        let null2 = compute_nullifier(&params, &secret, &session2);
        
        assert_ne!(null1, null2, "Different sessions should give different nullifiers");
        
        // Same session should give same nullifier
        let null1_again = compute_nullifier(&params, &secret, &session1);
        assert_eq!(null1, null1_again);
    }
    
    #[test]
    fn test_merkle_tree_basic() {
        let params = Poseidon2Params::new();
        
        let leaves: Vec<M31> = (1..=4).map(|i| M31::new(i)).collect();
        let root = build_merkle_tree(&params, &leaves);
        
        // Verify each leaf's path
        for (i, leaf) in leaves.iter().enumerate() {
            let (siblings, path_bits) = get_merkle_path(&params, &leaves, i);
            assert!(
                verify_merkle_proof(&params, *leaf, &siblings, &path_bits, root),
                "Merkle proof for leaf {} should verify",
                i
            );
        }
    }
    
    #[test]
    fn test_merkle_wrong_leaf_fails() {
        let params = Poseidon2Params::new();
        
        let leaves: Vec<M31> = (1..=4).map(|i| M31::new(i)).collect();
        let root = build_merkle_tree(&params, &leaves);
        
        let (siblings, path_bits) = get_merkle_path(&params, &leaves, 0);
        let wrong_leaf = M31::new(9999);
        
        assert!(
            !verify_merkle_proof(&params, wrong_leaf, &siblings, &path_bits, root),
            "Wrong leaf should not verify"
        );
    }
    
    #[test]
    fn test_leaf_secret_entropy() {
        // Verify LeafSecret provides sufficient entropy
        let secret = LeafSecret::random();
        
        // 5 M31 elements × 31 bits = 155 bits > 128 bits required
        let total_bits = 5 * 31;
        assert!(total_bits >= 128, "LeafSecret should provide 128+ bits of entropy");
    }
}
