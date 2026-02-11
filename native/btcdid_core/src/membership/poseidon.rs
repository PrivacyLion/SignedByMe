//! Poseidon Hash Implementation
//!
//! A circuit-friendly hash function used for Merkle trees.
//! Uses parameters compatible with STWO/Starknet.
//!
//! Parameters:
//! - Width: t = 3 (2 inputs + 1 capacity)
//! - Full rounds: RF = 8 (4 + 4)
//! - Partial rounds: RP = 57
//! - S-box: x^5
//!
//! Note: This is a simplified implementation. For production,
//! use the actual STWO Poseidon implementation.

/// Field element wrapper (256-bit for compatibility)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement([u64; 4]);

impl FieldElement {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut arr = [0u64; 4];
        let len = bytes.len().min(32);
        
        // Pack bytes into u64s (big-endian)
        for (i, chunk) in bytes[..len].chunks(8).rev().enumerate() {
            if i < 4 {
                let mut buf = [0u8; 8];
                let start = 8 - chunk.len();
                buf[start..].copy_from_slice(chunk);
                arr[i] = u64::from_be_bytes(buf);
            }
        }
        
        Self(arr)
    }
    
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, &val) in self.0.iter().rev().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&val.to_be_bytes());
        }
        out
    }
    
    pub fn from_u64(val: u64) -> Self {
        Self([val, 0, 0, 0])
    }
    
    /// Add two field elements (simplified - wrapping add)
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum1, c1) = self.0[i].overflowing_add(other.0[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        Self(result)
    }
    
    /// Multiply two field elements (simplified - low bits only)
    pub fn mul(&self, other: &Self) -> Self {
        // Simplified: just multiply the low limb
        // For production, use proper 256-bit multiplication with reduction
        let low = self.0[0].wrapping_mul(other.0[0]);
        Self([low, 0, 0, 0])
    }
    
    /// x^5 (S-box)
    pub fn pow5(&self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(&x2);
        x4.mul(self)
    }
}

/// Poseidon hasher state
pub struct PoseidonHasher {
    state: [FieldElement; 3],
    pos: usize,
}

impl PoseidonHasher {
    pub fn new() -> Self {
        Self {
            state: [FieldElement::ZERO; 3],
            pos: 0,
        }
    }
    
    pub fn update(&mut self, input: &FieldElement) {
        self.state[self.pos] = self.state[self.pos].add(input);
        self.pos += 1;
        
        if self.pos == 2 {
            self.permute();
            self.pos = 0;
        }
    }
    
    pub fn finalize(mut self) -> FieldElement {
        if self.pos > 0 {
            self.permute();
        }
        self.state[0]
    }
    
    fn permute(&mut self) {
        // Simplified permutation: just mix the state
        // For production, use actual Poseidon round constants and S-boxes
        
        // Full rounds (first 4)
        for round in 0..4 {
            self.add_round_constant(round);
            self.sbox_full();
            self.mds_mix();
        }
        
        // Partial rounds (57)
        for round in 4..61 {
            self.add_round_constant(round);
            self.sbox_partial();
            self.mds_mix();
        }
        
        // Full rounds (last 4)
        for round in 61..65 {
            self.add_round_constant(round);
            self.sbox_full();
            self.mds_mix();
        }
    }
    
    fn add_round_constant(&mut self, round: usize) {
        // Simplified: use round number as constant
        // For production, use actual Poseidon round constants
        for i in 0..3 {
            let c = FieldElement::from_u64((round * 3 + i) as u64);
            self.state[i] = self.state[i].add(&c);
        }
    }
    
    fn sbox_full(&mut self) {
        for i in 0..3 {
            self.state[i] = self.state[i].pow5();
        }
    }
    
    fn sbox_partial(&mut self) {
        self.state[2] = self.state[2].pow5();
    }
    
    fn mds_mix(&mut self) {
        // Simplified MDS matrix multiplication
        // For production, use actual Poseidon MDS matrix
        let old = self.state;
        self.state[0] = old[0].mul(&FieldElement::from_u64(3))
            .add(&old[1])
            .add(&old[2]);
        self.state[1] = old[0]
            .add(&old[1].mul(&FieldElement::from_u64(3)))
            .add(&old[2]);
        self.state[2] = old[0]
            .add(&old[1])
            .add(&old[2].mul(&FieldElement::from_u64(3)));
    }
}

impl Default for PoseidonHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash two field elements (for Merkle tree)
pub fn poseidon_hash_pair(left: &FieldElement, right: &FieldElement) -> FieldElement {
    let mut hasher = PoseidonHasher::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

/// Hash arbitrary bytes to field element
pub fn poseidon_hash_bytes(data: &[u8]) -> FieldElement {
    let mut hasher = PoseidonHasher::new();
    
    // Pack bytes into field elements (31 bytes per element for safety)
    for chunk in data.chunks(31) {
        let fe = FieldElement::from_bytes_be(chunk);
        hasher.update(&fe);
    }
    
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_element_roundtrip() {
        let bytes = [0xab; 32];
        let fe = FieldElement::from_bytes_be(&bytes);
        let back = fe.to_bytes_be();
        assert_eq!(bytes, back);
    }

    #[test]
    fn test_hash_pair_deterministic() {
        let a = FieldElement::from_u64(1);
        let b = FieldElement::from_u64(2);
        
        let h1 = poseidon_hash_pair(&a, &b);
        let h2 = poseidon_hash_pair(&a, &b);
        
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_pair_different_order() {
        let a = FieldElement::from_u64(1);
        let b = FieldElement::from_u64(2);
        
        let h1 = poseidon_hash_pair(&a, &b);
        let h2 = poseidon_hash_pair(&b, &a);
        
        assert_ne!(h1, h2, "Different order should produce different hashes");
    }

    #[test]
    fn test_poseidon_bytes() {
        let data = b"hello world";
        let h1 = poseidon_hash_bytes(data);
        let h2 = poseidon_hash_bytes(data);
        
        assert_eq!(h1, h2);
    }
}
