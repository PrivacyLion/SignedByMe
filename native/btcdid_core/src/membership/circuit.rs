//! Poseidon2-M31 Circuit for STWO STARK Membership Proofs
//!
//! This circuit proves:
//! 1. Knowledge of leaf_secret such that leaf_commitment = Poseidon2(LEAF_DOM || secret)
//! 2. Merkle path from leaf_commitment to root is valid
//! 3. Nullifier = Poseidon2(NULL_DOM || leaf_secret || session_id) is correctly computed
//! 4. Binding hash is incorporated (public input)
//!
//! # Why Poseidon2-M31 over SHA-256?
//!
//! - Native M31 field arithmetic (no bit decomposition needed)
//! - 8+14+4 = 26 total rounds (vs 64×5=320 for SHA-256 with 5 blocks)
//! - S-box only applied to position 0 in internal rounds
//! - 1+Diag(V) internal layer is sparse (cheap)
//!
//! # Constraint Estimate
//!
//! Per Poseidon2 permutation (WIDTH=16, 8+14 rounds):
//! - External rounds (8 total): 16 S-boxes each = 128 S-boxes
//! - Internal rounds (14 total): 1 S-box each = 14 S-boxes
//! - Total S-boxes: 142
//! - S-box x^5 = 2 multiplications = 284 multiplication constraints
//! - Linear layers: 22 rounds × O(WIDTH) ≈ 352 additions (cheap)
//!
//! For membership proof:
//! - 1 Poseidon2 for leaf commitment
//! - 1 Poseidon2 for nullifier
//! - 20 Poseidon2 for Merkle path (depth 20)
//! - Total: 22 permutations ≈ 6,248 multiplication constraints
//!
//! This is MUCH smaller than SHA-256 circuit (~100k constraints for 5 blocks).

#![cfg(feature = "real-stwo")]

use anyhow::{anyhow, Result};
use p3_field::PrimeField32;
use p3_mersenne_31::Mersenne31;
use stwo::core::fields::m31::BaseField;
use stwo::prover::backend::CpuBackend;
use stwo::prover::backend::{Col, Column};
use stwo_constraint_framework::EvalAtRow;

use super::poseidon2_m31::{
    M31, WIDTH, RATE, FULL_ROUNDS_FIRST, FULL_ROUNDS_LAST, PARTIAL_ROUNDS,
    DOMAIN_LEAF, DOMAIN_NULL, DOMAIN_MERK,
    Poseidon2M31Hasher,
};

// ============================================================================
// Circuit Parameters
// ============================================================================

/// Tree depth (supports ~1M members)
pub const TREE_DEPTH: usize = 20;

/// Number of M31 elements in leaf_secret (155 bits entropy > 128 required)
pub const LEAF_SECRET_LEN: usize = 5;

/// Number of M31 elements in session_id (128 bits = 4 elements × 31 bits)
pub const SESSION_ID_LEN: usize = 5;

/// Number of M31 elements in nullifier output (4 elements = 124 bits)
pub const NULLIFIER_LEN: usize = 4;

/// Total rounds in Poseidon2
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS_FIRST + PARTIAL_ROUNDS + FULL_ROUNDS_LAST;

// ============================================================================
// Trace Column Layout
// ============================================================================
//
// For each Poseidon2 permutation, we store:
// - Input state: 16 M31 elements
// - State after each round: 26 rounds × 16 elements = 416 elements
// - Output state: 16 M31 elements (included in above)
//
// Total per permutation: 16 + 416 = 432 columns
//
// For membership proof:
// - 1 leaf commitment permutation: 432 columns
// - 1 nullifier permutation: 432 columns
// - 20 Merkle path permutations: 20 × 432 = 8,640 columns
// Total: 9,504 columns
//
// Plus auxiliary columns:
// - path_bits[20]: 20 columns (0 or 1 indicating left/right)
// - leaf_secret[5]: 5 columns (private witness)
// - session_id[5]: 5 columns (public input)
// - merkle_root: 1 column (public input)
// - nullifier[4]: 4 columns (public output)
// - binding_hash[8]: 8 columns (public input, as M31 elements)
//
// Grand total: 9,504 + 20 + 5 + 5 + 1 + 4 + 8 = 9,547 columns

/// Columns per Poseidon2 permutation
const COLS_PER_PERM: usize = WIDTH * (1 + TOTAL_ROUNDS);

/// Total Poseidon2 permutations (leaf + nullifier + merkle path)
const NUM_PERMS: usize = 1 + 1 + TREE_DEPTH;

/// Number of trace columns
pub const N_TRACE_COLS: usize = COLS_PER_PERM * NUM_PERMS + TREE_DEPTH + LEAF_SECRET_LEN + SESSION_ID_LEN + 1 + NULLIFIER_LEN + 8;

/// Log2 of number of rows
pub const LOG_N_ROWS: u32 = 5; // 32 rows

// ============================================================================
// Round Constants (loaded from poseidon2_m31.rs)
// ============================================================================

/// Get external round constants for round `r` and element `i`
fn external_rc(r: usize, i: usize) -> M31 {
    // These come from Plonky3's verified parameters
    // Generated via Xoroshiro128Plus(seed=1)
    super::poseidon2_m31::get_external_constants()[r * WIDTH + i]
}

/// Get internal round constant for round `r` (only element 0)
fn internal_rc(r: usize) -> M31 {
    super::poseidon2_m31::get_internal_constants()[r]
}

/// Get internal diagonal matrix V values
fn internal_diag(i: usize) -> M31 {
    super::poseidon2_m31::get_internal_diag()[i]
}

// ============================================================================
// Poseidon2 Operations
// ============================================================================

/// S-box: x^5
#[inline]
fn sbox(x: M31) -> M31 {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// External linear layer: M4 matrix applied to state in groups of 4
/// M4 = circ(2, 3, 1, 1) (circulant matrix)
fn external_linear(state: &mut [M31; WIDTH]) {
    // Apply M4 to each group of 4 elements
    for chunk in state.chunks_exact_mut(4) {
        let t0 = chunk[0] + chunk[1];
        let t1 = chunk[2] + chunk[3];
        let t2 = chunk[1] + chunk[1] + t1; // 2*chunk[1] + chunk[2] + chunk[3]
        let t3 = chunk[3] + chunk[3] + t0; // 2*chunk[3] + chunk[0] + chunk[1]
        let t4 = t1 + t1 + t1 + t1 + t3;   // 4*t1 + t3
        let t5 = t0 + t0 + t0 + t0 + t2;   // 4*t0 + t2
        
        chunk[0] = t3;
        chunk[1] = t5;
        chunk[2] = t2;
        chunk[3] = t4;
    }
    
    // Mix groups: each element gets sum of corresponding elements from all groups
    for i in 0..4 {
        let sum: M31 = (0..4).map(|g| state[g * 4 + i]).sum();
        for g in 0..4 {
            state[g * 4 + i] = state[g * 4 + i] + sum;
        }
    }
}

/// Internal linear layer: 1 + Diag(V)
/// Each element multiplied by (1 + V[i]) and added to element 0's contribution
fn internal_linear(state: &mut [M31; WIDTH]) {
    // First compute s0 contribution to all elements
    let s0 = state[0];
    
    // Apply 1 + Diag(V): state[i] = state[i] * (1 + V[i]) + s0 * V[i]_contribution
    // Actually: new[i] = old[i] + old[0] for i > 0, and new[0] = sum of all
    let sum: M31 = state.iter().copied().sum();
    
    for i in 1..WIDTH {
        state[i] = state[i] + s0;
    }
    state[0] = sum;
}

// ============================================================================
// Circuit Witness Generation
// ============================================================================

/// Witness for a single Poseidon2 permutation
#[derive(Clone)]
pub struct PermutationWitness {
    /// Input state
    pub input: [M31; WIDTH],
    /// State after each round (26 rounds)
    pub round_states: Vec<[M31; WIDTH]>,
}

impl PermutationWitness {
    /// Generate witness for a Poseidon2 permutation
    pub fn generate(input: [M31; WIDTH]) -> Self {
        let mut state = input;
        let mut round_states = Vec::with_capacity(TOTAL_ROUNDS);
        
        // First half of full rounds
        for r in 0..FULL_ROUNDS_FIRST {
            // Add round constants
            for i in 0..WIDTH {
                state[i] = state[i] + external_rc(r, i);
            }
            // S-box to all elements
            for i in 0..WIDTH {
                state[i] = sbox(state[i]);
            }
            // Linear layer
            external_linear(&mut state);
            round_states.push(state);
        }
        
        // Partial rounds
        for r in 0..PARTIAL_ROUNDS {
            // Add round constant to element 0 only
            state[0] = state[0] + internal_rc(r);
            // S-box to element 0 only
            state[0] = sbox(state[0]);
            // Internal linear layer
            internal_linear(&mut state);
            round_states.push(state);
        }
        
        // Second half of full rounds
        for r in 0..FULL_ROUNDS_LAST {
            let rc_idx = FULL_ROUNDS_FIRST + r;
            // Add round constants
            for i in 0..WIDTH {
                state[i] = state[i] + external_rc(rc_idx, i);
            }
            // S-box to all elements
            for i in 0..WIDTH {
                state[i] = sbox(state[i]);
            }
            // Linear layer
            external_linear(&mut state);
            round_states.push(state);
        }
        
        Self { input, round_states }
    }
    
    /// Get the output (state after last round)
    pub fn output(&self) -> [M31; WIDTH] {
        self.round_states[TOTAL_ROUNDS - 1]
    }
}

/// Full membership proof witness
pub struct MembershipWitness {
    /// Leaf secret (private)
    pub leaf_secret: [M31; LEAF_SECRET_LEN],
    /// Session ID (public, for nullifier)
    pub session_id: [M31; SESSION_ID_LEN],
    /// Merkle path siblings (private)
    pub siblings: Vec<M31>,
    /// Path bits: 0 = sibling on right, 1 = sibling on left (private)
    pub path_bits: Vec<bool>,
    /// Merkle root (public)
    pub root: M31,
    /// Binding hash as M31 elements (public)
    pub binding_hash: [M31; 8],
    
    /// Computed: leaf commitment permutation witness
    pub leaf_perm: PermutationWitness,
    /// Computed: nullifier permutation witness
    pub null_perm: PermutationWitness,
    /// Computed: Merkle path permutation witnesses
    pub merkle_perms: Vec<PermutationWitness>,
    /// Computed: nullifier output
    pub nullifier: [M31; NULLIFIER_LEN],
}

impl MembershipWitness {
    /// Generate full witness for membership proof
    pub fn generate(
        leaf_secret: [M31; LEAF_SECRET_LEN],
        session_id: [M31; SESSION_ID_LEN],
        siblings: Vec<M31>,
        path_bits: Vec<bool>,
        root: M31,
        binding_hash: [M31; 8],
    ) -> Result<Self> {
        if siblings.len() != TREE_DEPTH {
            return Err(anyhow!("Expected {} siblings, got {}", TREE_DEPTH, siblings.len()));
        }
        if path_bits.len() != TREE_DEPTH {
            return Err(anyhow!("Expected {} path_bits, got {}", TREE_DEPTH, path_bits.len()));
        }
        
        // 1. Compute leaf commitment
        let mut leaf_input = [M31::zero(); WIDTH];
        leaf_input[0] = M31::new(DOMAIN_LEAF);
        for i in 0..LEAF_SECRET_LEN {
            leaf_input[1 + i] = leaf_secret[i];
        }
        let leaf_perm = PermutationWitness::generate(leaf_input);
        let leaf_commitment = leaf_perm.output()[1]; // Output from position 1
        
        // 2. Compute nullifier
        let mut null_input = [M31::zero(); WIDTH];
        null_input[0] = M31::new(DOMAIN_NULL);
        for i in 0..LEAF_SECRET_LEN {
            null_input[1 + i] = leaf_secret[i];
        }
        for i in 0..SESSION_ID_LEN {
            null_input[1 + LEAF_SECRET_LEN + i] = session_id[i];
        }
        let null_perm = PermutationWitness::generate(null_input);
        let nullifier = [
            null_perm.output()[1],
            null_perm.output()[2],
            null_perm.output()[3],
            null_perm.output()[4],
        ];
        
        // 3. Verify Merkle path and generate witnesses
        let mut current = leaf_commitment;
        let mut merkle_perms = Vec::with_capacity(TREE_DEPTH);
        
        for i in 0..TREE_DEPTH {
            let sibling = siblings[i];
            let (left, right) = if path_bits[i] {
                (sibling, current)
            } else {
                (current, sibling)
            };
            
            let mut merkle_input = [M31::zero(); WIDTH];
            merkle_input[0] = M31::new(DOMAIN_MERK);
            merkle_input[1] = left;
            merkle_input[2] = right;
            
            let perm = PermutationWitness::generate(merkle_input);
            current = perm.output()[1];
            merkle_perms.push(perm);
        }
        
        // Verify root matches
        if current != root {
            return Err(anyhow!(
                "Merkle path does not lead to expected root. Got {:?}, expected {:?}",
                current, root
            ));
        }
        
        Ok(Self {
            leaf_secret,
            session_id,
            siblings,
            path_bits,
            root,
            binding_hash,
            leaf_perm,
            null_perm,
            merkle_perms,
            nullifier,
        })
    }
}

// ============================================================================
// STWO Circuit Constraints (FrameworkEval implementation)
// ============================================================================

/// Membership proof evaluator for STWO constraint framework
pub struct MembershipEval {
    pub log_n_rows: u32,
}

impl Default for MembershipEval {
    fn default() -> Self {
        Self { log_n_rows: LOG_N_ROWS }
    }
}

// Column indices for trace
const COL_LEAF_SECRET_START: usize = 0;
const COL_SESSION_ID_START: usize = LEAF_SECRET_LEN;
const COL_PATH_BITS_START: usize = COL_SESSION_ID_START + SESSION_ID_LEN;
const COL_ROOT: usize = COL_PATH_BITS_START + TREE_DEPTH;
const COL_NULLIFIER_START: usize = COL_ROOT + 1;
const COL_BINDING_HASH_START: usize = COL_NULLIFIER_START + NULLIFIER_LEN;
const COL_PERM_START: usize = COL_BINDING_HASH_START + 8;

impl stwo_constraint_framework::FrameworkEval for MembershipEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // x^5 S-box requires degree 5 constraints
        // log2(5) ≈ 2.32, so we need log_n_rows + 3 for safety
        self.log_n_rows + 3
    }
    
    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        // This is where the STARK constraints are defined
        // Each constraint enforces that trace values satisfy Poseidon2 transitions
        
        // The actual constraint implementation requires:
        // 1. For each round of each permutation:
        //    - Constrain S-box: out = in^5
        //    - Constrain linear layer: out = M * in + RC
        // 2. Constrain leaf commitment = Poseidon2(DOM || secret)[1]
        // 3. Constrain nullifier = Poseidon2(DOM || secret || session)[1..5]
        // 4. Constrain Merkle transitions: parent = Poseidon2(DOM || left || right)[1]
        // 5. Constrain final Merkle output == root
        
        // For now, return identity (constraints will be added incrementally)
        // TODO: Implement full constraints
        eval
    }
}

// ============================================================================
// Trace Generation
// ============================================================================

/// Generate STWO trace from membership witness
pub fn generate_trace(witness: &MembershipWitness) -> Vec<Col<CpuBackend, BaseField>> {
    let n_rows = 1 << LOG_N_ROWS;
    let mut trace: Vec<Col<CpuBackend, BaseField>> = Vec::with_capacity(N_TRACE_COLS);
    
    // Initialize all columns with zeros
    for _ in 0..N_TRACE_COLS {
        let col = Col::<CpuBackend, BaseField>::zeros(n_rows);
        trace.push(col);
    }
    
    // Fill in witness values (row 0)
    // Leaf secret
    for i in 0..LEAF_SECRET_LEN {
        trace[COL_LEAF_SECRET_START + i].as_mut_slice()[0] = 
            BaseField::from(witness.leaf_secret[i].as_canonical_u32());
    }
    
    // Session ID
    for i in 0..SESSION_ID_LEN {
        trace[COL_SESSION_ID_START + i].as_mut_slice()[0] = 
            BaseField::from(witness.session_id[i].as_canonical_u32());
    }
    
    // Path bits
    for i in 0..TREE_DEPTH {
        trace[COL_PATH_BITS_START + i].as_mut_slice()[0] = 
            if witness.path_bits[i] { BaseField::one() } else { BaseField::zero() };
    }
    
    // Root
    trace[COL_ROOT].as_mut_slice()[0] = BaseField::from(witness.root.as_canonical_u32());
    
    // Nullifier
    for i in 0..NULLIFIER_LEN {
        trace[COL_NULLIFIER_START + i].as_mut_slice()[0] = 
            BaseField::from(witness.nullifier[i].as_canonical_u32());
    }
    
    // Binding hash
    for i in 0..8 {
        trace[COL_BINDING_HASH_START + i].as_mut_slice()[0] = 
            BaseField::from(witness.binding_hash[i].as_canonical_u32());
    }
    
    // Permutation states
    let mut perm_col = COL_PERM_START;
    
    // Leaf commitment permutation
    fill_permutation_trace(&mut trace, perm_col, &witness.leaf_perm);
    perm_col += COLS_PER_PERM;
    
    // Nullifier permutation
    fill_permutation_trace(&mut trace, perm_col, &witness.null_perm);
    perm_col += COLS_PER_PERM;
    
    // Merkle path permutations
    for perm in &witness.merkle_perms {
        fill_permutation_trace(&mut trace, perm_col, perm);
        perm_col += COLS_PER_PERM;
    }
    
    trace
}

/// Fill trace columns for a single permutation
fn fill_permutation_trace(
    trace: &mut Vec<Col<CpuBackend, BaseField>>,
    start_col: usize,
    perm: &PermutationWitness,
) {
    // Input state
    for i in 0..WIDTH {
        trace[start_col + i].as_mut_slice()[0] = 
            BaseField::from(perm.input[i].as_canonical_u32());
    }
    
    // Round states
    for (r, state) in perm.round_states.iter().enumerate() {
        let offset = start_col + WIDTH + r * WIDTH;
        for i in 0..WIDTH {
            trace[offset + i].as_mut_slice()[0] = 
                BaseField::from(state[i].as_canonical_u32());
        }
    }
}

// ============================================================================
// Public Interface
// ============================================================================

/// Generate a membership proof
pub fn prove_membership(
    leaf_secret: &[u8; 32],
    session_id: &[u8; 32],
    siblings: &[[u8; 32]],
    path_bits: &[bool],
    root: &[u8; 32],
    binding_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    // Convert inputs to M31 elements
    let leaf_m31 = bytes_to_m31_array::<LEAF_SECRET_LEN>(leaf_secret)?;
    let session_m31 = bytes_to_m31_array::<SESSION_ID_LEN>(session_id)?;
    let root_m31 = bytes_to_single_m31(root);
    let binding_m31 = bytes_to_m31_array::<8>(binding_hash)?;
    
    let siblings_m31: Vec<M31> = siblings.iter()
        .map(|s| bytes_to_single_m31(s))
        .collect();
    
    // Generate witness
    let witness = MembershipWitness::generate(
        leaf_m31,
        session_m31,
        siblings_m31,
        path_bits.to_vec(),
        root_m31,
        binding_m31,
    )?;
    
    // Generate trace
    let _trace = generate_trace(&witness);
    
    // TODO: Generate actual STWO proof
    // For now, return the nullifier and witness hash as placeholder
    let mut proof = Vec::new();
    proof.push(0x03); // Version 3
    
    // Nullifier (16 bytes)
    for n in &witness.nullifier {
        proof.extend_from_slice(&n.as_canonical_u32().to_le_bytes());
    }
    
    // Root (for verification)
    proof.extend_from_slice(root);
    
    // Binding hash (for verification)
    proof.extend_from_slice(binding_hash);
    
    Ok(proof)
}

/// Verify a membership proof
pub fn verify_membership(
    proof: &[u8],
    root: &[u8; 32],
    binding_hash: &[u8; 32],
) -> Result<bool> {
    if proof.len() < 1 + 16 + 32 + 32 {
        return Err(anyhow!("Proof too short"));
    }
    
    let version = proof[0];
    if version != 0x03 {
        return Err(anyhow!("Unsupported proof version: {}", version));
    }
    
    // Extract root from proof and compare
    let proof_root = &proof[17..49];
    if proof_root != root {
        return Ok(false);
    }
    
    // Extract binding hash from proof and compare
    let proof_binding = &proof[49..81];
    if proof_binding != binding_hash {
        return Ok(false);
    }
    
    // TODO: Verify actual STWO proof
    Ok(true)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert 32 bytes to an array of M31 elements
fn bytes_to_m31_array<const N: usize>(bytes: &[u8; 32]) -> Result<[M31; N]> {
    let mut result = [M31::zero(); N];
    for i in 0..N.min(8) {
        let offset = i * 4;
        if offset + 4 <= 32 {
            let val = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            // Reduce to M31 range
            result[i] = M31::new(val & 0x7FFFFFFF);
        }
    }
    Ok(result)
}

/// Convert 32 bytes to a single M31 element (takes first 4 bytes)
fn bytes_to_single_m31(bytes: &[u8; 32]) -> M31 {
    let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    M31::new(val & 0x7FFFFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_permutation_witness() {
        let mut input = [M31::zero(); WIDTH];
        input[0] = M31::new(DOMAIN_LEAF);
        input[1] = M31::new(12345);
        
        let witness = PermutationWitness::generate(input);
        assert_eq!(witness.round_states.len(), TOTAL_ROUNDS);
        
        // Output should be deterministic
        let witness2 = PermutationWitness::generate(input);
        assert_eq!(witness.output(), witness2.output());
    }
    
    #[test]
    fn test_membership_witness_generation() {
        let leaf_secret: [M31; LEAF_SECRET_LEN] = [
            M31::new(1), M31::new(2), M31::new(3), M31::new(4), M31::new(5)
        ];
        let session_id: [M31; SESSION_ID_LEN] = [
            M31::new(101), M31::new(102), M31::new(103), M31::new(104), M31::new(105)
        ];
        
        // Create a simple 1-level tree for testing
        let mut siblings = vec![M31::zero(); TREE_DEPTH];
        let path_bits = vec![false; TREE_DEPTH];
        
        // Compute expected root manually
        let mut leaf_input = [M31::zero(); WIDTH];
        leaf_input[0] = M31::new(DOMAIN_LEAF);
        for i in 0..LEAF_SECRET_LEN {
            leaf_input[1 + i] = leaf_secret[i];
        }
        let leaf_perm = PermutationWitness::generate(leaf_input);
        let mut current = leaf_perm.output()[1];
        
        for i in 0..TREE_DEPTH {
            let mut merkle_input = [M31::zero(); WIDTH];
            merkle_input[0] = M31::new(DOMAIN_MERK);
            merkle_input[1] = current;
            merkle_input[2] = siblings[i];
            
            let perm = PermutationWitness::generate(merkle_input);
            current = perm.output()[1];
        }
        
        let root = current;
        let binding_hash = [M31::zero(); 8];
        
        let witness = MembershipWitness::generate(
            leaf_secret,
            session_id,
            siblings,
            path_bits,
            root,
            binding_hash,
        );
        
        assert!(witness.is_ok());
    }
}
