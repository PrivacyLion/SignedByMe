//! Merkle membership proofs for SignedByMe
//!
//! This module provides:
//! - V4 binding hash computation (must match Python exactly)
//! - SHA-256 based Merkle tree hashing (consistent across all platforms)
//! - Merkle tree construction and path verification
//! - Membership proof generation and verification
//!
//! IMPORTANT: We use SHA-256 (not Poseidon) for Merkle trees.
//! This ensures consistency between:
//! - Rust native library
//! - Python API server
//! - Verifier binary
//!
//! Privacy guarantees:
//! - Unlinkability: Same user proving to different employers cannot be correlated
//! - Anonymity: Verifier learns "user is in set" but not which member
//! - No correlators: leaf_commitment never exposed

pub mod binding;
pub mod merkle_hash;  // SHA-256 based Merkle hashing
pub mod poseidon;     // Legacy - kept for backwards compat, use merkle_hash instead
pub mod merkle;
pub mod proof;
pub mod jni;

pub use binding::{compute_binding_hash_v4, hash_field, SCHEMA_VERSION_V4, DOMAIN_SEPARATOR_V4};
pub use merkle_hash::{hash_pair as merkle_hash_pair, hash_leaf, verify_proof as verify_merkle_proof, build_tree};
pub use poseidon::{poseidon_hash_pair, poseidon_hash_bytes, PoseidonHasher, FieldElement};  // Legacy
pub use merkle::{MerkleTree, MerklePath, PathSibling, verify_merkle_path};
pub use proof::{MembershipProof, MembershipPublicInputs, MembershipWitness, prove_membership, verify_membership};

/// Purpose ID enum (circuit-friendly)
pub const PURPOSE_NONE: u8 = 0;
pub const PURPOSE_ALLOWLIST: u8 = 1;
pub const PURPOSE_ISSUER_BATCH: u8 = 2;
pub const PURPOSE_REVOCATION: u8 = 3;

/// Get purpose ID from string
pub fn get_purpose_id(purpose: &str) -> u8 {
    match purpose {
        "" => PURPOSE_NONE,
        "allowlist" => PURPOSE_ALLOWLIST,
        "issuer_batch" => PURPOSE_ISSUER_BATCH,
        "revocation" => PURPOSE_REVOCATION,
        _ => PURPOSE_NONE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purpose_ids() {
        assert_eq!(get_purpose_id(""), PURPOSE_NONE);
        assert_eq!(get_purpose_id("allowlist"), PURPOSE_ALLOWLIST);
        assert_eq!(get_purpose_id("issuer_batch"), PURPOSE_ISSUER_BATCH);
        assert_eq!(get_purpose_id("revocation"), PURPOSE_REVOCATION);
        assert_eq!(get_purpose_id("unknown"), PURPOSE_NONE);
    }
}
