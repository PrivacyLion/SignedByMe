// stwo_dlc_bridge.h - C Interface to btcdid_core Rust Library
// SignedByMe iOS - Full feature parity with Android
// Auto-generated header for Rust FFI

#ifndef STWO_DLC_BRIDGE_H
#define STWO_DLC_BRIDGE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Memory Management
// ============================================================================

/// Free a string returned by Rust
void sbm_free_string(char *ptr);

/// Free a byte buffer returned by Rust
void sbm_free_bytes(uint8_t *ptr, size_t len);

// ============================================================================
// Basic Functions
// ============================================================================

/// Returns a hello string from Rust (for sanity check)
char *sbm_hello_from_rust(void);

/// Compute SHA-256 hash of input string, returns hex
char *sbm_sha256_hex(const char *input);

// ============================================================================
// Key Management (secp256k1)
// ============================================================================

/// Generate a random 32-byte secp256k1 private key
/// Returns: pointer to 32 bytes (caller must free with sbm_free_bytes)
uint8_t *sbm_generate_private_key(void);

/// Derive compressed public key hex (33 bytes) from private key
/// priv_key: pointer to 32 bytes
/// Returns: hex string (caller must free with sbm_free_string)
char *sbm_derive_public_key_hex(const uint8_t *priv_key, size_t priv_len);

/// Get x-only public key hex (32 bytes) for Taproot/Schnorr
char *sbm_get_x_only_pubkey(const uint8_t *priv_key, size_t priv_len);

/// Sign message with ECDSA (returns DER hex signature)
char *sbm_sign_message_der_hex(const uint8_t *priv_key, size_t priv_len,
                               const char *message);

/// Sign message with Schnorr (returns 64-byte signature hex)
char *sbm_sign_schnorr(const uint8_t *priv_key, size_t priv_len,
                       const char *message);

// ============================================================================
// STWO Prover (Zero-Knowledge Proofs)
// ============================================================================

/// Check if real STWO is compiled in
bool sbm_has_real_stwo(void);

/// Generate STWO proof for circuit
/// Circuit types: "hash_integrity", "content_transform", "login_proof", etc.
char *sbm_generate_stwo_proof(const char *circuit,
                              const char *input_hash_hex,
                              const char *output_hash_hex);

/// Generate Identity Proof (Step 3 onboarding)
char *sbm_generate_identity_proof(const char *did_pubkey,
                                  const char *wallet_address,
                                  const char *wallet_signature,
                                  int64_t expiry_days);

/// Verify an Identity Proof
char *sbm_verify_identity_proof(const char *proof_json);

/// Generate REAL STWO Identity Proof V3 (full security bindings)
/// did_pubkey_hex: DID public key (hex)
/// wallet_address: Wallet address string
/// payment_hash_hex: 32-byte Lightning payment hash (hex)
/// amount_sats: Payment amount in satoshis
/// expires_at: Unix timestamp
/// ea_domain: Enterprise domain
/// nonce_hex: 16-byte session nonce (hex)
char *sbm_generate_real_identity_proof_v3(const char *did_pubkey_hex,
                                          const char *wallet_address,
                                          const char *payment_hash_hex,
                                          int64_t amount_sats,
                                          int64_t expires_at,
                                          const char *ea_domain,
                                          const char *nonce_hex);

/// Generate REAL STWO Identity Proof (v1 legacy)
char *sbm_generate_real_identity_proof(const char *did_pubkey_hex,
                                       const char *wallet_address,
                                       const char *payment_hash_hex,
                                       int64_t expiry_days);

/// Verify a REAL STWO proof
char *sbm_verify_real_identity_proof(const char *proof_json);

// ============================================================================
// DLC (Discreet Log Contracts)
// ============================================================================

/// Get oracle x-only public key (BIP340, 32 bytes hex)
char *sbm_oracle_pubkey_hex(void);

/// Sign outcome as oracle (real Schnorr)
char *sbm_oracle_sign_outcome(const char *outcome);

/// Acknowledge signing policy for contract
char *sbm_oracle_acknowledge_policy(const char *outcome, const char *contract_id);

/// Verify oracle attestation signature
bool sbm_oracle_verify_attestation(const char *outcome,
                                   const char *signature_hex,
                                   const char *pubkey_hex);

/// Create DLC contract
char *sbm_create_dlc_contract(const char *outcome,
                              const char *payouts_json,
                              const char *oracle_json);

/// Sign DLC outcome (alias for oracle_sign_outcome)
char *sbm_sign_dlc_outcome(const char *outcome);

// ============================================================================
// Lightning Payments
// ============================================================================

/// Generate preimage and payment hash
/// Returns: JSON with preimage_hex and payment_hash
char *sbm_generate_preimage(void);

/// Verify payment (preimage against payment hash)
char *sbm_verify_payment(const char *payment_hash, const char *preimage_hex);

/// Create Payment Request Package (PRP)
char *sbm_create_prp(int64_t amount_sats,
                     const char *description,
                     const char *payee_did,
                     const char *payee_ln_address,
                     int64_t expiry_secs);

// ============================================================================
// Membership Proofs (Merkle Tree)
// ============================================================================

/// Generate membership proof
/// leaf_secret: 32 bytes
/// merkle_path: array of 20 siblings, each 32 bytes (flatten to 640 bytes)
/// path_indices: 20 bytes (0=left, 1=right)
/// root: 32 bytes
/// binding_hash: 32 bytes (from sbm_compute_binding_hash_v4)
/// purpose_id: 0=none, 1=allowlist, 2=issuer_batch, 3=revocation
/// out_len: receives output length
/// Returns: proof bytes (caller must free with sbm_free_bytes)
uint8_t *sbm_prove_membership(const uint8_t *leaf_secret,
                              const uint8_t *merkle_path,  // 20 * 32 = 640 bytes
                              const uint8_t *path_indices, // 20 bytes
                              const uint8_t *root,         // 32 bytes
                              const uint8_t *binding_hash, // 32 bytes
                              int32_t purpose_id,
                              size_t *out_len);

/// Verify membership proof locally
bool sbm_verify_membership(const uint8_t *proof, size_t proof_len,
                           const uint8_t *root,
                           const uint8_t *binding_hash,
                           int32_t purpose_id);

/// Compute V4 binding hash
/// did_pubkey: DID public key bytes
/// did_pubkey_len: length of did_pubkey
/// wallet_address: wallet address string
/// client_id: enterprise client ID
/// session_id: session ID
/// payment_hash: 32 bytes
/// amount_sats: payment amount
/// expires_at: Unix timestamp
/// nonce: 16 bytes
/// ea_domain: enterprise domain
/// purpose_id: membership purpose
/// root_id: root ID string
/// Returns: 32-byte binding hash (caller must free with sbm_free_bytes)
uint8_t *sbm_compute_binding_hash_v4(const uint8_t *did_pubkey, size_t did_pubkey_len,
                                     const char *wallet_address,
                                     const char *client_id,
                                     const char *session_id,
                                     const uint8_t *payment_hash,
                                     int64_t amount_sats,
                                     int64_t expires_at,
                                     const uint8_t *nonce,
                                     const char *ea_domain,
                                     int32_t purpose_id,
                                     const char *root_id);

/// Compute leaf commitment from leaf secret
/// leaf_secret: 32 bytes (NEVER log or transmit!)
/// Returns: 32-byte commitment (caller must free with sbm_free_bytes)
uint8_t *sbm_compute_leaf_commitment(const uint8_t *leaf_secret);

// ============================================================================
// Legacy Functions (backwards compatibility)
// ============================================================================

// These map to the original function names for existing code
char *generate_stwo_proof(const char *circuit, const char *input_hash, const char *output_hash);
void free_proof(char *ptr);
char *create_dlc_contract(const char *outcome, const double *payout, int payout_len, const char *oracle);
void free_contract(char *ptr);
char *sign_dlc_outcome(const char *outcome);
void free_signature(char *ptr);

#ifdef __cplusplus
}
#endif

#endif // STWO_DLC_BRIDGE_H
