// lib.rs - BTC DID Core Library
// Implements KeyManager, DLC Builder, STWO Prover, and Lightning payments

use anyhow::{Result, anyhow};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jstring, jlong, jboolean};
use jni::JNIEnv;

use sha2::{Digest, Sha256};

// Module declarations
pub mod key_manager;
pub mod dlc_builder;
pub mod stwo_prover;
pub mod lightning;
pub mod dlc_oracle; // Keep for backwards compatibility
pub mod membership; // Merkle membership proofs

// Real STWO module (only when feature enabled)
#[cfg(feature = "real-stwo")]
pub mod stwo_real;

// SHA-256 circuit for STWO (only when feature enabled)
#[cfg(feature = "real-stwo")]
pub mod sha256_circuit;

use key_manager::ManagedKey;
use dlc_builder::{DlcContract, DlcOutcome, OracleInfo, PayoutSplit, oracle_sign_outcome};
use stwo_prover::{StwoProver, CircuitType};
use lightning::{Preimage, PaymentRequestPackage, verify_payment};

// ============================================================================
// LEGACY JNI FUNCTIONS (for backwards compatibility)
// ============================================================================

/// Simple sanity check
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_helloFromRust(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    env.new_string("Hello from Rust core v2 (zkDLC-Mobile) 👋")
        .unwrap()
        .into_raw()
}

/// SHA-256 helper
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_sha256Hex(
    mut env: JNIEnv,
    _clazz: JClass,
    input: JString,
) -> jstring {
    let s = match env.get_string(&input) {
        Ok(js) => js.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error").unwrap().into_raw(),
    };
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hex = hex::encode(hasher.finalize());
    env.new_string(hex).unwrap().into_raw()
}

/// Generate 32-byte secp256k1 private key
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generateSecp256k1PrivateKey(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jbyteArray {
    match ManagedKey::generate() {
        Ok(key) => {
            let bytes = key.secret_key.secret_bytes();
            env.byte_array_from_slice(&bytes).unwrap().into_raw()
        }
        Err(_) => {
            // Fallback to random bytes
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).unwrap();
            env.byte_array_from_slice(&bytes).unwrap().into_raw()
        }
    }
}

/// Derive compressed public key hex from private key bytes
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_derivePublicKeyHex(
    mut env: JNIEnv,
    _clazz: JClass,
    priv_bytes: JByteArray,
) -> jstring {
    let bytes = match env.convert_byte_array(priv_bytes) {
        Ok(b) => b,
        Err(_) => return env.new_string("error").unwrap().into_raw(),
    };
    
    match ManagedKey::from_bytes(&bytes) {
        Ok(key) => env.new_string(key.pubkey_hex()).unwrap().into_raw(),
        Err(_) => env.new_string("error").unwrap().into_raw(),
    }
}

/// Sign message with secp256k1 key (DER sig hex)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_signMessageDerHex(
    mut env: JNIEnv,
    _clazz: JClass,
    priv_bytes: JByteArray,
    msg_jstr: JString,
) -> jstring {
    let priv_vec = match env.convert_byte_array(priv_bytes) {
        Ok(v) => v,
        Err(_) => return env.new_string("error:no_priv_bytes").unwrap().into_raw(),
    };

    let msg_str = match env.get_string(&msg_jstr) {
        Ok(js) => js.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:no_msg").unwrap().into_raw(),
    };

    let key = match ManagedKey::from_bytes(&priv_vec) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };

    match key.sign_ecdsa(msg_str.as_bytes()) {
        Ok(sig) => env.new_string(sig).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

// ============================================================================
// STWO PROVER JNI FUNCTIONS
// ============================================================================

/// Generate STWO proof for various circuit types
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generateStwoProof(
    mut env: JNIEnv,
    _clazz: JClass,
    circuit: JString,
    input_hash_hex: JString,
    output_hash_hex: JString,
) -> jstring {
    let circuit_s = env.get_string(&circuit)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let in_hex = env.get_string(&input_hash_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let out_hex = env.get_string(&output_hash_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let prover = StwoProver::default();
    
    let result = match CircuitType::from_str(&circuit_s) {
        Some(CircuitType::HashIntegrity) => prover.prove_hash_integrity(&in_hex, &out_hex),
        Some(CircuitType::ContentTransform) => prover.prove_content_transform(&in_hex, "default", &out_hex),
        Some(CircuitType::LoginProof) => {
            // For login proof, input_hash is nonce, output_hash is device_hash
            prover.prove_login(&in_hex, &out_hex, std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), "")
        }
        Some(CircuitType::SignatureValidation) => prover.prove_signature_validation(&in_hex, &out_hex, ""),
        Some(CircuitType::PaymentTriggerHash) => prover.prove_payment_trigger("", &in_hex, &out_hex),
        Some(CircuitType::IdentityProof) => {
            // For identity proof, use the dedicated function
            Err(anyhow!("Use generateIdentityProof() for identity proofs"))
        }
        None => Err(anyhow!("Unknown circuit type: {}", circuit_s)),
    };

    match result {
        Ok(proof) => {
            let json = proof.to_json().unwrap_or_else(|_| "{}".to_string());
            env.new_string(json).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Generate an Identity Proof binding DID to wallet ownership
/// This is the core proof for SignedByMe - generated in Step 3
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generateIdentityProof(
    mut env: JNIEnv,
    _clazz: JClass,
    did_pubkey: JString,
    wallet_address: JString,
    wallet_signature: JString,
    expiry_days: jlong,
) -> jstring {
    let did = env.get_string(&did_pubkey)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let wallet = env.get_string(&wallet_address)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sig = env.get_string(&wallet_signature)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let prover = StwoProver::default();
    
    match prover.prove_identity(&did, &wallet, &sig, timestamp, expiry_days as u32) {
        Ok(proof) => {
            let json = proof.to_json().unwrap_or_else(|_| "{}".to_string());
            env.new_string(json).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Verify an Identity Proof
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_verifyIdentityProof(
    mut env: JNIEnv,
    _clazz: JClass,
    proof_json: JString,
) -> jstring {
    let json_str = env.get_string(&proof_json)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    
    let proof: stwo_prover::StwoProof = match serde_json::from_str(&json_str) {
        Ok(p) => p,
        Err(e) => {
            let error_json = format!(r#"{{"valid":false,"error":"Invalid proof JSON: {}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };
    
    let prover = StwoProver::default();
    
    match prover.verify_identity(&proof) {
        Ok(valid) => {
            let result = serde_json::json!({
                "valid": valid,
                "did_pubkey": proof.public_inputs.did_pubkey,
                "wallet_address": proof.public_inputs.wallet_address,
                "expires_at": proof.public_inputs.expires_at,
            });
            env.new_string(result.to_string()).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = format!(r#"{{"valid":false,"error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

// ============================================================================
// DLC BUILDER JNI FUNCTIONS
// ============================================================================

/// Create a DLC contract
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_createDlcContract(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
    payouts_json: JString,
    oracle_json: JString,
) -> jstring {
    let _outcome = env.get_string(&outcome)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let payouts = env.get_string(&payouts_json)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let oracle = env.get_string(&oracle_json)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Parse oracle info
    let oracle_info = match serde_json::from_str::<OracleInfo>(&oracle) {
        Ok(o) => o,
        Err(_) => OracleInfo {
            name: "local_oracle".to_string(),
            pubkey_hex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            x_only_pubkey: None,
        },
    };

    // Parse payout split
    let split = match serde_json::from_str::<PayoutSplit>(&payouts) {
        Ok(s) => s,
        Err(_) => PayoutSplit::default(),
    };

    // Generate a key for the contract (in production, this would come from the user)
    let user_key = match ManagedKey::generate() {
        Ok(k) => k,
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };

    match DlcContract::new(&user_key, oracle_info, 0, split) {
        Ok(contract) => {
            let json = contract.to_json().unwrap_or_else(|_| "{}".to_string());
            env.new_string(json).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Sign a DLC outcome with real Schnorr signature (steps 14-15)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_signDlcOutcome(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
) -> jstring {
    let outcome_str = env.get_string(&outcome)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Use the deterministic local oracle with real Schnorr signing
    let json = dlc_oracle::oracle_sign_outcome(&outcome_str);
    env.new_string(json).unwrap().into_raw()
}

/// Get oracle x-only public key (BIP340 format)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oraclePubkeyHex(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    // Return the real oracle's x-only pubkey (deterministic)
    env.new_string(dlc_oracle::oracle_pubkey_hex())
        .unwrap()
        .into_raw()
}

/// Oracle sign outcome (alias for signDlcOutcome)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oracleSignOutcome(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
) -> jstring {
    Java_com_privacylion_btcdid_NativeBridge_signDlcOutcome(env, _clazz, outcome)
}

/// Acknowledge oracle signing policy for a contract (steps 7-8)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oracleAcknowledgePolicy(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
    contract_id: JString,
) -> jstring {
    let outcome_str = env.get_string(&outcome)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let contract_str = env.get_string(&contract_id)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let json = dlc_oracle::oracle_acknowledge_policy(&outcome_str, &contract_str);
    env.new_string(json).unwrap().into_raw()
}

/// Verify an oracle attestation signature
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oracleVerifyAttestation(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
    signature_hex: JString,
    pubkey_hex: JString,
) -> jboolean {
    let outcome_str = env.get_string(&outcome)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sig_str = env.get_string(&signature_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let pubkey_str = env.get_string(&pubkey_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let is_valid = dlc_oracle::oracle_verify_attestation(&outcome_str, &sig_str, &pubkey_str);
    if is_valid { 1 } else { 0 }
}

// ============================================================================
// LIGHTNING PAYMENT JNI FUNCTIONS
// ============================================================================

/// Generate a Lightning preimage and payment hash
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generatePreimage(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    let preimage = Preimage::generate();
    let json = serde_json::json!({
        "preimage_hex": preimage.preimage_hex,
        "payment_hash": preimage.hash.hash_hex,
    });
    env.new_string(json.to_string()).unwrap().into_raw()
}

/// Verify a payment (preimage against payment hash)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_verifyPayment(
    mut env: JNIEnv,
    _clazz: JClass,
    payment_hash: JString,
    preimage_hex: JString,
) -> jstring {
    let hash = env.get_string(&payment_hash)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let preimage = env.get_string(&preimage_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let result = verify_payment(&hash, &preimage);
    let json = serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json).unwrap().into_raw()
}

/// Extract payment hash from a BOLT11 invoice using proper decoding
/// 
/// SECURITY: This uses the lightning-invoice crate for proper BOLT11 parsing.
/// Never use string hashing to extract payment hash.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_extractPaymentHashFromBolt11(
    mut env: JNIEnv,
    _clazz: JClass,
    bolt11: JString,
) -> jstring {
    use lightning_invoice::Bolt11Invoice;
    use std::str::FromStr;
    
    let invoice_str = match env.get_string(&bolt11) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:invalid_string").unwrap().into_raw(),
    };
    
    // Parse the BOLT11 invoice
    match Bolt11Invoice::from_str(&invoice_str) {
        Ok(invoice) => {
            // Extract the payment hash
            let payment_hash = invoice.payment_hash();
            // Use as_byte_array() since the inner field is private
            let hash_hex = hex::encode(payment_hash.to_byte_array());
            env.new_string(hash_hex).unwrap().into_raw()
        }
        Err(e) => {
            let error_msg = format!("error:bolt11_parse_failed:{}", e);
            env.new_string(error_msg).unwrap().into_raw()
        }
    }
}

/// Create a Payment Request Package (PRP)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_createPrp(
    mut env: JNIEnv,
    _clazz: JClass,
    amount_sats: jlong,
    description: JString,
    payee_did: JString,
    payee_ln_address: JString,
    expiry_secs: jlong,
) -> jstring {
    let desc = env.get_string(&description)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let did = env.get_string(&payee_did)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ln_addr = env.get_string(&payee_ln_address)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let preimage = Preimage::generate();
    let prp = PaymentRequestPackage::new(
        &preimage,
        amount_sats as u64,
        &desc,
        &did,
        &ln_addr,
        expiry_secs as u32,
    );

    match prp.to_json() {
        Ok(json) => {
            // Include the preimage in the response (for the payee to verify later)
            let full_json = serde_json::json!({
                "prp": serde_json::from_str::<serde_json::Value>(&json).unwrap_or_default(),
                "preimage_hex": preimage.preimage_hex,
            });
            env.new_string(full_json.to_string()).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Sign a message with Schnorr (for Taproot/DLC)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_signSchnorr(
    mut env: JNIEnv,
    _clazz: JClass,
    priv_bytes: JByteArray,
    msg_jstr: JString,
) -> jstring {
    let priv_vec = match env.convert_byte_array(priv_bytes) {
        Ok(v) => v,
        Err(_) => return env.new_string("error:no_priv_bytes").unwrap().into_raw(),
    };

    let msg_str = match env.get_string(&msg_jstr) {
        Ok(js) => js.to_string_lossy().into_owned(),
        Err(_) => return env.new_string("error:no_msg").unwrap().into_raw(),
    };

    let key = match ManagedKey::from_bytes(&priv_vec) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };

    match key.sign_schnorr(msg_str.as_bytes()) {
        Ok(sig) => env.new_string(sig).unwrap().into_raw(),
        Err(e) => env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    }
}

/// Get x-only public key (for Taproot)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_getXOnlyPubkey(
    mut env: JNIEnv,
    _clazz: JClass,
    priv_bytes: JByteArray,
) -> jstring {
    let priv_vec = match env.convert_byte_array(priv_bytes) {
        Ok(v) => v,
        Err(_) => return env.new_string("error:no_priv_bytes").unwrap().into_raw(),
    };

    let key = match ManagedKey::from_bytes(&priv_vec) {
        Ok(k) => k,
        Err(e) => return env.new_string(format!("error:{}", e)).unwrap().into_raw(),
    };

    env.new_string(key.x_only_pubkey_hex()).unwrap().into_raw()
}

// ============================================================================
// REAL STWO PROVER JNI FUNCTIONS (only available with real-stwo feature)
// ============================================================================

/// Generate a REAL STWO identity proof v4 (SHA-256 STARK circuit)
/// This proves knowledge of the preimage that hashes to the binding hash.
/// The circuit implements SHA-256 compression rounds as STARK constraints.
/// Includes all v4 fields: client_id, session_id, purpose_id, root_id for full binding
#[cfg(feature = "real-stwo")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generateRealIdentityProofV4(
    mut env: JNIEnv,
    _clazz: JClass,
    did_pubkey_hex: JString,
    wallet_address: JString,
    client_id: JString,
    session_id: JString,
    payment_hash_hex: JString,
    amount_sats: jlong,
    expires_at: jlong,
    ea_domain: JString,
    nonce_hex: JString,
    purpose_id: jlong,
    root_id: JString,
) -> jstring {
    use stwo_real::prove_identity_binding;
    
    let did_hex = env.get_string(&did_pubkey_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let wallet = env.get_string(&wallet_address)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let client = env.get_string(&client_id)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let session = env.get_string(&session_id)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let payment_hex = env.get_string(&payment_hash_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let domain = env.get_string(&ea_domain)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let nonce_str = env.get_string(&nonce_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let root = env.get_string(&root_id)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    
    // Parse hex inputs
    let did_bytes = match hex::decode(&did_hex) {
        Ok(b) => b,
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"Invalid DID hex: {}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };
    
    let payment_hash: [u8; 32] = match hex::decode(&payment_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(_) => {
            let error_json = r#"{"status":"error","error":"Payment hash must be 32 bytes"}"#;
            return env.new_string(error_json).unwrap().into_raw();
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"Invalid payment hash hex: {}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };
    
    let nonce: [u8; 16] = match hex::decode(&nonce_str) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(_) => {
            let error_json = r#"{"status":"error","error":"Nonce must be 16 bytes (32 hex chars)"}"#;
            return env.new_string(error_json).unwrap().into_raw();
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"Invalid nonce hex: {}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };
    
    match prove_identity_binding(
        &did_bytes,
        &wallet,
        &client,
        &session,
        &payment_hash,
        amount_sats as u64,
        expires_at as u64,
        &domain,
        &nonce,
        purpose_id as u8,
        &root,
    ) {
        Ok(proof) => {
            match serde_json::to_string(&proof) {
                Ok(json) => env.new_string(json).unwrap().into_raw(),
                Err(e) => {
                    let error_json = format!(r#"{{"status":"error","error":"JSON serialization failed: {}"}}"#, e);
                    env.new_string(error_json).unwrap().into_raw()
                }
            }
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Generate a REAL STWO identity proof v3 (legacy, redirects to v4)
/// For backwards compatibility - calls v4 with default client/session/purpose/root
#[cfg(feature = "real-stwo")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generateRealIdentityProofV3(
    mut env: JNIEnv,
    _clazz: JClass,
    did_pubkey_hex: JString,
    wallet_address: JString,
    payment_hash_hex: JString,
    amount_sats: jlong,
    expires_at: jlong,
    ea_domain: JString,
    nonce_hex: JString,
) -> jstring {
    use stwo_real::prove_identity_binding;
    
    let did_hex = env.get_string(&did_pubkey_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let wallet = env.get_string(&wallet_address)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let payment_hex = env.get_string(&payment_hash_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let domain = env.get_string(&ea_domain)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let nonce_str = env.get_string(&nonce_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    
    // Parse hex inputs
    let did_bytes = match hex::decode(&did_hex) {
        Ok(b) => b,
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"Invalid DID hex: {}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };
    
    let payment_hash: [u8; 32] = match hex::decode(&payment_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(_) => {
            let error_json = r#"{"status":"error","error":"Payment hash must be 32 bytes"}"#;
            return env.new_string(error_json).unwrap().into_raw();
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"Invalid payment hash hex: {}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };
    
    let nonce: [u8; 16] = match hex::decode(&nonce_str) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(_) => {
            let error_json = r#"{"status":"error","error":"Nonce must be 16 bytes (32 hex chars)"}"#;
            return env.new_string(error_json).unwrap().into_raw();
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"Invalid nonce hex: {}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };
    
    // Call v4 with default values for new fields
    match prove_identity_binding(
        &did_bytes,
        &wallet,
        "legacy_v3",  // client_id
        "legacy_v3",  // session_id
        &payment_hash,
        amount_sats as u64,
        expires_at as u64,
        &domain,
        &nonce,
        0,   // purpose_id = none
        "",  // root_id = empty
    ) {
        Ok(proof) => {
            match serde_json::to_string(&proof) {
                Ok(json) => env.new_string(json).unwrap().into_raw(),
                Err(e) => {
                    let error_json = format!(r#"{{"status":"error","error":"JSON serialization failed: {}"}}"#, e);
                    env.new_string(error_json).unwrap().into_raw()
                }
            }
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Generate a REAL STWO identity proof (v1 backwards compat)
/// Uses the legacy v2 hash format for existing deployments
#[cfg(feature = "real-stwo")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generateRealIdentityProof(
    mut env: JNIEnv,
    _clazz: JClass,
    did_pubkey_hex: JString,
    wallet_address: JString,
    payment_hash_hex: JString,
    expiry_days: jlong,
) -> jstring {
    use stwo_real::prove_identity_binding_v1;
    
    let did_hex = env.get_string(&did_pubkey_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let wallet = env.get_string(&wallet_address)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let payment_hex = env.get_string(&payment_hash_hex)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    
    // Parse hex inputs
    let did_bytes = match hex::decode(&did_hex) {
        Ok(b) => b,
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"Invalid DID hex: {}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };
    
    let payment_hash: [u8; 32] = match hex::decode(&payment_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(_) => {
            let error_json = r#"{"status":"error","error":"Payment hash must be 32 bytes"}"#;
            return env.new_string(error_json).unwrap().into_raw();
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"Invalid payment hash hex: {}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    match prove_identity_binding_v1(&did_bytes, &wallet, &payment_hash, timestamp, expiry_days as u32) {
        Ok(proof) => {
            match serde_json::to_string(&proof) {
                Ok(json) => env.new_string(json).unwrap().into_raw(),
                Err(e) => {
                    let error_json = format!(r#"{{"status":"error","error":"JSON serialization failed: {}"}}"#, e);
                    env.new_string(error_json).unwrap().into_raw()
                }
            }
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Verify a REAL STWO identity proof
#[cfg(feature = "real-stwo")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_verifyRealIdentityProof(
    mut env: JNIEnv,
    _clazz: JClass,
    proof_json: JString,
) -> jstring {
    use stwo_real::verify_proof_json;
    
    let json_str = env.get_string(&proof_json)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    
    match verify_proof_json(&json_str) {
        Ok(valid) => {
            let result = serde_json::json!({
                "valid": valid,
                "real_stwo": true,
            });
            env.new_string(result.to_string()).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = format!(r#"{{"valid":false,"real_stwo":true,"error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Check if real STWO is available
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_hasRealStwo(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jboolean {
    #[cfg(feature = "real-stwo")]
    { 1 }
    #[cfg(not(feature = "real-stwo"))]
    { 0 }
}
