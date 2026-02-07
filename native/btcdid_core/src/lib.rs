// lib.rs - BTC DID Core Library
// Implements KeyManager, DLC Builder, STWO Prover, and Lightning payments

use anyhow::{Result, anyhow};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jstring, jlong};
use jni::JNIEnv;

use sha2::{Digest, Sha256};

// Module declarations
pub mod key_manager;
pub mod dlc_builder;
pub mod stwo_prover;
pub mod lightning;
pub mod dlc_oracle; // Keep for backwards compatibility

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

/// Sign a DLC outcome (as oracle)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_signDlcOutcome(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
) -> jstring {
    let outcome_str = env.get_string(&outcome)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Generate oracle key (in production, this would be stored/loaded)
    let oracle_key = match ManagedKey::generate() {
        Ok(k) => k,
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            return env.new_string(error_json).unwrap().into_raw();
        }
    };

    let dlc_outcome = if outcome_str == "paid=true" {
        DlcOutcome::Paid
    } else if outcome_str == "refund=true" {
        DlcOutcome::Refund
    } else {
        DlcOutcome::Custom(outcome_str)
    };

    match oracle_sign_outcome(&oracle_key, &dlc_outcome) {
        Ok(attestation) => {
            let json = serde_json::to_string_pretty(&attestation)
                .unwrap_or_else(|_| "{}".to_string());
            env.new_string(json).unwrap().into_raw()
        }
        Err(e) => {
            let error_json = format!(r#"{{"status":"error","error":"{}"}}"#, e);
            env.new_string(error_json).unwrap().into_raw()
        }
    }
}

/// Get oracle public key
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oraclePubkeyHex(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    // Return the standard oracle pubkey (generator point for testing)
    env.new_string("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .unwrap()
        .into_raw()
}

/// Oracle sign outcome (backwards compat)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_oracleSignOutcome(
    mut env: JNIEnv,
    _clazz: JClass,
    outcome: JString,
) -> jstring {
    // Delegate to the new function
    Java_com_privacylion_btcdid_NativeBridge_signDlcOutcome(env, _clazz, outcome)
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
