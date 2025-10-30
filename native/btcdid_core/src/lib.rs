use anyhow::{Result, anyhow};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jstring};
use jni::JNIEnv;

use sha2::{Digest, Sha256};
use hex;

use k256::SecretKey;
use k256::ecdsa::{SigningKey, VerifyingKey, Signature};
use rand_core::OsRng;

/// ===== Simple sanity check (kept) =====
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_helloFromRust(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jstring {
    hello()
        .map(|s| env.new_string(s).unwrap().into_raw())
        .unwrap_or_else(|_| env.new_string("rust error").unwrap().into_raw())
}

/// ===== SHA-256 helper (kept) =====
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
    let hex = sha256_hex(&s).unwrap_or_else(|_| "error".to_string());
    env.new_string(hex).unwrap().into_raw()
}

/// ===== generate 32-byte secp256k1 private key =====
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generateSecp256k1PrivateKey(
    mut env: JNIEnv,
    _clazz: JClass,
) -> jbyteArray {
    // Random secp256k1 secret; OsRng works on Android
    let sk = SigningKey::random(&mut OsRng);
    let bytes = sk.to_bytes(); // 32 bytes
    env.byte_array_from_slice(bytes.as_slice()).unwrap().into_raw()
}

/// ===== derive compressed public key hex from private key bytes =====
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
    let hexstr = match derive_pub_hex_from_priv(&bytes) {
        Ok(h) => h,
        Err(_) => "error".to_string(),
    };
    env.new_string(hexstr).unwrap().into_raw()
}

/// ===== sign message with secp256k1 key (DER sig hex) =====
/// JNI name must EXACTLY match what Kotlin calls: signMessageDerHex(byte[], String)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_signMessageDerHex(
    mut env: JNIEnv,
    _clazz: JClass,
    priv_bytes: JByteArray,
    msg_jstr: JString,
) -> jstring {
    // 1. get raw 32-byte private key from JVM
    let priv_vec = match env.convert_byte_array(priv_bytes) {
        Ok(v) => v,
        Err(_) => {
            return env
                .new_string("error:no_priv_bytes")
                .unwrap()
                .into_raw();
        }
    };

    // 2. get message string from JVM
    let msg_str = match env.get_string(&msg_jstr) {
        Ok(js) => js.to_string_lossy().into_owned(),
        Err(_) => {
            return env
                .new_string("error:no_msg")
                .unwrap()
                .into_raw();
        }
    };

    // 3. sign it and hex-encode DER output
    let sig_hex = match sign_message_der_hex(&priv_vec, &msg_str) {
        Ok(h) => h,
        Err(e) => format!("error:{}", e),
    };

    // 4. wipe the temp key buffer (best-effort scrub)
    let mut priv_wipe = priv_vec;
    for b in &mut priv_wipe {
        *b = 0;
    }

    env.new_string(sig_hex).unwrap().into_raw()
}

/// ---- helper: returns "Hello from Rust core 👋" ----
fn hello() -> Result<String> {
    Ok("Hello from Rust core 👋".to_string())
}

/// ---- helper: sha256(string) -> hex ----
fn sha256_hex(s: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// ---- helper: derive compressed pubkey from 32-byte privkey -> hex ----
fn derive_pub_hex_from_priv(bytes: &[u8]) -> Result<String> {
    // Parse 32-byte secp256k1 secret
    let sk = SecretKey::from_slice(bytes).map_err(|_| anyhow!("bad secp256k1 key"))?;

    // Turn SecretKey -> SigningKey
    let signing: SigningKey = sk.into();

    // Grab public key
    let vk: VerifyingKey = signing.verifying_key().clone();

    // Compressed SEC1 (33 bytes). We hex that.
    Ok(hex::encode(vk.to_encoded_point(true).as_bytes()))
}

/// ---- helper: sign message -> DER sig hex ----
/// We do: sig = ECDSA_sign( sha256(message) )
fn sign_message_der_hex(priv_bytes: &[u8], msg: &str) -> Result<String> {
    // convert priv bytes into k256 SigningKey
    let sk = SecretKey::from_slice(priv_bytes)
        .map_err(|_| anyhow!("bad secp256k1 key"))?;
    let signing_key: SigningKey = sk.into();

    // hash message first (like we will on iOS)
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let digest = hasher.finalize();

    // sign digest → DER ECDSA
    use k256::ecdsa::signature::Signer; // trait for .sign()
    let sig: Signature = signing_key.sign(&digest);

    // sig.to_der() gives a DER object that can be seen as bytes with .as_bytes()
    let der_obj = sig.to_der();
    let der_bytes = der_obj.as_bytes();

    // return DER bytes as lowercase hex
    Ok(hex::encode(der_bytes))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_generateStwoProof(
    mut env: jni::JNIEnv,
    _clazz: jni::objects::JClass,
    circuit: jni::objects::JString,
    input_hash: jni::objects::JString,
    output_hash: jni::objects::JString,
) -> jni::sys::jstring {
    let _c = env.get_string(&circuit).map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let _i = env.get_string(&input_hash).map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let _o = env.get_string(&output_hash).map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    env.new_string("{\"status\":\"ok\",\"proof\":\"stub\"}").unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_createDlcContract(
    mut env: jni::JNIEnv,
    _clazz: jni::objects::JClass,
    outcome: jni::objects::JString,
    payouts_json: jni::objects::JString,
    oracle_json: jni::objects::JString,
) -> jni::sys::jstring {
    let _ = (outcome, payouts_json, oracle_json);
    env.new_string("{\"status\":\"ok\",\"contract_id\":\"stub-contract\"}").unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_signDlcOutcome(
    mut env: jni::JNIEnv,
    _clazz: jni::objects::JClass,
    outcome: jni::objects::JString,
) -> jni::sys::jstring {
    let _ = outcome;
    env.new_string("{\"status\":\"ok\",\"sig\":\"stub-sig\"}").unwrap().into_raw()
}
