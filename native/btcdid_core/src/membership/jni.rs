//! JNI Bindings for Membership Proofs
//!
//! Provides Android native methods for:
//! - proveMembership: Generate a membership proof (v2 - with nullifier)
//! - verifyMembership: Verify a membership proof
//! - computeLeafCommitment: Compute leaf from secret (SHA-256)

use jni::objects::{JByteArray, JClass, JObjectArray};
use jni::sys::{jboolean, jbyteArray, jint, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use sha2::{Sha256, Digest};

use super::proof::{prove_membership, verify_membership, MembershipProof};

/// Domain separator for leaf commitment (must match proof.rs)
const LEAF_COMMITMENT_DOMAIN: &[u8] = b"leaf_commit:";

/// Prove membership (called from Kotlin) - v2 API with session_id
///
/// Signature: (
///     leafSecret: ByteArray,         // 32 bytes
///     merkleSiblings: Array<ByteArray>, // Array of 32-byte siblings
///     pathBits: ByteArray,           // 0 or 1 for each level (sibling position)
///     root: ByteArray,               // 32 bytes
///     bindingHash: ByteArray,        // 32 bytes
///     sessionId: ByteArray,          // 32 bytes (for nullifier)
///     purposeId: Int
/// ) -> ByteArray (proof)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_proveMembership<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    leaf_secret: JByteArray<'local>,
    merkle_siblings: JObjectArray<'local>,
    path_bits: JByteArray<'local>,
    root: JByteArray<'local>,
    binding_hash: JByteArray<'local>,
    session_id: JByteArray<'local>,
    purpose_id: jint,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>, String> {
        // Parse leaf_secret
        let leaf_secret_vec = env.convert_byte_array(&leaf_secret)
            .map_err(|e| e.to_string())?;
        if leaf_secret_vec.len() != 32 {
            return Err("leaf_secret must be 32 bytes".into());
        }
        let mut leaf_secret_arr = [0u8; 32];
        leaf_secret_arr.copy_from_slice(&leaf_secret_vec);
        
        // Parse merkle siblings
        let path_len = env.get_array_length(&merkle_siblings)
            .map_err(|e| e.to_string())? as usize;
        let path_bits_vec = env.convert_byte_array(&path_bits)
            .map_err(|e| e.to_string())?;
        
        if path_bits_vec.len() != path_len {
            return Err("path_bits length must match merkle_siblings length".into());
        }
        
        let mut siblings: Vec<[u8; 32]> = Vec::with_capacity(path_len);
        let mut bits: Vec<bool> = Vec::with_capacity(path_len);
        
        for i in 0..path_len {
            let sibling_obj = env.get_object_array_element(&merkle_siblings, i as i32)
                .map_err(|e| e.to_string())?;
            let sibling_arr: JByteArray = sibling_obj.into();
            let sibling_vec = env.convert_byte_array(&sibling_arr)
                .map_err(|e| e.to_string())?;
            
            if sibling_vec.len() != 32 {
                return Err(format!("sibling {} must be 32 bytes", i));
            }
            
            let mut sibling = [0u8; 32];
            sibling.copy_from_slice(&sibling_vec);
            siblings.push(sibling);
            bits.push(path_bits_vec[i] != 0);
        }
        
        // Parse root
        let root_vec = env.convert_byte_array(&root)
            .map_err(|e| e.to_string())?;
        if root_vec.len() != 32 {
            return Err("root must be 32 bytes".into());
        }
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&root_vec);
        
        // Parse binding_hash
        let binding_hash_vec = env.convert_byte_array(&binding_hash)
            .map_err(|e| e.to_string())?;
        if binding_hash_vec.len() != 32 {
            return Err("binding_hash must be 32 bytes".into());
        }
        let mut binding_hash_arr = [0u8; 32];
        binding_hash_arr.copy_from_slice(&binding_hash_vec);
        
        // Parse session_id
        let session_id_vec = env.convert_byte_array(&session_id)
            .map_err(|e| e.to_string())?;
        if session_id_vec.len() != 32 {
            return Err("session_id must be 32 bytes".into());
        }
        let mut session_id_arr = [0u8; 32];
        session_id_arr.copy_from_slice(&session_id_vec);
        
        // Generate proof (v2 - with nullifier, no leaf leak)
        let proof = prove_membership(
            &leaf_secret_arr,
            &siblings,
            &bits,
            &root_arr,
            &binding_hash_arr,
            &session_id_arr,
            purpose_id as u8,
        )?;
        
        Ok(proof.data)
    })();
    
    match result {
        Ok(data) => {
            match env.byte_array_from_slice(&data) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

/// Verify membership (called from Kotlin) - v2 API with session_id
///
/// Signature: (
///     proof: ByteArray,
///     root: ByteArray,            // 32 bytes
///     bindingHash: ByteArray,     // 32 bytes
///     sessionId: ByteArray,       // 32 bytes
///     purposeId: Int
/// ) -> Boolean
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_verifyMembership<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    proof: JByteArray<'local>,
    root: JByteArray<'local>,
    binding_hash: JByteArray<'local>,
    session_id: JByteArray<'local>,
    purpose_id: jint,
) -> jboolean {
    let result = (|| -> Result<bool, String> {
        // Parse proof
        let proof_vec = env.convert_byte_array(&proof)
            .map_err(|e| e.to_string())?;
        let membership_proof = MembershipProof::from_bytes(proof_vec);
        
        // Parse root
        let root_vec = env.convert_byte_array(&root)
            .map_err(|e| e.to_string())?;
        if root_vec.len() != 32 {
            return Err("root must be 32 bytes".into());
        }
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&root_vec);
        
        // Parse binding_hash
        let binding_hash_vec = env.convert_byte_array(&binding_hash)
            .map_err(|e| e.to_string())?;
        if binding_hash_vec.len() != 32 {
            return Err("binding_hash must be 32 bytes".into());
        }
        let mut binding_hash_arr = [0u8; 32];
        binding_hash_arr.copy_from_slice(&binding_hash_vec);
        
        // Parse session_id
        let session_id_vec = env.convert_byte_array(&session_id)
            .map_err(|e| e.to_string())?;
        if session_id_vec.len() != 32 {
            return Err("session_id must be 32 bytes".into());
        }
        let mut session_id_arr = [0u8; 32];
        session_id_arr.copy_from_slice(&session_id_vec);
        
        // Verify (v2 - with session_id, no nullifier tracking here - API handles that)
        verify_membership(
            &membership_proof,
            &root_arr,
            &binding_hash_arr,
            &session_id_arr,
            purpose_id as u8,
            None, // Nullifier tracking happens at API layer
        )
    })();
    
    match result {
        Ok(true) => JNI_TRUE,
        Ok(false) => JNI_FALSE,
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            JNI_FALSE
        }
    }
}

/// Compute V4 binding hash (called from Kotlin)
///
/// This allows the app to compute the binding hash client-side
/// to include in proof generation.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_computeBindingHashV4<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    did_pubkey: JByteArray<'local>,
    wallet_address: jni::objects::JString<'local>,
    client_id: jni::objects::JString<'local>,
    session_id: jni::objects::JString<'local>,
    payment_hash: JByteArray<'local>,
    amount_sats: jni::sys::jlong,
    expires_at: jni::sys::jlong,
    nonce: JByteArray<'local>,
    ea_domain: jni::objects::JString<'local>,
    purpose_id: jint,
    root_id: jni::objects::JString<'local>,
) -> jbyteArray {
    use super::binding::compute_binding_hash_v4;
    
    let result = (|| -> Result<[u8; 32], String> {
        // Parse all inputs
        let did_pubkey_vec = env.convert_byte_array(&did_pubkey)
            .map_err(|e| e.to_string())?;
        
        let wallet_str: String = env.get_string(&wallet_address)
            .map_err(|e| e.to_string())?
            .into();
        
        let client_str: String = env.get_string(&client_id)
            .map_err(|e| e.to_string())?
            .into();
        
        let session_str: String = env.get_string(&session_id)
            .map_err(|e| e.to_string())?
            .into();
        
        let payment_hash_vec = env.convert_byte_array(&payment_hash)
            .map_err(|e| e.to_string())?;
        
        let nonce_vec = env.convert_byte_array(&nonce)
            .map_err(|e| e.to_string())?;
        
        let ea_domain_str: String = env.get_string(&ea_domain)
            .map_err(|e| e.to_string())?
            .into();
        
        let root_id_str: String = env.get_string(&root_id)
            .map_err(|e| e.to_string())?
            .into();
        
        Ok(compute_binding_hash_v4(
            &did_pubkey_vec,
            &wallet_str,
            &client_str,
            &session_str,
            &payment_hash_vec,
            amount_sats as u64,
            expires_at as u64,
            &nonce_vec,
            &ea_domain_str,
            purpose_id as u8,
            &root_id_str,
        ))
    })();
    
    match result {
        Ok(hash) => {
            match env.byte_array_from_slice(&hash) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

/// Compute leaf commitment from leaf secret (called from Kotlin)
///
/// Uses SHA-256 with domain separator (matches proof.rs and membership.py):
/// leaf_commitment = SHA256("leaf_commit:" || leaf_secret)
///
/// Signature: (leafSecret: ByteArray) -> ByteArray (32 bytes)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_computeLeafCommitment<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    leaf_secret: JByteArray<'local>,
) -> jbyteArray {
    let result = (|| -> Result<[u8; 32], String> {
        // Parse leaf_secret
        let leaf_secret_vec = env.convert_byte_array(&leaf_secret)
            .map_err(|e| e.to_string())?;
        if leaf_secret_vec.len() != 32 {
            return Err("leaf_secret must be 32 bytes".into());
        }
        
        // Compute: SHA256("leaf_commit:" || leaf_secret)
        let mut hasher = Sha256::new();
        hasher.update(LEAF_COMMITMENT_DOMAIN);
        hasher.update(&leaf_secret_vec);
        let commitment: [u8; 32] = hasher.finalize().into();
        
        Ok(commitment)
    })();
    
    match result {
        Ok(hash) => {
            match env.byte_array_from_slice(&hash) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}

/// Compute nullifier from leaf secret and session ID (called from Kotlin)
///
/// nullifier = SHA256("nullifier:" || leaf_secret || session_id)
///
/// This is useful for the app to pre-compute the nullifier that will
/// appear in the proof, for tracking/debugging purposes.
///
/// Signature: (leafSecret: ByteArray, sessionId: ByteArray) -> ByteArray (32 bytes)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_computeNullifier<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    leaf_secret: JByteArray<'local>,
    session_id: JByteArray<'local>,
) -> jbyteArray {
    const NULLIFIER_DOMAIN: &[u8] = b"nullifier:";
    
    let result = (|| -> Result<[u8; 32], String> {
        // Parse leaf_secret
        let leaf_secret_vec = env.convert_byte_array(&leaf_secret)
            .map_err(|e| e.to_string())?;
        if leaf_secret_vec.len() != 32 {
            return Err("leaf_secret must be 32 bytes".into());
        }
        
        // Parse session_id
        let session_id_vec = env.convert_byte_array(&session_id)
            .map_err(|e| e.to_string())?;
        if session_id_vec.len() != 32 {
            return Err("session_id must be 32 bytes".into());
        }
        
        // Compute: SHA256("nullifier:" || leaf_secret || session_id)
        let mut hasher = Sha256::new();
        hasher.update(NULLIFIER_DOMAIN);
        hasher.update(&leaf_secret_vec);
        hasher.update(&session_id_vec);
        let nullifier: [u8; 32] = hasher.finalize().into();
        
        Ok(nullifier)
    })();
    
    match result {
        Ok(hash) => {
            match env.byte_array_from_slice(&hash) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e);
            std::ptr::null_mut()
        }
    }
}
