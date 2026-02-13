//! JNI Bindings for Membership Proofs
//!
//! Provides Android native methods for:
//! - proveMembership: Generate a membership proof
//! - verifyMembership: Verify a membership proof

use jni::objects::{JByteArray, JClass, JObject, JObjectArray};
use jni::sys::{jboolean, jbyteArray, jint, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use super::merkle::{MerklePath, PathSibling};
use super::poseidon::FieldElement;
use super::proof::{prove_membership, verify_membership, MembershipProof};

/// Prove membership (called from Kotlin)
///
/// Signature: (
///     leafSecret: ByteArray,      // 32 bytes
///     merklePath: Array<ByteArray>, // Array of 32-byte siblings
///     pathIndices: ByteArray,     // 0 or 1 for each level
///     root: ByteArray,            // 32 bytes
///     bindingHash: ByteArray,     // 32 bytes
///     purposeId: Int
/// ) -> ByteArray (proof)
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_proveMembership<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    leaf_secret: JByteArray<'local>,
    merkle_path: JObjectArray<'local>,
    path_indices: JByteArray<'local>,
    root: JByteArray<'local>,
    binding_hash: JByteArray<'local>,
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
        
        // Parse merkle path
        let path_len = env.get_array_length(&merkle_path)
            .map_err(|e| e.to_string())? as usize;
        let indices_vec = env.convert_byte_array(&path_indices)
            .map_err(|e| e.to_string())?;
        
        if indices_vec.len() != path_len {
            return Err("path_indices length must match merkle_path length".into());
        }
        
        let mut siblings = Vec::with_capacity(path_len);
        for i in 0..path_len {
            let sibling_obj = env.get_object_array_element(&merkle_path, i as i32)
                .map_err(|e| e.to_string())?;
            let sibling_arr: JByteArray = sibling_obj.into();
            let sibling_vec = env.convert_byte_array(&sibling_arr)
                .map_err(|e| e.to_string())?;
            
            if sibling_vec.len() != 32 {
                return Err(format!("sibling {} must be 32 bytes", i));
            }
            
            siblings.push(PathSibling {
                hash: FieldElement::from_bytes_be(&sibling_vec),
                is_right: indices_vec[i] != 0,
            });
        }
        
        let merkle_path = MerklePath { siblings };
        
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
        
        // Generate proof
        let proof = prove_membership(
            &leaf_secret_arr,
            &merkle_path,
            &root_arr,
            &binding_hash_arr,
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

/// Verify membership (called from Kotlin)
///
/// Signature: (
///     proof: ByteArray,
///     root: ByteArray,            // 32 bytes
///     bindingHash: ByteArray,     // 32 bytes
///     purposeId: Int
/// ) -> Boolean
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_privacylion_btcdid_NativeBridge_verifyMembership<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    proof: JByteArray<'local>,
    root: JByteArray<'local>,
    binding_hash: JByteArray<'local>,
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
        
        // Verify
        verify_membership(
            &membership_proof,
            &root_arr,
            &binding_hash_arr,
            purpose_id as u8,
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
