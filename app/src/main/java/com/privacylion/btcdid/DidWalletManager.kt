package com.privacylion.btcdid

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.KeyStore
import java.security.SecureRandom
import android.security.keystore.KeyInfo
import javax.crypto.SecretKeyFactory

class DidWalletManager(private val context: Context) {

    private val ksAlias = "btcdid_aes_wrap_v1"
    private val wrappedFile = "did_wrapped.bin"
    private val fallbackKeyFile = "aes_fallback.bin"
    private val androidKeyStore = "AndroidKeyStore"
    private val rng = SecureRandom()

    @Volatile var currentDid: String? = null
        private set

    /** Prefer hardware Keystore; fall back to private software key on failure (emulators/old devices). */
    fun ensureKeystoreKey() {
        try {
            val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
            if (ks.containsAlias(ksAlias)) return

            val specBuilder = KeyGenParameterSpec.Builder(
                ksAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                // TEMP: no auth prompt until BiometricPrompt is wired
                .setUserAuthenticationRequired(false)
                .setRandomizedEncryptionRequired(true)

            if (Build.VERSION.SDK_INT >= 28) {
                try { specBuilder.setUnlockedDeviceRequired(true) } catch (_: Throwable) {}
                try { specBuilder.setIsStrongBoxBacked(true) } catch (_: Throwable) {}
            }

            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, androidKeyStore)
            kg.init(specBuilder.build())
            kg.generateKey()
        } catch (_: Throwable) {
            // Keystore unavailable → create/persist a software AES-256 key as a fallback
            if (context.getFileStreamPath(fallbackKeyFile)?.exists() != true) {
                val b = ByteArray(32).also { rng.nextBytes(it) }
                context.openFileOutput(fallbackKeyFile, Context.MODE_PRIVATE).use { it.write(b) }
            }
        }
    }

    private fun getAesKey(): SecretKey {
        return try {
            val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
            (ks.getKey(ksAlias, null) as SecretKey?) ?: loadFallbackKey()
        } catch (_: Throwable) {
            loadFallbackKey()
        }
    }

    private fun loadFallbackKey(): SecretKey {
        val b = context.openFileInput(fallbackKeyFile).use { it.readBytes() }
        return SecretKeySpec(b, "AES")
    }

    fun wrapPrivateKey(plain: ByteArray): ByteArray {
        val secret = getAesKey()
        val iv = ByteArray(12).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secret, GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(plain)
        return iv + ct
    }

    fun unwrapPrivateKey(wrapped: ByteArray): ByteArray {
        require(wrapped.size > 12) { "wrapped too short" }
        val secret = getAesKey()
        val iv = wrapped.copyOfRange(0, 12)
        val ct = wrapped.copyOfRange(12, wrapped.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    fun saveWrapped(bytes: ByteArray) {
        context.openFileOutput(wrappedFile, Context.MODE_PRIVATE).use { it.write(bytes) }
    }

    fun signClaimWithDid(privateKeyBytes: ByteArray, claimJson: String): String {
        // delegate to Rust/JNI just like before
        val sigHex = NativeBridge.signMessageDerHex(privateKeyBytes, claimJson)
        // wipe key material
        java.util.Arrays.fill(privateKeyBytes, 0)
        return sigHex
    }

    fun loadWrapped(): ByteArray? {
        return try { context.openFileInput(wrappedFile).use { it.readBytes() } } catch (_: Throwable) { null }
    }

    /** Generate secp256k1 in Rust, wrap & save, compute did:btcr:<pubHex>. */
    fun createDid(): String {
        ensureKeystoreKey()
        val priv = NativeBridge.generateSecp256k1PrivateKey()   // 32 bytes from Rust
        val pubHex = NativeBridge.derivePublicKeyHex(priv)      // compressed SEC1 hex (66 chars)
        val wrapped = wrapPrivateKey(priv)
        saveWrapped(wrapped)
        // Zeroize plaintext copy ASAP
        java.util.Arrays.fill(priv, 0)
        currentDid = "did:btcr:$pubHex"
        return currentDid!!
    }

    /** Return DID (derive if needed). */
    fun getPublicDID(): String? {
        currentDid?.let { return it }
        val wrapped = loadWrapped() ?: return null
        val priv = unwrapPrivateKey(wrapped)
        val pubHex = NativeBridge.derivePublicKeyHex(priv)
        java.util.Arrays.fill(priv, 0)
        currentDid = "did:btcr:$pubHex"
        return currentDid
    }

    fun regenerateKeyPair(): String {
        currentDid = null
        return createDid()
    }

    /** Debug info: is the Keystore key hardware-backed / StrongBox? */
    fun keystoreInfo(): String {
        return try {
            // if we actually have a wrapped DID key saved, say so first
            if (loadWrapped() != null) {
                "Keystore key: OK (wrapped DID present)"
            } else {
                // fall back to reporting on the wrapping key itself
                val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
                val sk = ks.getKey(ksAlias, null) as? SecretKey
                    ?: return "Keystore key: not found"

                val factory = SecretKeyFactory.getInstance(sk.algorithm, androidKeyStore)
                val keyInfo = factory.getKeySpec(sk, KeyInfo::class.java) as KeyInfo

                val hw = if (keyInfo.isInsideSecureHardware) "YES" else "NO"

                val sb = try {
                    if (Build.VERSION.SDK_INT >= 28) {
                        val m = KeyInfo::class.java.getMethod("isStrongBoxBacked")
                        val result = m.invoke(keyInfo) as? Boolean ?: false
                        if (result) "YES" else "NO"
                    } else {
                        "NO"
                    }
                } catch (_: Throwable) {
                    "NO"
                }

                "Keystore key: found (HW=$hw, StrongBox=$sb)"
            }
        } catch (t: Throwable) {
            "Keystore key: error ${t.message}"
        }

    }
    fun generateStwoProof(circuit: String, inputHashHex: String, outputHashHex: String): String {
        return try {
            NativeBridge.generateStwoProof(circuit, inputHashHex, outputHashHex)
        } catch (t: Throwable) {
            """{"status":"stub","fn":"generate_stwo_proof","error":"${t.message ?: "not implemented"}"}"""
        }
    }

    fun createDlcContract(outcome: String, payoutsJson: String, oracleJson: String): String {
        return try {
            NativeBridge.createDlcContract(outcome, payoutsJson, oracleJson)
        } catch (t: Throwable) {
            """{"status":"stub","fn":"create_dlc_contract","error":"${t.message ?: "not implemented"}"}"""
        }
    }

    fun signDlcOutcome(outcome: String): String {
        return try {
            NativeBridge.signDlcOutcome(outcome)
        } catch (t: Throwable) {
            """{"status":"stub","fn":"sign_dlc_outcome","error":"${t.message ?: "not implemented"}"}"""
        }
    }

    fun signOwnershipClaim(claimJson: String): String {
        // Load wrapped DID key from storage
        val wrapped = loadWrapped() ?: throw IllegalStateException("no wrapped key saved")
        // Unwrap to raw key (in RAM briefly)
        val priv = unwrapPrivateKey(wrapped)
        return try {
            // Delegate signing to JNI
            NativeBridge.signMessageDerHex(priv, claimJson)
        } finally {
            // Always wipe the secret from memory
            java.util.Arrays.fill(priv, 0)
        }
    }

    fun buildOwnershipClaimJson(did: String, nonce: String, walletType: String, withdrawTo: String): String {
        val paidStub = true
        val preimageStub = "mock-preimage-32b"
        val json = org.json.JSONObject()
            .put("did", did)
            .put("schema", "pl.claim.v1")
            .put("type", "ownership_claim")
            .put("aud", "beta.privacy-lion.com")
            .put("wallet_type", walletType)
            .put("withdraw_to", withdrawTo)
            .put("wallet_hint", "android-mock")
            .put("paid", paidStub)
            .put("preimage", preimageStub)
            .put("nonce", nonce)
            .put("timestamp_ms", System.currentTimeMillis())
        return json.toString()
    }

}
