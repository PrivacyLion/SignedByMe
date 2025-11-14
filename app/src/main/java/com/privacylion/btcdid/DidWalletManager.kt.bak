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

    private fun hexToBytes(hex: String): ByteArray =
        hex.trim().chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun bytesToHex(b: ByteArray): String =
        b.joinToString("") { "%02x".format(it) }

    fun buildOwnershipClaimJson(
        did: String,
        nonce: String,
        walletType: String,
        withdrawTo: String,
        preimage: String? // pass lastPreimage from the UI; null/blank means unpaid
    ): String {
        val paid = !preimage.isNullOrBlank()

        val preimageTrim = preimage?.trim()
        if (paid) {
            require(preimageTrim!!.length % 2 == 0) { "preimage hex must have even length" }
            require(preimageTrim.length >= 64) { "preimage must be ≥32 bytes (≥64 hex chars)" }
            require(preimageTrim.all { it in "0123456789abcdefABCDEF" }) { "preimage must be hex" }
        }

        val preimageSha256Hex: String? = if (paid) {
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val hash = md.digest(hexToBytes(preimage!!.trim()))
            bytesToHex(hash)
        } else null

        val obj = org.json.JSONObject().apply {
            put("schema", "pl/ownership-claim/1")
            put("type", "ownership_claim")
            put("did", did)
            put("nonce", nonce)
            put("wallet_type", walletType)
            put("withdraw_to", withdrawTo)
            put("paid", paid)
            if (paid) {
                put("preimage", preimage!!.trim())
                put("preimage_sha256", preimageSha256Hex)
                // Authentication methods reference; UI/API may read this
                put("amr", org.json.JSONArray(listOf("did_sig", "ln_preimage")))
            }
            put("timestamp_ms", System.currentTimeMillis())
            // optional hint to distinguish platforms in logs
            put("wallet_hint", "android")
            put("aud", "beta.privacy-lion.com")
        }

        return obj.toString()
    }

    // Fetch a real nonce from your API (no new deps; blocking call).
// Call this from a background thread / coroutine (not the main thread).
    fun fetchNonce(
        apiBase: String = "https://api.beta.privacy-lion.com",
        domain: String = "beta.privacy-lion.com",
        timeoutMs: Int = 8000
    ): String {
        val url = java.net.URL("$apiBase/v1/login/start")
        val payload = org.json.JSONObject()
            .put("domain", domain)
            .toString()

        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }

        conn.outputStream.use { os ->
            val bytes = payload.toByteArray(Charsets.UTF_8)
            os.write(bytes)
            os.flush()
        }

        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
            .bufferedReader(Charsets.UTF_8)
            .use { it.readText() }

        if (code !in 200..299) {
            throw java.io.IOException("HTTP $code: $body")
        }

        val json = org.json.JSONObject(body)

        // Accept either top-level "nonce" or nested "data.nonce"
        return when {
            json.has("nonce") -> json.getString("nonce")
            json.has("data") && json.getJSONObject("data").has("nonce") ->
                json.getJSONObject("data").getString("nonce")
            else -> throw java.io.IOException("nonce missing in response: $body")
        }
    }

    data class LoginStart(val loginId: String, val nonce: String)

    fun startLogin(
        apiBase: String = "https://api.beta.privacy-lion.com",
        domain: String = "beta.privacy-lion.com",
        timeoutMs: Int = 8000
    ): LoginStart {
        val url = java.net.URL("$apiBase/v1/login/start")
        val payload = org.json.JSONObject().put("domain", domain).toString()

        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }
        conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }

        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
            .bufferedReader(Charsets.UTF_8).use { it.readText() }
        if (code !in 200..299) throw java.io.IOException("HTTP $code: $body")

        val json = org.json.JSONObject(body)
        val loginId = when {
            json.has("login_id") -> json.getString("login_id")
            json.optJSONObject("data")?.has("login_id") == true -> json.getJSONObject("data").getString("login_id")
            else -> throw java.io.IOException("login_id missing in response: $body")
        }
        val nonce = when {
            json.has("nonce") -> json.getString("nonce")
            json.optJSONObject("data")?.has("nonce") == true -> json.getJSONObject("data").getString("nonce")
            else -> throw java.io.IOException("nonce missing in response: $body")
        }
        return LoginStart(loginId = loginId, nonce = nonce)
    }

    fun fetchLoginStatus(
        loginId: String,
        apiBase: String = "https://api.beta.privacy-lion.com",
        timeoutMs: Int = 8000
    ): String {
        require(loginId.isNotBlank()) { "loginId is empty" }
        val url = java.net.URL("$apiBase/v1/login/status/$loginId")
        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            setRequestProperty("Accept", "application/json")
        }
        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
            .bufferedReader(Charsets.UTF_8).use { it.readText() }
        if (code !in 200..299) throw java.io.IOException("HTTP $code: $body")
        return body // caller can parse or display
    }

    // Demo-only helper to mark a login as settled on the server
    fun settleLoginDemo(
        loginId: String,
        preimageHex: String,
        apiBase: String = "https://api.beta.privacy-lion.com",
        timeoutMs: Int = 8000
    ): String {
        require(loginId.isNotBlank()) { "loginId is empty" }
        require(preimageHex.isNotBlank()) { "preimage is empty" }

        val url = java.net.URL(
            "$apiBase/v1/login/settle?login_id=$loginId&preimage=$preimageHex&txid="
        )
        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST" // server accepts POST for settle
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            setRequestProperty("Accept", "application/json")
        }

        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
            .bufferedReader(Charsets.UTF_8).use { it.readText() }
        if (code !in 200..299) throw java.io.IOException("HTTP $code: $body")
        return body  // typically {"status":"ok"} or similar
    }

    /**
     * Build a DLC-tagged Payment Request Package (PRP) for Enterprise login.
     * This is a simple JSON builder we’ll evolve; it references the preimage SHA-256.
     *
     * userShare/operatorShare are percentages that must sum to 100.
     */
    fun buildPrpJson(
        loginId: String,
        did: String,
        preimageSha256Hex: String,
        amountSats: Long = 0L,
        userShare: Int = 90,
        operatorShare: Int = 10,
        oracleName: String = "local_oracle",
        oraclePubkeyHex: String = "deadbeef" // TODO: replace with real oracle pubkey
    ): String {
        require(loginId.isNotBlank()) { "loginId required" }
        require(did.startsWith("did:")) { "did must start with did:" }
        require(preimageSha256Hex.length == 64) { "preimage_sha256 must be 32 bytes hex" }
        require(userShare + operatorShare == 100) { "split must sum to 100" }

        val prp = org.json.JSONObject().apply {
            put("schema", "pl/prp/1")
            put("type", "payment_request_package")
            put("login_id", loginId)
            put("did", did)
            put("amount_sats", amountSats) // 0 until we wire real amounts
            put("preimage_sha256", preimageSha256Hex)
            put("split", org.json.JSONObject().apply {
                put("user_pct", userShare)
                put("operator_pct", operatorShare)
            })
            put("dlc", org.json.JSONObject().apply {
                put("oracle", org.json.JSONObject().apply {
                    put("name", oracleName)
                    put("pubkey_hex", oraclePubkeyHex)
                })
                // outcome string is canonicalized; we’ll use this when we sign the outcome later
                put("outcome", "paid=true")
            })
        }
        return prp.toString()
    }
}


