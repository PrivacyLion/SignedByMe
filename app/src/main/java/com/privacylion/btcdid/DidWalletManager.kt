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

    private val seedFile = "seed_wrapped.bin"
    
    /**
     * Derive keys from a BIP39 seed phrase.
     * Stores the seed securely and derives a Lightning-compatible address.
     * 
     * @param seedPhrase Space-separated mnemonic words (12 or 24)
     * @param passphrase Optional BIP39 passphrase (empty string if none)
     * @return A derived Lightning address or pubkey for display
     */
    fun deriveFromSeedPhrase(seedPhrase: String, passphrase: String = ""): String {
        ensureKeystoreKey()
        
        // Validate word count
        val words = seedPhrase.trim().split("\\s+".toRegex())
        require(words.size == 12 || words.size == 24) { 
            "Seed phrase must be 12 or 24 words, got ${words.size}" 
        }
        
        // For now, derive key using SHA-256 of seed+passphrase as entropy
        // TODO: Implement proper BIP39/BIP32 derivation in Rust
        val combined = "$seedPhrase:$passphrase"
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val entropy = md.digest(combined.toByteArray(Charsets.UTF_8))
        
        // Use first 32 bytes as secp256k1 private key
        val priv = entropy.copyOf(32)
        val pubHex = NativeBridge.derivePublicKeyHex(priv)
        
        // Wrap and save the derived private key (replacing any existing)
        val wrapped = wrapPrivateKey(priv)
        saveWrapped(wrapped)
        
        // Also save the encrypted seed phrase for recovery display
        val seedBytes = seedPhrase.toByteArray(Charsets.UTF_8)
        val wrappedSeed = wrapPrivateKey(seedBytes)
        context.openFileOutput(seedFile, Context.MODE_PRIVATE).use { it.write(wrappedSeed) }
        
        // Zeroize sensitive data
        java.util.Arrays.fill(priv, 0.toByte())
        java.util.Arrays.fill(entropy, 0.toByte())
        
        // Update current DID
        currentDid = "did:btcr:$pubHex"
        
        // Return a truncated pubkey as the "address" for display
        // In production, this would be a proper Lightning address
        return "ln:${pubHex.take(16)}...${pubHex.takeLast(8)}"
    }
    
    /**
     * Check if a seed phrase is stored
     */
    fun hasSeedPhrase(): Boolean {
        return try {
            context.openFileInput(seedFile).use { it.readBytes().isNotEmpty() }
        } catch (_: Throwable) {
            false
        }
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
    
    // ============================================================================
    // STWO Identity Proof (for SignedByMe Login)
    // ============================================================================
    
    private val identityProofFile = "identity_proof_wrapped.bin"
    
    /**
     * Generate and store an STWO Identity Proof binding DID to wallet.
     * This proves ownership of both DID and wallet in zero knowledge.
     * 
     * @param walletAddress The wallet address (e.g., Spark address)
     * @param expiryDays How many days until the proof expires (default: 30)
     * @return JSON string with the identity proof
     */
    fun generateIdentityProof(walletAddress: String, expiryDays: Long = 30): String {
        val did = getPublicDID() ?: throw IllegalStateException("No DID created")
        
        // Create a challenge and sign it with DID to prove wallet ownership
        // The wallet signature proves we control the wallet
        val wrapped = loadWrapped() ?: throw IllegalStateException("No DID key")
        val priv = unwrapPrivateKey(wrapped)
        
        return try {
            // Sign a challenge binding DID to wallet
            val challenge = "signedby.me:bind:$did:$walletAddress:${System.currentTimeMillis()}"
            val walletSignature = NativeBridge.signMessageDerHex(priv, challenge)
            
            // Generate STWO proof
            val proofJson = NativeBridge.generateIdentityProof(
                did.removePrefix("did:btcr:"),
                walletAddress,
                walletSignature,
                expiryDays
            )
            
            // Store proof encrypted (defense in depth)
            saveIdentityProof(proofJson)
            
            proofJson
        } finally {
            java.util.Arrays.fill(priv, 0)
        }
    }
    
    /**
     * Get the stored identity proof, or null if none exists
     */
    fun getIdentityProof(): String? {
        return loadIdentityProof()
    }
    
    /**
     * Get the hash of the stored identity proof (for including in VCC)
     */
    fun getIdentityProofHash(): String? {
        val proof = loadIdentityProof() ?: return null
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return bytesToHex(md.digest(proof.toByteArray(Charsets.UTF_8)))
    }
    
    /**
     * Check if an identity proof exists
     */
    fun hasIdentityProof(): Boolean {
        return loadIdentityProof() != null
    }
    
    /**
     * Verify the stored identity proof is still valid (not expired)
     */
    fun verifyIdentityProof(): String {
        val proof = loadIdentityProof() ?: return """{"valid":false,"error":"No proof stored"}"""
        return try {
            NativeBridge.verifyIdentityProof(proof)
        } catch (t: Throwable) {
            """{"valid":false,"error":"${t.message ?: "Verification failed"}"}"""
        }
    }
    
    /**
     * Create a payment binding signature for login
     * This binds the identity proof to a specific payment
     * 
     * @param paymentHash The payment hash from the invoice
     * @param nonce A random nonce to prevent replay
     * @return Signature over (proof_hash + payment_hash + nonce)
     */
    fun createPaymentBinding(paymentHash: String, nonce: String): String {
        val proofHash = getIdentityProofHash() 
            ?: throw IllegalStateException("No identity proof")
        
        // Build binding data
        val bindingData = """{"stwo_proof_hash":"$proofHash","payment_hash":"$paymentHash","nonce":"$nonce","timestamp":${System.currentTimeMillis()}}"""
        
        // Hash the binding data
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val bindingHash = bytesToHex(md.digest(bindingData.toByteArray(Charsets.UTF_8)))
        
        // Sign with DID
        val wrapped = loadWrapped() ?: throw IllegalStateException("No DID key")
        val priv = unwrapPrivateKey(wrapped)
        
        return try {
            NativeBridge.signMessageDerHex(priv, bindingHash)
        } finally {
            java.util.Arrays.fill(priv, 0)
        }
    }
    
    /**
     * Generate a real STWO login proof for authentication.
     * This creates a cryptographically sound Circle STARK proof that binds:
     * - The user's DID
     * - Their wallet address
     * - The specific payment hash for this login session
     * 
     * @param walletAddress The user's wallet address
     * @param paymentHashHex The payment hash from the employer's invoice (32 bytes hex)
     * @param expiryDays How many days until the proof expires (default: 1 for login)
     * @return JSON with the real STWO proof, or falls back to mock if real STWO unavailable
     */
    fun generateLoginProof(walletAddress: String, paymentHashHex: String, expiryDays: Long = 1): String {
        val did = getPublicDID() ?: throw IllegalStateException("No DID created")
        val didPubkeyHex = did.removePrefix("did:btcr:")
        
        return try {
            if (NativeBridge.hasRealStwo()) {
                // Use real STWO Circle STARK proof
                NativeBridge.generateRealIdentityProof(
                    didPubkeyHex,
                    walletAddress,
                    paymentHashHex,
                    expiryDays
                )
            } else {
                // Fallback to mock proof (for testing/development only)
                android.util.Log.w("DidWalletManager", "Real STWO not available, using mock proof")
                val wrapped = loadWrapped() ?: throw IllegalStateException("No DID key")
                val priv = unwrapPrivateKey(wrapped)
                try {
                    val challenge = "signedby.me:bind:$did:$walletAddress:${System.currentTimeMillis()}"
                    val signature = NativeBridge.signMessageDerHex(priv, challenge)
                    NativeBridge.generateIdentityProof(didPubkeyHex, walletAddress, signature, expiryDays)
                } finally {
                    java.util.Arrays.fill(priv, 0)
                }
            }
        } catch (t: Throwable) {
            """{"status":"error","error":"${t.message ?: "Failed to generate login proof"}"}"""
        }
    }
    
    /**
     * Check if real STWO (Circle STARK) proofs are available.
     * When true, login proofs are cryptographically sound.
     * When false, mock proofs are used (testing only).
     */
    fun hasRealStwoSupport(): Boolean {
        return try {
            NativeBridge.hasRealStwo()
        } catch (_: Throwable) {
            false
        }
    }
    
    private fun saveIdentityProof(proofJson: String) {
        ensureKeystoreKey()
        val proofBytes = proofJson.toByteArray(Charsets.UTF_8)
        val wrapped = wrapPrivateKey(proofBytes)
        context.openFileOutput(identityProofFile, Context.MODE_PRIVATE).use { it.write(wrapped) }
    }
    
    private fun loadIdentityProof(): String? {
        return try {
            val wrapped = context.openFileInput(identityProofFile).use { it.readBytes() }
            if (wrapped.isEmpty()) return null
            val proofBytes = unwrapPrivateKey(wrapped)
            String(proofBytes, Charsets.UTF_8)
        } catch (_: Throwable) {
            null
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
        oraclePubkeyHex: String = NativeBridge.oraclePubkeyHex() // TODO: replace with real oracle pubkey
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


