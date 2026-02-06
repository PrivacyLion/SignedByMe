package com.privacylion.btcdid

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import breez_sdk.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Breez SDK Wallet Manager for SignedByMe
 * 
 * Handles Lightning wallet operations:
 * - Wallet initialization and seed management
 * - Invoice generation for receiving payments
 * - Payment status monitoring
 * - Balance tracking
 */
class BreezWalletManager(private val context: Context) {

    companion object {
        private const val TAG = "BreezWalletManager"
        private const val KEYSTORE_ALIAS = "breez_seed_wrap_v1"
        private const val SEED_FILE = "breez_seed_wrapped.bin"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        
        // Breez API key - in production, this should be in BuildConfig or secure storage
        // Get your API key from https://breez.technology
        private const val BREEZ_API_KEY = "" // TODO: Add your Breez API key
    }

    private val rng = SecureRandom()
    private var sdk: BlockingBreezServices? = null
    private var nodeInfo: NodeState? = null
    
    // State flows for UI observation
    private val _walletState = MutableStateFlow<WalletState>(WalletState.Uninitialized)
    val walletState: StateFlow<WalletState> = _walletState
    
    private val _balanceSats = MutableStateFlow(0L)
    val balanceSats: StateFlow<Long> = _balanceSats

    sealed class WalletState {
        object Uninitialized : WalletState()
        object Initializing : WalletState()
        data class Ready(val nodeId: String) : WalletState()
        data class Error(val message: String) : WalletState()
    }

    /**
     * Data class for invoice creation result
     */
    data class InvoiceResult(
        val bolt11: String,
        val paymentHash: String,
        val amountSats: Long,
        val description: String
    )

    /**
     * Initialize or restore the wallet
     * If no seed exists, creates a new one
     */
    suspend fun initializeWallet(): Result<String> = withContext(Dispatchers.IO) {
        try {
            _walletState.value = WalletState.Initializing
            
            // Ensure keystore key exists
            ensureKeystoreKey()
            
            // Get or create seed
            val seed = getOrCreateSeed()
            
            // Set up Breez working directory
            val workDir = File(context.filesDir, "breez").apply { mkdirs() }
            
            // Create Breez config
            val config = defaultConfig(
                envType = EnvironmentType.PRODUCTION,
                apiKey = BREEZ_API_KEY,
                nodeConfig = NodeConfig.Greenlight(
                    config = GreenlightNodeConfig(
                        partnerCredentials = null,
                        inviteCode = null
                    )
                )
            ).also {
                it.workingDir = workDir.absolutePath
            }
            
            // Connect to Breez SDK
            sdk = connect(config, seed, BreezEventListener())
            
            // Get node info
            val info = sdk?.nodeInfo()
            nodeInfo = info
            
            val nodeId = info?.id ?: "unknown"
            _balanceSats.value = info?.channelsBalanceMsat?.div(1000) ?: 0L
            _walletState.value = WalletState.Ready(nodeId)
            
            Result.success(nodeId)
        } catch (e: Exception) {
            val errorMsg = e.message ?: "Unknown error initializing wallet"
            _walletState.value = WalletState.Error(errorMsg)
            Result.failure(e)
        }
    }

    /**
     * Check if wallet is already set up (seed exists)
     */
    fun isWalletSetUp(): Boolean {
        return context.getFileStreamPath(SEED_FILE)?.exists() == true
    }

    /**
     * Get wallet balance in sats
     */
    suspend fun getBalance(): Long = withContext(Dispatchers.IO) {
        try {
            val info = sdk?.nodeInfo()
            val balance = info?.channelsBalanceMsat?.div(1000) ?: 0L
            _balanceSats.value = balance
            balance
        } catch (e: Exception) {
            0L
        }
    }

    /**
     * Generate a Lightning invoice for receiving payment
     */
    suspend fun createInvoice(
        amountSats: Long,
        description: String
    ): Result<InvoiceResult> = withContext(Dispatchers.IO) {
        try {
            val sdkInstance = sdk ?: return@withContext Result.failure(
                IllegalStateException("Wallet not initialized")
            )
            
            val request = ReceivePaymentRequest(
                amountMsat = amountSats * 1000,
                description = description,
                preimage = null,
                openingFeeParams = null,
                useDescriptionHash = false,
                expiry = 3600u, // 1 hour expiry
                cltv = null
            )
            
            val response = sdkInstance.receivePayment(request)
            
            Result.success(
                InvoiceResult(
                    bolt11 = response.lnInvoice.bolt11,
                    paymentHash = response.lnInvoice.paymentHash,
                    amountSats = amountSats,
                    description = description
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Check if a specific payment has been received
     */
    suspend fun isPaymentReceived(paymentHash: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val sdkInstance = sdk ?: return@withContext false
            val payment = sdkInstance.paymentByHash(paymentHash)
            payment?.status == PaymentStatus.COMPLETE
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get payment details including preimage if paid
     */
    suspend fun getPaymentDetails(paymentHash: String): Payment? = withContext(Dispatchers.IO) {
        try {
            sdk?.paymentByHash(paymentHash)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Get the mnemonic seed phrase for backup
     * Returns null if no seed exists
     */
    fun getMnemonicForBackup(): List<String>? {
        return try {
            val wrapped = context.openFileInput(SEED_FILE).use { it.readBytes() }
            val seedBytes = unwrapData(wrapped)
            mnemonicToSeed(seedBytes.toList().map { it.toUByte() })
            // Note: Breez SDK uses raw seed bytes, not mnemonic directly
            // For backup, we'd need to convert or store the mnemonic separately
            null // Placeholder - implement mnemonic storage if needed
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Disconnect and cleanup
     */
    fun disconnect() {
        try {
            sdk?.disconnect()
            sdk = null
            _walletState.value = WalletState.Uninitialized
        } catch (e: Exception) {
            // Ignore disconnect errors
        }
    }

    // ==================== Private Methods ====================

    private fun getOrCreateSeed(): List<UByte> {
        val seedFile = context.getFileStreamPath(SEED_FILE)
        
        return if (seedFile?.exists() == true) {
            // Load existing seed
            val wrapped = context.openFileInput(SEED_FILE).use { it.readBytes() }
            val seedBytes = unwrapData(wrapped)
            seedBytes.toList().map { it.toUByte() }
        } else {
            // Generate new seed
            val mnemonic = generateMnemonic(MnemonicWordCount.TWELVE)
            val seed = mnemonicToSeed(mnemonic)
            
            // Wrap and save
            val seedBytes = seed.map { it.toByte() }.toByteArray()
            val wrapped = wrapData(seedBytes)
            context.openFileOutput(SEED_FILE, Context.MODE_PRIVATE).use { 
                it.write(wrapped) 
            }
            
            // Zeroize local copy
            java.util.Arrays.fill(seedBytes, 0)
            
            seed
        }
    }

    private fun ensureKeystoreKey() {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(KEYSTORE_ALIAS)) return

            val specBuilder = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false) // TODO: Enable with BiometricPrompt
                .setRandomizedEncryptionRequired(true)

            if (Build.VERSION.SDK_INT >= 28) {
                try { specBuilder.setUnlockedDeviceRequired(true) } catch (_: Throwable) {}
                try { specBuilder.setIsStrongBoxBacked(true) } catch (_: Throwable) {}
            }

            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            kg.init(specBuilder.build())
            kg.generateKey()
        } catch (_: Throwable) {
            // Fallback handled in getAesKey()
        }
    }

    private fun getAesKey(): SecretKey {
        return try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            (ks.getKey(KEYSTORE_ALIAS, null) as SecretKey?) ?: createFallbackKey()
        } catch (_: Throwable) {
            createFallbackKey()
        }
    }

    private fun createFallbackKey(): SecretKey {
        val fallbackFile = "breez_aes_fallback.bin"
        val file = context.getFileStreamPath(fallbackFile)
        
        return if (file?.exists() == true) {
            val b = context.openFileInput(fallbackFile).use { it.readBytes() }
            SecretKeySpec(b, "AES")
        } else {
            val b = ByteArray(32).also { rng.nextBytes(it) }
            context.openFileOutput(fallbackFile, Context.MODE_PRIVATE).use { it.write(b) }
            SecretKeySpec(b, "AES")
        }
    }

    private fun wrapData(plain: ByteArray): ByteArray {
        val secret = getAesKey()
        val iv = ByteArray(12).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secret, GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(plain)
        return iv + ct
    }

    private fun unwrapData(wrapped: ByteArray): ByteArray {
        require(wrapped.size > 12) { "wrapped data too short" }
        val secret = getAesKey()
        val iv = wrapped.copyOfRange(0, 12)
        val ct = wrapped.copyOfRange(12, wrapped.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, iv))
        return cipher.doFinal(ct)
    }

    /**
     * Event listener for Breez SDK events
     */
    private inner class BreezEventListener : EventListener {
        override fun onEvent(e: BreezEvent) {
            when (e) {
                is BreezEvent.InvoicePaid -> {
                    // Update balance when invoice is paid
                    CoroutineScope(Dispatchers.IO).launch {
                        getBalance()
                    }
                }
                is BreezEvent.Synced -> {
                    // Update balance after sync
                    CoroutineScope(Dispatchers.IO).launch {
                        getBalance()
                    }
                }
                else -> { /* Handle other events as needed */ }
            }
        }
    }
}
