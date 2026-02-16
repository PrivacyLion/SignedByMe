package com.privacylion.btcdid

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * ViewModel for login flow operations.
 * Holds coroutines in viewModelScope to survive configuration changes
 * and prevent "coroutine scope left the composition" errors.
 */
class LoginViewModel(application: Application) : AndroidViewModel(application) {
    
    // UI State
    sealed class LoginState {
        object Idle : LoginState()
        object CreatingSession : LoginState()
        object GeneratingInvoice : LoginState()
        object GeneratingProof : LoginState()
        object SendingToApi : LoginState()
        data class Success(val response: ApiResponse) : LoginState()
        data class Error(val message: String) : LoginState()
    }
    
    data class ApiResponse(
        val ok: Boolean,
        val sessionId: String,
        val stwoVerified: Boolean,
        val bindingVerified: Boolean,
        val dlcVerified: Boolean,
        val membershipVerified: Boolean,
        val message: String
    )
    
    private val _loginState = MutableStateFlow<LoginState>(LoginState.Idle)
    val loginState: StateFlow<LoginState> = _loginState.asStateFlow()
    
    private val _statusMessage = MutableStateFlow("")
    val statusMessage: StateFlow<String> = _statusMessage.asStateFlow()
    
    // Current session info (survives recomposition)
    private var currentLoginSession: LoginSession? = null
    private var lastInvoice: String? = null
    private var lastPaymentHash: String? = null
    private var lastDlcContract: DlcManager.DlcContract? = null
    
    /**
     * Process a scanned QR code or deep link.
     * Called from Compose UI - work happens in viewModelScope.
     */
    fun processLoginUrl(
        url: String,
        didMgr: DidWalletManager,
        breezMgr: BreezWalletManager,
        onSessionCreated: (LoginSession) -> Unit
    ) {
        viewModelScope.launch {
            _loginState.value = LoginState.CreatingSession
            _statusMessage.value = "Processing login request..."
            
            try {
                // Parse URL parameters
                val uri = android.net.Uri.parse(url)
                val sessionId = uri.getQueryParameter("session") ?: throw IllegalArgumentException("Missing session ID")
                val enterprise = uri.getQueryParameter("enterprise") ?: "Unknown"
                val clientId = uri.getQueryParameter("client")
                val requiredRootId = uri.getQueryParameter("root_id")
                val amountStr = uri.getQueryParameter("amount") ?: "100"
                val amount = amountStr.toLongOrNull() ?: 100L
                
                Log.i("LoginViewModel", "Session received: id=$sessionId, client=$clientId, root=$requiredRootId")
                
                val session = LoginSession(
                    sessionId = sessionId,
                    enterpriseName = enterprise,
                    amountSats = amount.toULong(),
                    clientId = clientId,
                    requiredRootId = requiredRootId
                )
                
                currentLoginSession = session
                
                withContext(Dispatchers.Main) {
                    onSessionCreated(session)
                }
                
                _loginState.value = LoginState.Idle
                
            } catch (e: Exception) {
                Log.e("LoginViewModel", "Failed to process login URL: ${e.message}")
                _loginState.value = LoginState.Error("Failed to process: ${e.message}")
                _statusMessage.value = "Error: ${e.message}"
            }
        }
    }
    
    /**
     * Execute the full login flow: invoice -> proof -> API.
     * Called when user confirms login - all work in viewModelScope.
     */
    fun executeLogin(
        loginSession: LoginSession,
        did: String,
        walletAddress: String,
        didMgr: DidWalletManager,
        breezMgr: BreezWalletManager,
        onInvoiceCreated: (String) -> Unit,
        onComplete: (Boolean, String) -> Unit
    ) {
        viewModelScope.launch {
            try {
                val sessionId = loginSession.sessionId
                val enterpriseDomain = loginSession.enterpriseName
                val sessionAmount = loginSession.amountSats?.toLong() ?: 100L
                
                // 1. Generate invoice
                _loginState.value = LoginState.GeneratingInvoice
                _statusMessage.value = "Creating invoice..."
                
                val invoiceResult = breezMgr.createInvoice(
                    amountSats = sessionAmount.toULong(),
                    description = "SignedByMe Log In: $enterpriseDomain - $sessionId"
                )
                
                val invoice = invoiceResult.getOrElse { e ->
                    throw Exception("Failed to create invoice: ${e.message}")
                }
                
                lastInvoice = invoice
                
                withContext(Dispatchers.Main) {
                    onInvoiceCreated(invoice)
                }
                
                // Extract payment hash
                val paymentHashMatch = Regex("lnbc[0-9a-z]+pp5([a-z0-9]{52})").find(invoice.lowercase())
                val paymentHash = paymentHashMatch?.groupValues?.get(1)?.let { bech32Data ->
                    // Convert from bech32 to hex (simplified - payment hash is in the data)
                    invoice.substringAfter("pp5").take(52).let { data ->
                        // For now, use SHA256 of invoice as payment hash identifier
                        java.security.MessageDigest.getInstance("SHA-256")
                            .digest(invoice.toByteArray())
                            .joinToString("") { "%02x".format(it) }
                    }
                } ?: java.security.MessageDigest.getInstance("SHA-256")
                    .digest(invoice.toByteArray())
                    .joinToString("") { "%02x".format(it) }
                
                lastPaymentHash = paymentHash
                
                // 2. Generate STWO proof
                _loginState.value = LoginState.GeneratingProof
                _statusMessage.value = "Generating proof..."
                
                // Get or generate nonce
                val sessionNonce = loginSession.nonce?.takeIf { it.length == 32 }
                    ?: java.security.SecureRandom().let { rng ->
                        ByteArray(16).also { rng.nextBytes(it) }
                            .joinToString("") { "%02x".format(it) }
                    }
                
                val stwoproof = withContext(Dispatchers.IO) {
                    didMgr.generateLoginProofV3(
                        walletAddress = walletAddress,
                        paymentHashHex = paymentHash,
                        amountSats = sessionAmount,
                        eaDomain = enterpriseDomain,
                        nonceHex = sessionNonce
                    )
                }
                
                // 3. Build DLC contract
                val dlcContract = withContext(Dispatchers.IO) {
                    DlcManager.buildLoginDlc(sessionId, did)
                }
                lastDlcContract = dlcContract
                
                // 4. Generate membership proof if required
                var membershipBundle: MembershipBundle? = null
                val requiredRootId = loginSession.requiredRootId
                val clientId = loginSession.clientId
                
                if (requiredRootId != null && clientId != null) {
                    Log.i("LoginViewModel", "Membership required: client=$clientId, root=$requiredRootId")
                    
                    val witness = didMgr.loadWitness(clientId, requiredRootId)
                    if (witness != null) {
                        val didPubkeyHex = did.removePrefix("did:btcr:")
                        val didPubkeyBytes = didPubkeyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                        val paymentHashBytes = paymentHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                        val nonceBytes = sessionNonce.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                        
                        val bindingHash = NativeBridge.computeBindingHashV4(
                            didPubkey = didPubkeyBytes,
                            walletAddress = walletAddress,
                            clientId = clientId,
                            sessionId = sessionId,
                            paymentHash = paymentHashBytes,
                            amountSats = sessionAmount,
                            expiresAt = loginSession.expiresAt ?: (System.currentTimeMillis() / 1000 + 300),
                            nonce = nonceBytes,
                            eaDomain = enterpriseDomain,
                            purposeId = witness.purposeId,
                            rootId = requiredRootId
                        )
                        
                        val proofBase64 = didMgr.generateMembershipProof(witness, bindingHash)
                        if (proofBase64 != null) {
                            membershipBundle = MembershipBundle(
                                rootId = requiredRootId,
                                purpose = didMgr.purposeIdToString(witness.purposeId),
                                proofBase64 = proofBase64
                            )
                            Log.i("LoginViewModel", "Membership proof generated successfully")
                        } else {
                            throw Exception("Could not generate membership proof. Please re-enroll with this employer.")
                        }
                    } else {
                        throw Exception("Not enrolled with this employer. Contact your admin.")
                    }
                }
                
                // 5. Send to API
                _loginState.value = LoginState.SendingToApi
                _statusMessage.value = "Sending to API..."
                
                val apiResult = withContext(Dispatchers.IO) {
                    sendInvoiceToApi(
                        sessionToken = loginSession.sessionToken,
                        sessionId = sessionId,
                        invoice = invoice,
                        did = did,
                        enterpriseName = enterpriseDomain,
                        amountSats = sessionAmount,
                        stwoproof = stwoproof,
                        nonce = sessionNonce,
                        dlcContractJson = dlcContract?.toJson(),
                        membership = membershipBundle,
                        walletAddress = walletAddress
                    )
                }
                
                if (apiResult.success) {
                    _loginState.value = LoginState.Success(
                        ApiResponse(
                            ok = true,
                            sessionId = sessionId,
                            stwoVerified = true,
                            bindingVerified = true,
                            dlcVerified = true,
                            membershipVerified = membershipBundle != null,
                            message = "Identity verified"
                        )
                    )
                    _statusMessage.value = "Login successful!"
                    
                    withContext(Dispatchers.Main) {
                        onComplete(true, "Login successful!")
                    }
                } else {
                    throw Exception(apiResult.errorMessage ?: "API request failed")
                }
                
            } catch (e: Exception) {
                Log.e("LoginViewModel", "Login failed: ${e.message}", e)
                _loginState.value = LoginState.Error(e.message ?: "Unknown error")
                _statusMessage.value = "Error: ${e.message}"
                
                withContext(Dispatchers.Main) {
                    onComplete(false, e.message ?: "Unknown error")
                }
            }
        }
    }
    
    /**
     * Reset state for a new login attempt.
     */
    fun reset() {
        _loginState.value = LoginState.Idle
        _statusMessage.value = ""
        currentLoginSession = null
        lastInvoice = null
        lastPaymentHash = null
        lastDlcContract = null
    }
    
    // API call helper (same as MainActivity but returns ApiResult)
    private data class ApiResult(val success: Boolean, val errorMessage: String? = null, val responseBody: String? = null)
    
    private fun sendInvoiceToApi(
        sessionToken: String?,
        sessionId: String,
        invoice: String,
        did: String,
        enterpriseName: String,
        amountSats: Long,
        stwoproof: String?,
        nonce: String,
        dlcContractJson: String?,
        membership: MembershipBundle? = null,
        walletAddress: String? = null
    ): ApiResult {
        return try {
            val endpoint = if (sessionToken != null) "/v1/login/submit" else "/v1/login/invoice"
            val url = java.net.URL("https://api.beta.privacy-lion.com$endpoint")
            
            val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 10000
                readTimeout = 10000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
            
            val payload = JSONObject().apply {
                if (sessionToken != null) {
                    put("session_token", sessionToken)
                } else {
                    put("session_id", sessionId)
                    put("enterprise", enterpriseName)
                }
                put("invoice", invoice)
                put("did", did)
                put("amount_sats", amountSats)
                put("nonce", nonce)
                
                if (walletAddress != null) {
                    put("wallet_address", walletAddress)
                }
                
                if (stwoproof != null) {
                    put("stwo_proof", stwoproof)
                }
                
                if (dlcContractJson != null) {
                    put("dlc_contract", JSONObject(dlcContractJson))
                }
                
                if (membership != null) {
                    put("membership", JSONObject().apply {
                        put("root_id", membership.rootId)
                        put("purpose", membership.purpose)
                        put("proof", membership.proofBase64)
                    })
                }
            }.toString()
            
            Log.i("LoginViewModel", "Sending to API: ${payload.take(500)}...")
            
            conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
            
            val responseCode = conn.responseCode
            val responseBody = try {
                if (responseCode in 200..299) {
                    conn.inputStream.bufferedReader().readText()
                } else {
                    conn.errorStream?.bufferedReader()?.readText() ?: ""
                }
            } catch (e: Exception) { "" }
            
            conn.disconnect()
            
            Log.i("LoginViewModel", "API response: $responseCode - $responseBody")
            
            if (responseCode in 200..299) {
                ApiResult(success = true, responseBody = responseBody)
            } else {
                val errorDetail = try {
                    JSONObject(responseBody).optString("detail", "Request failed ($responseCode)")
                } catch (e: Exception) {
                    "Request failed ($responseCode)"
                }
                ApiResult(success = false, errorMessage = errorDetail)
            }
        } catch (e: Exception) {
            Log.e("LoginViewModel", "API call failed: ${e.message}")
            ApiResult(success = false, errorMessage = "Network error: ${e.message}")
        }
    }
}

// MembershipBundle is defined in MainActivity.kt
