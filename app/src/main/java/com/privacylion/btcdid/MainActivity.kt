package com.privacylion.btcdid

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.compose.foundation.*
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.privacylion.btcdid.ui.theme.BTC_DIDTheme
import kotlinx.coroutines.*
import org.json.JSONObject
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.common.BitMatrix

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val didMgr = DidWalletManager(applicationContext)
        val breezMgr = BreezWalletManager(applicationContext)
        
        // Parse deep link from intent
        val initialLoginSession = parseLoginIntent(intent)

        setContent {
            BTC_DIDTheme {
                SignedByMeApp(didMgr, breezMgr, initialLoginSession)
            }
        }
    }
    
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        // Re-parse when app receives new intent while running
        // Note: For full implementation, use a ViewModel or state holder
    }
    
    private fun parseLoginIntent(intent: Intent?): LoginSession? {
        val uri = intent?.data ?: return null
        
        // Handle both signedby.me:// and https://signedby.me/login
        if (uri.scheme == "signedby.me" || 
            (uri.scheme == "https" && uri.host == "signedby.me")) {
            val sessionId = uri.getQueryParameter("session")
            val employer = uri.getQueryParameter("employer")
            val amountStr = uri.getQueryParameter("amount")
            val amount = amountStr?.toULongOrNull() ?: 100UL // Default 100 sats
            
            if (sessionId != null && employer != null) {
                return LoginSession(sessionId, employer, amount)
            }
        }
        return null
    }
}

// Data class for login session from deep link / QR
data class LoginSession(
    val sessionId: String,
    val employerName: String,
    val amountSats: ULong = 100UL // Default 100 sats if not specified
)

// API Configuration
private const val API_BASE_URL = "https://api.signedby.me" // TODO: Update with actual API URL

/**
 * Send the Lightning invoice to the API for the employer to pay.
 * Returns true if successful, false otherwise.
 */
private fun sendInvoiceToApi(
    sessionId: String,
    invoice: String,
    did: String,
    employerName: String
): Boolean {
    return try {
        val url = java.net.URL("$API_BASE_URL/v1/login/invoice")
        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10000
            readTimeout = 10000
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
        }
        
        val payload = JSONObject().apply {
            put("session_id", sessionId)
            put("invoice", invoice)
            put("did", did)
            put("employer", employerName)
        }.toString()
        
        conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
        
        val responseCode = conn.responseCode
        conn.disconnect()
        
        // Success if 2xx response
        responseCode in 200..299
    } catch (e: Exception) {
        android.util.Log.e("SignedByMe", "Failed to send invoice to API: ${e.message}")
        false
    }
}

@Composable
fun SignedByMeApp(
    didMgr: DidWalletManager, 
    breezMgr: BreezWalletManager,
    initialLoginSession: LoginSession? = null
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // ===== State =====
    var did by remember { mutableStateOf(didMgr.getPublicDID() ?: "") }
    var step1Complete by remember { mutableStateOf(did.isNotEmpty()) }
    val walletState by breezMgr.walletState.collectAsState()
    var step2Complete by remember { mutableStateOf(walletState is BreezWalletManager.WalletState.Connected) }
    var step3Complete by remember { mutableStateOf(false) }
    
    // Login session state (from deep link, QR scan, or demo)
    var loginSession by remember { mutableStateOf(initialLoginSession) }

    // Breez wallet state - derive from WalletState
    val balanceSats = when (val state = walletState) {
        is BreezWalletManager.WalletState.Connected -> state.balanceSats.toLong()
        else -> 0L
    }
    var isWalletInitializing by remember { mutableStateOf(false) }
    var walletSparkAddress by remember { mutableStateOf("") }

    // Login/API state
    var lastNonce by remember { mutableStateOf("") }
    var lastLoginId by remember { mutableStateOf("") }
    var lastPreimage by remember { mutableStateOf("") }
    var lastClaimJson by remember { mutableStateOf("") }
    var lastSigHex by remember { mutableStateOf("") }
    var lastPrpJson by remember { mutableStateOf("") }
    var lastInvoice by remember { mutableStateOf("") }
    var lastPaymentHash by remember { mutableStateOf("") }

    // Login state
    var isLoginActive by remember { mutableStateOf(false) }
    var isCreatingInvoice by remember { mutableStateOf(false) }
    var isPollingPayment by remember { mutableStateOf(false) }
    var paymentReceived by remember { mutableStateOf(false) }
    var showInvoiceDialog by remember { mutableStateOf(false) }
    var invoiceAmountSats by remember { mutableStateOf(100UL) } // Default 100 sats for demo

    // UI state
    var statusMessage by remember { mutableStateOf("") }
    var showIdDialog by remember { mutableStateOf(false) }
    var showWalletInfoDialog by remember { mutableStateOf(false) }
    var showVccResult by remember { mutableStateOf(false) }
    var vccResult by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var vccId by remember { mutableStateOf("") }

    // Check if onboarding is complete (with delayed transition)
    val onboardingComplete = step1Complete && step2Complete && step3Complete
    var showLoginScreen by remember { mutableStateOf(false) }
    
    // Delay transition to login screen so user sees Step 3 complete
    LaunchedEffect(onboardingComplete) {
        if (onboardingComplete && !showLoginScreen) {
            delay(1500) // 1.5 second delay to see completion
            showLoginScreen = true
        }
    }

    // Auto-initialize wallet if already set up
    LaunchedEffect(step2Complete) {
        if (step2Complete && walletState is BreezWalletManager.WalletState.Disconnected) {
            breezMgr.initializeWallet()
        }
    }

    // Update step2Complete when wallet becomes ready
    LaunchedEffect(walletState) {
        when (val state = walletState) {
            is BreezWalletManager.WalletState.Connected -> {
                walletSparkAddress = state.sparkAddress ?: ""
                step2Complete = true
                isWalletInitializing = false
            }
            is BreezWalletManager.WalletState.Error -> {
                statusMessage = "Wallet error: ${state.message}"
                isWalletInitializing = false
            }
            is BreezWalletManager.WalletState.Connecting -> {
                isWalletInitializing = true
            }
            else -> {}
        }
    }

    // Poll for payment when invoice is active
    LaunchedEffect(isPollingPayment, lastPaymentHash) {
        if (isPollingPayment && lastPaymentHash.isNotEmpty()) {
            while (isPollingPayment && !paymentReceived) {
                val received = breezMgr.isPaymentReceived(lastPaymentHash)
                if (received) {
                    paymentReceived = true
                    isPollingPayment = false
                    isLoginActive = false
                    statusMessage = "✅ Payment received! Log In verified."
                    // Close the invoice dialog
                    showInvoiceDialog = false
                }
                delay(3000) // Poll every 3 seconds
            }
        }
    }

    // ===== Screen Routing =====
    if (showLoginScreen) {
        // Show Login Screen
        LoginScreen(
            did = did,
            balanceSats = balanceSats,
            vccId = vccId,
            vccResult = vccResult,
            lastInvoice = lastInvoice,
            isCreatingInvoice = isCreatingInvoice,
            isPollingPayment = isPollingPayment,
            paymentReceived = paymentReceived,
            showInvoiceDialog = showInvoiceDialog,
            invoiceAmountSats = loginSession?.amountSats ?: 100UL,
            statusMessage = statusMessage,
            loginSession = loginSession,
            onLoginSessionReceived = { session ->
                loginSession = session
            },
            onStartLogin = {
                scope.launch {
                    isCreatingInvoice = true
                    statusMessage = ""
                    
                    // Use session ID from login session, or generate one for demo
                    val sessionId = loginSession?.sessionId ?: "demo_${System.currentTimeMillis()}"
                    lastLoginId = sessionId
                    
                    // Use amount from login session (set by employer in QR/link)
                    val amountSats = loginSession?.amountSats ?: 100UL
                    
                    // Create invoice using Breez SDK
                    val result = breezMgr.createInvoice(
                        amountSats = amountSats,
                        description = "SignedByMe Log In: ${loginSession?.employerName ?: "Demo"} - $sessionId"
                    )
                    
                    result.onSuccess { invoice ->
                        lastInvoice = invoice
                        lastPaymentHash = invoice.takeLast(64)
                        isLoginActive = true
                        isPollingPayment = true
                        
                        // Send invoice to API for employer to pay
                        launch(Dispatchers.IO) {
                            try {
                                val apiResult = sendInvoiceToApi(
                                    sessionId = sessionId,
                                    invoice = invoice,
                                    did = did,
                                    employerName = loginSession?.employerName ?: "Demo"
                                )
                                withContext(Dispatchers.Main) {
                                    if (!apiResult) {
                                        // API send failed - still allow manual testing via debug button
                                        statusMessage = "Note: Could not reach API. Use debug button to test."
                                    }
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    statusMessage = "API error: ${e.message}"
                                }
                            }
                        }
                    }.onFailure { e ->
                        statusMessage = "Failed to create invoice: ${e.message}"
                    }
                    
                    isCreatingInvoice = false
                }
            },
            onShowInvoiceDialog = { showInvoiceDialog = true },
            onDismissInvoiceDialog = { showInvoiceDialog = false },
            onCopyInvoice = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Lightning Invoice", lastInvoice))
                Toast.makeText(context, "Invoice copied!", Toast.LENGTH_SHORT).show()
            },
            onShareInvoice = {
                val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, lastInvoice)
                    type = "text/plain"
                }
                context.startActivity(Intent.createChooser(sendIntent, "Share Invoice"))
            },
            onResetLogin = {
                lastInvoice = ""
                lastPaymentHash = ""
                lastLoginId = ""
                isLoginActive = false
                isPollingPayment = false
                paymentReceived = false
                showInvoiceDialog = false
                statusMessage = ""
                loginSession = null
            },
            onCopyVcc = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("VCC", vccResult))
                Toast.makeText(context, "VCC copied!", Toast.LENGTH_SHORT).show()
            },
            onShareVcc = {
                val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, vccResult)
                    type = "text/plain"
                }
                context.startActivity(Intent.createChooser(sendIntent, "Share VCC"))
            }
        )
    } else {
        // Show Onboarding Screen
        OnboardingScreen(
            did = did,
            step1Complete = step1Complete,
            step2Complete = step2Complete,
            step3Complete = step3Complete,
            walletState = walletState,
            balanceSats = balanceSats,
            isWalletInitializing = isWalletInitializing,
            walletSparkAddress = walletSparkAddress,
            isLoading = isLoading,
            statusMessage = statusMessage,
            showIdDialog = showIdDialog,
            showWalletInfoDialog = showWalletInfoDialog,
            showVccResult = showVccResult,
            vccResult = vccResult,
            onGenerateDid = {
                did = didMgr.createDid()
                step1Complete = true
            },
            onShowIdDialog = { showIdDialog = true },
            onDismissIdDialog = { showIdDialog = false },
            onRegenerateDid = {
                did = didMgr.regenerateKeyPair()
                step1Complete = true
                step2Complete = false
                step3Complete = false
            },
            onCopyDid = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("DID", did))
                Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
            },
            onSetupWallet = {
                scope.launch {
                    isWalletInitializing = true
                    statusMessage = ""
                    val result = breezMgr.initializeWallet()
                    result.onFailure { e ->
                        statusMessage = "Error: ${e.message}"
                    }
                }
            },
            onShowWalletInfoDialog = { showWalletInfoDialog = true },
            onDismissWalletInfoDialog = { showWalletInfoDialog = false },
            onCopySparkAddress = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Spark Address", walletSparkAddress))
                Toast.makeText(context, "Spark Address copied!", Toast.LENGTH_SHORT).show()
            },
            onGenerateSignature = {
                isLoading = true
                scope.launch(Dispatchers.IO) {
                    try {
                        var preimage = lastPreimage
                        if (preimage.isEmpty()) {
                            val bytes = ByteArray(32)
                            java.security.SecureRandom().nextBytes(bytes)
                            preimage = bytes.joinToString("") { "%02x".format(it) }
                            withContext(Dispatchers.Main) { lastPreimage = preimage }
                        }

                        val claimJson = didMgr.buildOwnershipClaimJson(
                            did = did,
                            nonce = lastNonce.ifEmpty { "android-${System.currentTimeMillis()}" },
                            walletType = "breez",
                            withdrawTo = walletSparkAddress.ifEmpty { "lightning-wallet" },
                            preimage = preimage
                        )

                        val sigHex = didMgr.signOwnershipClaim(claimJson)

                        val preBytes = preimage.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                        val md = java.security.MessageDigest.getInstance("SHA-256")
                        val preShaHex = md.digest(preBytes).joinToString("") { "%02x".format(it) }

                        val prpJson = didMgr.buildPrpJson(
                            loginId = lastLoginId.ifEmpty { "android-${System.currentTimeMillis()}" },
                            did = did,
                            preimageSha256Hex = preShaHex
                        )

                        val generatedVccId = "vcc_${System.currentTimeMillis()}_${did.takeLast(8)}"
                        val vcc = JSONObject().apply {
                            put("schema", "signedby.me/vcc/1")
                            put("id", generatedVccId)
                            put("did", did)
                            put("content_hash", "sha256_demo_${System.currentTimeMillis()}")
                            put("proof_hash", preShaHex)
                            put("wallet_type", "breez")
                            put("timestamp", System.currentTimeMillis())
                            put("signature", sigHex)
                        }.toString()

                        withContext(Dispatchers.Main) {
                            lastClaimJson = claimJson
                            lastSigHex = sigHex
                            lastPrpJson = prpJson
                            vccResult = vcc
                            vccId = generatedVccId
                            step3Complete = true
                            showVccResult = true
                            isLoading = false
                            statusMessage = "Signature generated!"
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) {
                            statusMessage = "Error: ${e.message}"
                            isLoading = false
                        }
                    }
                }
            },
            onCopyVcc = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("VCC", vccResult))
                Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
            },
            onShareVcc = {
                val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, vccResult)
                    type = "text/plain"
                }
                context.startActivity(Intent.createChooser(sendIntent, "Share VCC"))
            }
        )
    }

}

// ===== Onboarding Screen =====
@Composable
fun OnboardingScreen(
    did: String,
    step1Complete: Boolean,
    step2Complete: Boolean,
    step3Complete: Boolean,
    walletState: BreezWalletManager.WalletState,
    balanceSats: Long,
    isWalletInitializing: Boolean,
    walletSparkAddress: String,
    isLoading: Boolean,
    statusMessage: String,
    showIdDialog: Boolean,
    showWalletInfoDialog: Boolean,
    showVccResult: Boolean,
    vccResult: String,
    onGenerateDid: () -> Unit,
    onShowIdDialog: () -> Unit,
    onDismissIdDialog: () -> Unit,
    onRegenerateDid: () -> Unit,
    onCopyDid: () -> Unit,
    onSetupWallet: () -> Unit,
    onShowWalletInfoDialog: () -> Unit,
    onDismissWalletInfoDialog: () -> Unit,
    onCopySparkAddress: () -> Unit,
    onGenerateSignature: () -> Unit,
    onCopyVcc: () -> Unit,
    onShareVcc: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.linearGradient(
                    colors = listOf(
                        Color(0xFFF7FAFF),
                        Color(0xFFF0F5FE),
                        Color(0xFFE6F0FC)
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            // Header
            Text(
                text = "SignedByMe",
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center,
                style = LocalTextStyle.current.copy(
                    brush = Brush.linearGradient(
                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6))
                    )
                )
            )

            Text(
                text = "Start by pressing the button below in Step 1",
                fontSize = 16.sp,
                color = Color.Gray,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )

            // Step 1: Create
            StepCard(
                stepNumber = 1,
                title = "Create",
                isComplete = step1Complete,
                isEnabled = true
            ) {
                if (!step1Complete) {
                    Text(
                        "Press button below to start",
                        color = Color.Gray,
                        fontSize = 14.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    GradientButton(
                        text = "Generate",
                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                        onClick = onGenerateDid
                    )
                } else {
                    CompletedStepContent(
                        message = "Signature created ✓",
                        onInfoClick = onShowIdDialog
                    )
                }
            }

            // Step 2: Connect
            StepCard(
                stepNumber = 2,
                title = "Connect",
                isComplete = step2Complete && walletState is BreezWalletManager.WalletState.Connected,
                isEnabled = step1Complete
            ) {
                if (!step2Complete || walletState !is BreezWalletManager.WalletState.Connected) {
                    Text(
                        "Press button below to set up your wallet",
                        color = Color.Gray,
                        fontSize = 14.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    Box(
                        modifier = Modifier.fillMaxWidth(),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(text = "⚡", fontSize = 48.sp)
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    if (isWalletInitializing) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(40.dp),
                                color = Color(0xFF3B82F6)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text("Setting up wallet...", fontSize = 14.sp, color = Color.Gray)
                        }
                    } else {
                        GradientButton(
                            text = "Set Up Wallet",
                            colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                            onClick = onSetupWallet
                        )
                    }

                    if (walletState is BreezWalletManager.WalletState.Error) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            (walletState as BreezWalletManager.WalletState.Error).message,
                            color = Color(0xFFEF4444),
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                } else {
                    CompletedStepContent(
                        message = "Wallet connected ✓",
                        onInfoClick = onShowWalletInfoDialog
                    )
                }
            }

            // Step 3: Prove
            StepCard(
                stepNumber = 3,
                title = "Prove",
                isComplete = step3Complete,
                isEnabled = step1Complete && step2Complete && walletState is BreezWalletManager.WalletState.Connected
            ) {
                if (!step3Complete) {
                    Text(
                        "Press button below to generate your Signature",
                        fontSize = 14.sp,
                        color = Color.Gray,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    if (isLoading) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(40.dp),
                                color = Color(0xFFEF4444)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text("Generating...", fontSize = 14.sp, color = Color.Gray)
                        }
                    } else {
                        GradientButton(
                            text = "Generate Signature",
                            colors = listOf(Color(0xFFEF4444), Color(0xFFF97316)),
                            enabled = walletState is BreezWalletManager.WalletState.Connected,
                            onClick = onGenerateSignature
                        )
                    }
                } else {
                    StatusPill("Signature Verified ✓", Color(0xFF10B981))
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    Text(
                        "Setup complete! You're ready to use SignedByMe.",
                        fontSize = 14.sp,
                        color = Color(0xFF10B981),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }

            // Status message
            if (statusMessage.isNotEmpty()) {
                Text(
                    text = statusMessage,
                    fontSize = 12.sp,
                    color = Color.Gray,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center
                )
            }

            Spacer(modifier = Modifier.height(40.dp))
        }
    }

    // Dialogs
    if (showIdDialog) {
        DIDInfoDialog(
            did = did,
            onDismiss = onDismissIdDialog,
            onRegenerate = onRegenerateDid,
            onCopy = onCopyDid
        )
    }

    if (showWalletInfoDialog) {
        WalletInfoDialog(
            sparkAddress = walletSparkAddress,
            balanceSats = balanceSats,
            onDismiss = onDismissWalletInfoDialog,
            onCopySparkAddress = onCopySparkAddress
        )
    }
}

// ===== Login Screen =====
@Composable
fun LoginScreen(
    did: String,
    balanceSats: Long,
    vccId: String,
    vccResult: String,
    lastInvoice: String,
    isCreatingInvoice: Boolean,
    isPollingPayment: Boolean,
    paymentReceived: Boolean,
    showInvoiceDialog: Boolean,
    invoiceAmountSats: ULong,
    statusMessage: String,
    loginSession: LoginSession?,
    onLoginSessionReceived: (LoginSession) -> Unit,
    onStartLogin: () -> Unit,
    onShowInvoiceDialog: () -> Unit,
    onDismissInvoiceDialog: () -> Unit,
    onCopyInvoice: () -> Unit,
    onShareInvoice: () -> Unit,
    onResetLogin: () -> Unit,
    onCopyVcc: () -> Unit,
    onShareVcc: () -> Unit
) {
    // QR Scanner state
    var showQrScanner by remember { mutableStateOf(false) }
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.linearGradient(
                    colors = listOf(
                        Color(0xFFF7FAFF),
                        Color(0xFFF0F5FE),
                        Color(0xFFE6F0FC)
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(40.dp))

            // Header
            Text(
                text = "SignedByMe",
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
                style = LocalTextStyle.current.copy(
                    brush = Brush.linearGradient(
                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6))
                    )
                )
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Ready to Log In",
                fontSize = 16.sp,
                color = Color.Gray
            )

            Spacer(modifier = Modifier.height(32.dp))

            // Login Section
            // Login Section Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .shadow(8.dp, RoundedCornerShape(24.dp)),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Box(modifier = Modifier.fillMaxWidth()) {
                    // Employer badge in upper left when session exists (hide after login complete)
                    if (loginSession != null && !paymentReceived) {
                        Row(
                            modifier = Modifier
                                .align(Alignment.TopStart)
                                .padding(12.dp)
                                .background(
                                    Color(0xFF10B981).copy(alpha = 0.1f),
                                    RoundedCornerShape(20.dp)
                                )
                                .padding(horizontal = 12.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = Color(0xFF10B981),
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = loginSession.employerName,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color(0xFF10B981)
                            )
                        }
                    }
                    
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp)
                            .padding(top = if (loginSession != null && !paymentReceived) 24.dp else 0.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        if (paymentReceived) {
                            // Success state
                            Box(
                                modifier = Modifier
                                    .size(64.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFF10B981).copy(alpha = 0.1f)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    Icons.Default.CheckCircle,
                                    contentDescription = null,
                                    tint = Color(0xFF10B981),
                                    modifier = Modifier.size(40.dp)
                                )
                            }

                            Spacer(modifier = Modifier.height(16.dp))

                            Text(
                                "Log In Verified!",
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF10B981)
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                if (loginSession != null) 
                                    "You're now logged in to ${loginSession.employerName}"
                                else 
                                    "Your identity has been verified.",
                                fontSize = 14.sp,
                                color = Color.Gray,
                                textAlign = TextAlign.Center
                            )

                            Spacer(modifier = Modifier.height(16.dp))

                            OutlinedButton(onClick = onResetLogin) {
                                Text("Start New Log In")
                            }

                        } else if (lastInvoice.isNotEmpty()) {
                            // Awaiting payment state
                            Text(
                                "⏳",
                                fontSize = 48.sp
                            )

                            Spacer(modifier = Modifier.height(12.dp))

                            Text(
                                "Awaiting Payment",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color(0xFFF59E0B)
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            // Show employer name if we have it
                            if (loginSession != null) {
                                Text(
                                    "Waiting for ${loginSession.employerName} to confirm",
                                    fontSize = 14.sp,
                                    color = Color.Gray,
                                    textAlign = TextAlign.Center
                                )
                            }

                            if (isPollingPayment) {
                                Spacer(modifier = Modifier.height(12.dp))
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.Center
                                ) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        strokeWidth = 2.dp,
                                        color = Color(0xFFF59E0B)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        "Checking for payment...",
                                        fontSize = 12.sp,
                                        color = Color.Gray
                                    )
                                }
                            }
                            
                            // Debug-only: View Invoice button (for testing payments)
                            if (BuildConfig.DEBUG) {
                                Spacer(modifier = Modifier.height(16.dp))
                                OutlinedButton(
                                    onClick = onShowInvoiceDialog,
                                    colors = ButtonDefaults.outlinedButtonColors(
                                        contentColor = Color.Gray
                                    )
                                ) {
                                    Text("View Invoice (Debug)", fontSize = 12.sp)
                                }
                            }

                        } else {
                            // Ready to start login
                            if (loginSession != null) {
                                // Has a session from QR/deep link - ready to login
                                Text(
                                    "🔐",
                                    fontSize = 48.sp
                                )

                                Spacer(modifier = Modifier.height(12.dp))

                                Text(
                                    "Ready to Log In",
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.SemiBold
                                )

                                Spacer(modifier = Modifier.height(8.dp))

                                Text(
                                    "Press button below to start your Log In with your Signature",
                                    fontSize = 14.sp,
                                    color = Color.Gray,
                                    textAlign = TextAlign.Center
                                )

                                Spacer(modifier = Modifier.height(20.dp))

                                if (isCreatingInvoice) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(40.dp),
                                        color = Color(0xFF3B82F6)
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text("Creating invoice...", fontSize = 13.sp, color = Color.Gray)
                                } else {
                                    GradientButton(
                                        text = "Start Log In",
                                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                                        onClick = onStartLogin
                                    )
                                }
                            } else {
                                // No session yet - show scan QR option
                                Text(
                                    "📷",
                                    fontSize = 48.sp
                                )

                                Spacer(modifier = Modifier.height(12.dp))

                                Text(
                                    "Scan Log In QR Code",
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.SemiBold
                                )

                                Spacer(modifier = Modifier.height(8.dp))

                                Text(
                                    "Scan the QR Code on your computer to Log In",
                                    fontSize = 14.sp,
                                    color = Color.Gray,
                                    textAlign = TextAlign.Center
                                )

                                Spacer(modifier = Modifier.height(20.dp))

                                GradientButton(
                                    text = "Scan QR Code",
                                    colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                                    onClick = { showQrScanner = true }
                                )

                                Spacer(modifier = Modifier.height(16.dp))

                                // Demo button for testing
                                OutlinedButton(
                                    onClick = {
                                        // Demo: simulate receiving a login session with 100 sats
                                        onLoginSessionReceived(LoginSession(
                                            sessionId = "demo_${System.currentTimeMillis()}",
                                            employerName = "Acme Corp",
                                            amountSats = 100UL
                                        ))
                                    }
                                ) {
                                    Text("Demo: Acme Corp Log In (100 sats)", fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }

            // VCC Section
            if (vccResult.isNotEmpty()) {
                Spacer(modifier = Modifier.height(24.dp))
                
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .shadow(8.dp, RoundedCornerShape(24.dp)),
                    shape = RoundedCornerShape(24.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White)
                ) {
                    Column(
                        modifier = Modifier.padding(24.dp)
                    ) {
                        Text(
                            "Your Verified Content Claim (VCC)",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            "Use your VCC to prove your content is yours. This VCC is cryptographically tied to your Signature.",
                            fontSize = 13.sp,
                            color = Color.Gray,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        StatusPill("Verified Content Claim", Color(0xFF10B981))
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        // VCC preview
                        Text(
                            text = vccResult.take(60) + "...",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color.Gray,
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFF3F4F6), RoundedCornerShape(8.dp))
                                .padding(12.dp)
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        // Copy / Share buttons
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            OutlinedButton(
                                onClick = onCopyVcc,
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("📋 Copy")
                            }
                            
                            OutlinedButton(
                                onClick = onShareVcc,
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Share")
                            }
                        }
                    }
                }
            }

            // Status message
            if (statusMessage.isNotEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = statusMessage,
                    fontSize = 12.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
            }

            Spacer(modifier = Modifier.height(40.dp))
        }
    }

    // Invoice Dialog
    if (showInvoiceDialog && lastInvoice.isNotEmpty()) {
        InvoiceDialog(
            invoice = lastInvoice,
            amountSats = invoiceAmountSats.toLong(),
            isPolling = isPollingPayment,
            onDismiss = onDismissInvoiceDialog,
            onCopy = onCopyInvoice,
            onShare = onShareInvoice
        )
    }
    
    // QR Scanner Dialog
    if (showQrScanner) {
        QrScannerDialog(
            onQrScanned = { qrContent ->
                showQrScanner = false
                // Parse the QR content (signedby.me://login?session=xxx&employer=xxx&amount=xxx)
                try {
                    val uri = android.net.Uri.parse(qrContent)
                    val sessionId = uri.getQueryParameter("session")
                    val employer = uri.getQueryParameter("employer")
                    val amountStr = uri.getQueryParameter("amount")
                    val amount = amountStr?.toULongOrNull() ?: 100UL // Default 100 sats
                    
                    if (sessionId != null && employer != null) {
                        onLoginSessionReceived(LoginSession(sessionId, employer, amount))
                    }
                } catch (e: Exception) {
                    // Invalid QR format
                }
            },
            onDismiss = { showQrScanner = false }
        )
    }
}

// ===== QR Scanner Dialog =====
@Composable
fun QrScannerDialog(
    onQrScanned: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var hasCameraPermission by remember {
        mutableStateOf(
            androidx.core.content.ContextCompat.checkSelfPermission(
                context, android.Manifest.permission.CAMERA
            ) == android.content.pm.PackageManager.PERMISSION_GRANTED
        )
    }
    
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }
    
    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permissionLauncher.launch(android.Manifest.permission.CAMERA)
        }
    }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(0.8f),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Scan Log In QR Code",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    "Point your camera at the QR Code on your computer screen",
                    fontSize = 13.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                if (hasCameraPermission) {
                    // Camera preview with QR scanning
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(Color.Black)
                    ) {
                        AndroidView(
                            factory = { ctx ->
                                val previewView = androidx.camera.view.PreviewView(ctx)
                                val cameraProviderFuture = androidx.camera.lifecycle.ProcessCameraProvider.getInstance(ctx)
                                
                                cameraProviderFuture.addListener({
                                    val cameraProvider = cameraProviderFuture.get()
                                    
                                    val preview = androidx.camera.core.Preview.Builder().build().also {
                                        it.setSurfaceProvider(previewView.surfaceProvider)
                                    }
                                    
                                    val imageAnalysis = androidx.camera.core.ImageAnalysis.Builder()
                                        .setBackpressureStrategy(androidx.camera.core.ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                        .build()
                                        .also { analysis ->
                                            analysis.setAnalyzer(
                                                java.util.concurrent.Executors.newSingleThreadExecutor()
                                            ) { imageProxy ->
                                                @androidx.camera.core.ExperimentalGetImage
                                                val mediaImage = imageProxy.image
                                                if (mediaImage != null) {
                                                    val inputImage = com.google.mlkit.vision.common.InputImage.fromMediaImage(
                                                        mediaImage, imageProxy.imageInfo.rotationDegrees
                                                    )
                                                    
                                                    val scanner = com.google.mlkit.vision.barcode.BarcodeScanning.getClient()
                                                    scanner.process(inputImage)
                                                        .addOnSuccessListener { barcodes ->
                                                            for (barcode in barcodes) {
                                                                barcode.rawValue?.let { value ->
                                                                    if (value.contains("session=") && value.contains("employer=")) {
                                                                        onQrScanned(value)
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        .addOnCompleteListener {
                                                            imageProxy.close()
                                                        }
                                                } else {
                                                    imageProxy.close()
                                                }
                                            }
                                        }
                                    
                                    try {
                                        cameraProvider.unbindAll()
                                        cameraProvider.bindToLifecycle(
                                            ctx as androidx.lifecycle.LifecycleOwner,
                                            androidx.camera.core.CameraSelector.DEFAULT_BACK_CAMERA,
                                            preview,
                                            imageAnalysis
                                        )
                                    } catch (e: Exception) {
                                        e.printStackTrace()
                                    }
                                }, androidx.core.content.ContextCompat.getMainExecutor(ctx))
                                
                                previewView
                            },
                            modifier = Modifier.fillMaxSize()
                        )
                        
                        // Scanning frame overlay
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(40.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(200.dp)
                                    .border(3.dp, Color.White, RoundedCornerShape(12.dp))
                            )
                        }
                    }
                } else {
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth(),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            "Camera permission required",
                            color = Color.Gray
                        )
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Cancel")
                }
            }
        }
    }
}

// ===== Components =====

@Composable
fun StepCard(
    stepNumber: Int,
    title: String,
    isComplete: Boolean,
    isEnabled: Boolean,
    content: @Composable ColumnScope.() -> Unit
) {
    val alphaValue = if (isEnabled) 1f else 0.6f

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .alpha(alphaValue)
            .shadow(
                elevation = if (isEnabled) 12.dp else 4.dp,
                shape = RoundedCornerShape(24.dp),
                ambientColor = Color.Black.copy(alpha = 0.08f)
            ),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.85f))
    ) {
        Column(modifier = Modifier.padding(24.dp)) {
            // Header
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Step badge
                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .clip(CircleShape)
                        .background(
                            if (isComplete) {
                                Brush.linearGradient(listOf(Color(0xFF10B981), Color(0xFF34D399)))
                            } else if (isEnabled) {
                                Brush.linearGradient(listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)))
                            } else {
                                Brush.linearGradient(listOf(Color.Gray, Color.Gray))
                            }
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    if (isComplete) {
                        Icon(
                            Icons.Default.Check,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(28.dp)
                        )
                    } else {
                        Text(
                            text = "$stepNumber",
                            color = Color.White,
                            fontSize = 24.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.width(16.dp))

                Text(
                    text = title,
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (isEnabled) Color.Black else Color.Gray
                )
            }

            // Content
            if (isEnabled || isComplete) {
                Spacer(modifier = Modifier.height(20.dp))
                content()
            }
        }
    }
}

@Composable
fun GradientButton(
    text: String,
    colors: List<Color>,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier
            .fillMaxWidth()
            .height(56.dp),
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
        contentPadding = PaddingValues(0.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    if (enabled) Brush.linearGradient(colors)
                    else Brush.linearGradient(listOf(Color.Gray, Color.Gray))
                ),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = text,
                color = Color.White,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}

@Composable
fun StatusPill(text: String, color: Color) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color.White, RoundedCornerShape(12.dp))
            .border(1.dp, Color.Black.copy(alpha = 0.1f), RoundedCornerShape(12.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Default.CheckCircle,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(20.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = text,
            fontWeight = FontWeight.SemiBold,
            fontSize = 16.sp
        )
    }
}

@Composable
fun CompletedStepContent(
    message: String,
    onInfoClick: (() -> Unit)?
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color.White.copy(alpha = 0.7f), RoundedCornerShape(8.dp))
            .border(1.dp, Color.Gray.copy(alpha = 0.2f), RoundedCornerShape(8.dp))
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = message,
            fontSize = 14.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.weight(1f)
        )
        if (onInfoClick != null) {
            IconButton(onClick = onInfoClick) {
                Icon(
                    Icons.Default.Info,
                    contentDescription = "Info",
                    tint = Color(0xFF3B82F6)
                )
            }
        }
    }
}

@Composable
fun DIDInfoDialog(
    did: String,
    onDismiss: () -> Unit,
    onRegenerate: () -> Unit,
    onCopy: () -> Unit
) {
    val qrBitmap = remember(did) { generateQRCode(did, 400) }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Your Signature",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.SemiBold
                )

                Spacer(modifier = Modifier.height(16.dp))

                // QR Code
                Box(
                    modifier = Modifier
                        .size(200.dp)
                        .background(Color.White, RoundedCornerShape(8.dp))
                        .border(1.dp, Color.Gray, RoundedCornerShape(8.dp))
                        .padding(8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (qrBitmap != null) {
                        Image(
                            bitmap = qrBitmap.asImageBitmap(),
                            contentDescription = "QR Code for DID",
                            modifier = Modifier.fillMaxSize()
                        )
                    } else {
                        Text("Error generating QR", color = Color.Gray)
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Truncated DID
                Text(
                    text = "${did.take(12)}...${did.takeLast(6)}",
                    fontSize = 14.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color.Gray
                )

                Spacer(modifier = Modifier.height(8.dp))

                // Full DID (scrollable)
                Text(
                    text = did,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 100.dp)
                        .verticalScroll(rememberScrollState())
                )

                Spacer(modifier = Modifier.height(16.dp))

                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedButton(onClick = onCopy) {
                        Text("📋 Copy ID")
                    }

                    Button(
                        onClick = {
                            onRegenerate()
                            onDismiss()
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFEF4444))
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Regenerate")
                    }
                }
            }
        }
    }
}

@Composable
fun WalletInfoDialog(
    sparkAddress: String,
    balanceSats: Long,
    onDismiss: () -> Unit,
    onCopySparkAddress: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Lightning icon
                Text("⚡", fontSize = 48.sp)
                
                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    "Lightning Wallet",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(20.dp))

                // Balance card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFF3B82F6).copy(alpha = 0.1f)
                    ),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            "Balance",
                            fontSize = 14.sp,
                            color = Color.Gray
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            "$balanceSats sats",
                            fontSize = 28.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF3B82F6)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Spark Address
                Text(
                    "Spark Address",
                    fontSize = 14.sp,
                    color = Color.Gray
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = if (sparkAddress.length > 20) "${sparkAddress.take(10)}...${sparkAddress.takeLast(10)}" else sparkAddress.ifEmpty { "Not available" },
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color.Black
                )

                Spacer(modifier = Modifier.height(20.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onCopySparkAddress,
                        modifier = Modifier.weight(1f),
                        enabled = sparkAddress.isNotEmpty()
                    ) {
                        Text("📋 Copy Address")
                    }
                    
                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                    ) {
                        Text("Done")
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Security note
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFFEF3C7)),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Text("🔒", fontSize = 14.sp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Your wallet keys are stored securely on this device using hardware-backed encryption.",
                            fontSize = 12.sp,
                            color = Color(0xFF92400E)
                        )
                    }
                }
            }
        }
    }
}

/**
 * Generate a QR code bitmap from a string.
 */
private fun generateQRCode(content: String, size: Int): Bitmap? {
    return try {
        val writer = QRCodeWriter()
        val bitMatrix: BitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size)
        
        val width = bitMatrix.width
        val height = bitMatrix.height
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
        
        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
            }
        }
        
        bitmap
    } catch (e: Exception) {
        e.printStackTrace()
        null
    }
}

@Composable
fun InvoiceDialog(
    invoice: String,
    amountSats: Long,
    isPolling: Boolean,
    onDismiss: () -> Unit,
    onCopy: () -> Unit,
    onShare: () -> Unit
) {
    val qrBitmap = remember(invoice) { generateQRCode(invoice, 400) }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Header
                Text("⚡", fontSize = 40.sp)
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    "Lightning Invoice",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                Text(
                    "$amountSats sats",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color(0xFFF59E0B)
                )

                Spacer(modifier = Modifier.height(16.dp))

                // QR Code
                Box(
                    modifier = Modifier
                        .size(220.dp)
                        .background(Color.White, RoundedCornerShape(12.dp))
                        .border(2.dp, Color(0xFFF59E0B), RoundedCornerShape(12.dp))
                        .padding(12.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (qrBitmap != null) {
                        Image(
                            bitmap = qrBitmap.asImageBitmap(),
                            contentDescription = "QR Code for Lightning Invoice",
                            modifier = Modifier.fillMaxSize()
                        )
                    } else {
                        Text("Error generating QR", color = Color.Gray)
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Invoice preview (truncated)
                Text(
                    text = "${invoice.take(25)}...${invoice.takeLast(10)}",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color.Gray
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Polling status
                if (isPolling) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = Color(0xFFFEF3C7)
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = Color(0xFFF59E0B)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                "Waiting for payment...",
                                fontSize = 14.sp,
                                color = Color(0xFF92400E)
                            )
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                }

                // Action buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onCopy,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("📋 Copy")
                    }
                    
                    OutlinedButton(
                        onClick = onShare,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Share")
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Done button
                Button(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                ) {
                    Text("Done")
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Instructions
                Text(
                    "Share this invoice with your employer.\nThey will pay it to verify your identity.",
                    fontSize = 12.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}
