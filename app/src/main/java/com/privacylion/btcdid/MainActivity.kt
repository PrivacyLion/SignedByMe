package com.privacylion.btcdid

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.*
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

        setContent {
            BTC_DIDTheme {
                SignedByMeApp(didMgr, breezMgr)
            }
        }
    }
}

@Composable
fun SignedByMeApp(didMgr: DidWalletManager, breezMgr: BreezWalletManager) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // ===== State =====
    var did by remember { mutableStateOf(didMgr.getPublicDID() ?: "") }
    var step1Complete by remember { mutableStateOf(did.isNotEmpty()) }
    val walletState by breezMgr.walletState.collectAsState()
    var step2Complete by remember { mutableStateOf(walletState is BreezWalletManager.WalletState.Connected) }
    var step3Complete by remember { mutableStateOf(false) }

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

    // Enterprise login state
    var isEnterpriseLoginActive by remember { mutableStateOf(false) }
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
                    isEnterpriseLoginActive = false
                    statusMessage = "✅ Payment received! Enterprise login verified."
                    // Close the invoice dialog
                    showInvoiceDialog = false
                }
                delay(3000) // Poll every 3 seconds
            }
        }
    }

    // Background gradient
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
            // ===== Header =====
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

            // ===== Step 1: Create =====
            StepCard(
                stepNumber = 1,
                title = "Create",
                isComplete = step1Complete,
                isEnabled = true
            ) {
                if (!step1Complete) {
                    Text(
                        "To Create a Signature press the button below.",
                        color = Color.Gray,
                        fontSize = 14.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    GradientButton(
                        text = "Generate",
                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                        onClick = {
                            did = didMgr.createDid()
                            step1Complete = true
                        }
                    )
                } else {
                    CompletedStepContent(
                        message = "Tap (i) to view your Signature",
                        onInfoClick = { showIdDialog = true }
                    )
                }
            }

            // ===== Step 2: Connect (Breez Wallet) =====
            StepCard(
                stepNumber = 2,
                title = "Connect",
                isComplete = step2Complete && walletState is BreezWalletManager.WalletState.Connected,
                isEnabled = step1Complete
            ) {
                if (!step2Complete || walletState !is BreezWalletManager.WalletState.Connected) {
                    // Not connected yet
                    Text(
                        "Set up your Lightning wallet to receive payments",
                        color = Color.Gray,
                        fontSize = 14.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    // Lightning bolt icon
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "⚡",
                            fontSize = 48.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        "Your wallet will be created securely on this device. " +
                        "You'll be able to receive Bitcoin payments instantly.",
                        color = Color.Gray,
                        fontSize = 13.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(20.dp))

                    if (isWalletInitializing) {
                        // Loading state
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(40.dp),
                                color = Color(0xFF3B82F6)
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                            Text(
                                "Setting up your wallet...",
                                fontSize = 14.sp,
                                color = Color.Gray
                            )
                        }
                    } else {
                        GradientButton(
                            text = "Set Up Wallet",
                            colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                            onClick = {
                                scope.launch {
                                    isWalletInitializing = true
                                    statusMessage = ""
                                    val result = breezMgr.initializeWallet()
                                    result.onFailure { e ->
                                        statusMessage = "Error: ${e.message}"
                                    }
                                }
                            }
                        )
                    }

                    // Error state
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
                    // Wallet connected
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        // Info button
                        TextButton(onClick = { showWalletInfoDialog = true }) {
                            Icon(
                                Icons.Default.Info,
                                contentDescription = "Wallet Info",
                                tint = Color(0xFF3B82F6),
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                "Wallet Info",
                                color = Color(0xFF3B82F6),
                                fontSize = 14.sp
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Wallet status card
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = Color(0xFF10B981).copy(alpha = 0.1f)
                        ),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            // Lightning icon
                            Box(
                                modifier = Modifier
                                    .size(44.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFF10B981).copy(alpha = 0.2f)),
                                contentAlignment = Alignment.Center
                            ) {
                                Text("⚡", fontSize = 24.sp)
                            }

                            Spacer(modifier = Modifier.width(12.dp))

                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    "Lightning Wallet",
                                    fontWeight = FontWeight.SemiBold,
                                    fontSize = 16.sp
                                )
                                Text(
                                    "Balance: $balanceSats sats",
                                    fontSize = 14.sp,
                                    color = Color.Gray
                                )
                            }

                            Icon(
                                Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = Color(0xFF10B981),
                                modifier = Modifier.size(24.dp)
                            )
                        }
                    }

                    // Enterprise Login Section
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    HorizontalDivider(color = Color.Gray.copy(alpha = 0.2f))
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    Text(
                        "Enterprise Login",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 16.sp
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    Text(
                        "Generate a Lightning invoice for your employer to pay. " +
                        "Once paid, your identity is verified.",
                        color = Color.Gray,
                        fontSize = 13.sp
                    )
                    
                    Spacer(modifier = Modifier.height(12.dp))

                    if (paymentReceived) {
                        // Payment confirmed state
                        StatusPill("✅ Payment Verified", Color(0xFF10B981))
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            "Enterprise login complete! Proceed to Step 3.",
                            color = Color(0xFF10B981),
                            fontSize = 13.sp,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                    } else if (lastInvoice.isNotEmpty()) {
                        // Invoice created, awaiting payment
                        StatusPill("⏳ Awaiting Payment", Color(0xFFF59E0B))
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        // Show invoice preview
                        Text(
                            text = "Invoice: ${lastInvoice.take(30)}...",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color.Gray
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = { showInvoiceDialog = true },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Show QR")
                            }
                            
                            OutlinedButton(
                                onClick = {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    clipboard.setPrimaryClip(ClipData.newPlainText("Invoice", lastInvoice))
                                    Toast.makeText(context, "Invoice copied!", Toast.LENGTH_SHORT).show()
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("📋 Copy")
                            }
                        }
                        
                        if (isPollingPayment) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
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
                    } else {
                        // No invoice yet - show create button
                        if (isCreatingInvoice) {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(32.dp),
                                    color = Color(0xFF3B82F6)
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    "Creating invoice...",
                                    fontSize = 13.sp,
                                    color = Color.Gray
                                )
                            }
                        } else {
                            GradientButton(
                                text = "Start Enterprise Login",
                                colors = listOf(Color(0xFFF59E0B), Color(0xFFEF4444)),
                                onClick = {
                                    scope.launch {
                                        isCreatingInvoice = true
                                        statusMessage = ""
                                        
                                        // Generate login ID
                                        val loginId = "login_${System.currentTimeMillis()}_${did.takeLast(8)}"
                                        lastLoginId = loginId
                                        
                                        // Create invoice using Breez SDK
                                        val result = breezMgr.createInvoice(
                                            amountSats = invoiceAmountSats,
                                            description = "SignedByMe Enterprise Login: $loginId"
                                        )
                                        
                                        result.onSuccess { invoice ->
                                            lastInvoice = invoice
                                            // Extract payment hash from invoice (it's the SHA256 of the preimage)
                                            // For now, use a simple identifier - we'll improve this
                                            lastPaymentHash = invoice.takeLast(64) // Placeholder
                                            isEnterpriseLoginActive = true
                                            isPollingPayment = true
                                            showInvoiceDialog = true
                                            statusMessage = "Invoice created! Share with your employer."
                                        }.onFailure { e ->
                                            statusMessage = "Failed to create invoice: ${e.message}"
                                        }
                                        
                                        isCreatingInvoice = false
                                    }
                                }
                            )
                        }
                    }
                }
            }

            // ===== Step 3: Prove =====
            StepCard(
                stepNumber = 3,
                title = "Prove",
                isComplete = step3Complete,
                isEnabled = step1Complete && step2Complete && walletState is BreezWalletManager.WalletState.Connected
            ) {
                Text(
                    "Generate your Signature",
                    fontSize = 14.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(16.dp))

                GradientButton(
                    text = "Generate Signature",
                    colors = listOf(Color(0xFFEF4444), Color(0xFFF97316)),
                    enabled = walletState is BreezWalletManager.WalletState.Connected,
                    onClick = {
                        isLoading = true
                        scope.launch(Dispatchers.IO) {
                            try {
                                // Generate demo preimage if we don't have one
                                var preimage = lastPreimage
                                if (preimage.isEmpty()) {
                                    val bytes = ByteArray(32)
                                    java.security.SecureRandom().nextBytes(bytes)
                                    preimage = bytes.joinToString("") { "%02x".format(it) }
                                    withContext(Dispatchers.Main) { lastPreimage = preimage }
                                }

                                // Build ownership claim
                                val claimJson = didMgr.buildOwnershipClaimJson(
                                    did = did,
                                    nonce = lastNonce.ifEmpty { "android-${System.currentTimeMillis()}" },
                                    walletType = "breez",
                                    withdrawTo = walletSparkAddress.ifEmpty { "lightning-wallet" },
                                    preimage = preimage
                                )

                                // Sign the claim
                                val sigHex = didMgr.signOwnershipClaim(claimJson)

                                // Derive preimage_sha256
                                val preBytes = preimage.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                val md = java.security.MessageDigest.getInstance("SHA-256")
                                val preShaHex = md.digest(preBytes).joinToString("") { "%02x".format(it) }

                                // Build PRP
                                val prpJson = didMgr.buildPrpJson(
                                    loginId = lastLoginId.ifEmpty { "android-${System.currentTimeMillis()}" },
                                    did = did,
                                    preimageSha256Hex = preShaHex
                                )

                                // Generate VCC with proper schema
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
                    }
                )

                if (isLoading) {
                    Spacer(modifier = Modifier.height(16.dp))
                    CircularProgressIndicator(
                        modifier = Modifier.align(Alignment.CenterHorizontally),
                        color = Color(0xFFEF4444)
                    )
                }

                // Show VCC result
                if (showVccResult && vccResult.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    Text(
                        "Use your Verified Content Claim (VCC) to prove your content is yours. " +
                        "Your VCC is cryptographically tied to your signature.",
                        fontSize = 14.sp,
                        color = Color.Gray,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )
                    
                    Spacer(modifier = Modifier.height(12.dp))

                    StatusPill("Verified Content Claim", Color(0xFF10B981))

                    Spacer(modifier = Modifier.height(8.dp))

                    // VCC preview
                    Text(
                        text = vccResult.take(60) + "...",
                        fontSize = 12.sp,
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
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("VCC", vccResult))
                                Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("📋 Copy")
                        }

                        OutlinedButton(
                            onClick = {
                                val sendIntent = Intent().apply {
                                    action = Intent.ACTION_SEND
                                    putExtra(Intent.EXTRA_TEXT, vccResult)
                                    type = "text/plain"
                                }
                                context.startActivity(Intent.createChooser(sendIntent, "Share VCC"))
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Share")
                        }
                    }

                    // Send bundle button
                    if (lastLoginId.isNotEmpty() && lastClaimJson.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(16.dp))
                        GradientButton(
                            text = "Send Bundle to API",
                            colors = listOf(Color(0xFF10B981), Color(0xFF059669)),
                            onClick = {
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val bundle = JSONObject()
                                            .put("schema", "pl/bundle/1")
                                            .put("type", "ownership_claim_bundle")
                                            .put("did", did)
                                            .put("sig_alg", "ES256K")
                                            .put("pubkey_hex", did.removePrefix("did:btcr:"))
                                            .put("claim", JSONObject(lastClaimJson))
                                            .put("signature_der_hex", lastSigHex)
                                            .put("prp", JSONObject(lastPrpJson))

                                        val url = java.net.URL("https://api.beta.privacy-lion.com/v1/login/complete")
                                        val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
                                            requestMethod = "POST"
                                            connectTimeout = 8000
                                            readTimeout = 8000
                                            doOutput = true
                                            setRequestProperty("Content-Type", "application/json")
                                        }

                                        val payload = JSONObject()
                                            .put("login_id", lastLoginId)
                                            .put("did_sig", JSONObject()
                                                .put("did", did)
                                                .put("pubkey_hex", did.removePrefix("did:btcr:"))
                                                .put("message", lastClaimJson)
                                                .put("signature_hex", lastSigHex)
                                                .put("alg", "ES256K")
                                            )
                                            .put("bundle", bundle)
                                            .toString()

                                        conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }

                                        val code = conn.responseCode
                                        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
                                            .bufferedReader(Charsets.UTF_8).use { it.readText() }

                                        withContext(Dispatchers.Main) {
                                            statusMessage = "Sent! HTTP $code"
                                            Toast.makeText(context, "Bundle sent: HTTP $code", Toast.LENGTH_LONG).show()
                                        }
                                    } catch (e: Exception) {
                                        withContext(Dispatchers.Main) {
                                            statusMessage = "Send error: ${e.message}"
                                        }
                                    }
                                }
                            }
                        )
                    }
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

            // Reset button
            OutlinedButton(
                onClick = {
                    lastNonce = ""
                    lastLoginId = ""
                    lastPreimage = ""
                    lastClaimJson = ""
                    lastSigHex = ""
                    lastPrpJson = ""
                    lastInvoice = ""
                    lastPaymentHash = ""
                    vccResult = ""
                    vccId = ""
                    statusMessage = ""
                    step3Complete = false
                    showVccResult = false
                    // Reset enterprise login state
                    isEnterpriseLoginActive = false
                    isCreatingInvoice = false
                    isPollingPayment = false
                    paymentReceived = false
                    showInvoiceDialog = false
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Reset Session")
            }

            Spacer(modifier = Modifier.height(40.dp))
        }
    }

    // ===== DID Info Dialog =====
    if (showIdDialog) {
        DIDInfoDialog(
            did = did,
            onDismiss = { showIdDialog = false },
            onRegenerate = {
                did = didMgr.regenerateKeyPair()
                step1Complete = true
                step2Complete = false
                step3Complete = false
            },
            onCopy = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("DID", did))
                Toast.makeText(context, "Copied!", Toast.LENGTH_SHORT).show()
            }
        )
    }

    // ===== Wallet Info Dialog =====
    if (showWalletInfoDialog) {
        WalletInfoDialog(
            sparkAddress = walletSparkAddress,
            balanceSats = balanceSats,
            onDismiss = { showWalletInfoDialog = false },
            onCopySparkAddress = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Spark Address", walletSparkAddress))
                Toast.makeText(context, "Spark Address copied!", Toast.LENGTH_SHORT).show()
            }
        )
    }

    // ===== Invoice Dialog =====
    if (showInvoiceDialog && lastInvoice.isNotEmpty()) {
        InvoiceDialog(
            invoice = lastInvoice,
            amountSats = invoiceAmountSats.toLong(),
            isPolling = isPollingPayment,
            onDismiss = { showInvoiceDialog = false },
            onCopy = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Lightning Invoice", lastInvoice))
                Toast.makeText(context, "Invoice copied!", Toast.LENGTH_SHORT).show()
            },
            onShare = {
                val sendIntent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, lastInvoice)
                    type = "text/plain"
                }
                context.startActivity(Intent.createChooser(sendIntent, "Share Invoice"))
            }
        )
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
