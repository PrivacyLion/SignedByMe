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
import androidx.compose.ui.res.painterResource
import com.privacylion.btcdid.ui.theme.BTC_DIDTheme
import kotlinx.coroutines.*
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val mgr = DidWalletManager(applicationContext)

        setContent {
            BTC_DIDTheme {
                SignedByMeApp(mgr)
            }
        }
    }
}

@Composable
fun SignedByMeApp(mgr: DidWalletManager) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // ===== State =====
    var did by remember { mutableStateOf(mgr.getPublicDID() ?: "") }
    var step1Complete by remember { mutableStateOf(did.isNotEmpty()) }
    var step2Complete by remember { mutableStateOf(false) }
    var step3Complete by remember { mutableStateOf(false) }

    // Connect step state
    var selectedWalletType by remember { mutableStateOf<String?>(null) }
    var withdrawAddress by remember { mutableStateOf("") }

    // Login/API state
    var lastNonce by remember { mutableStateOf("") }
    var lastLoginId by remember { mutableStateOf("") }
    var lastPreimage by remember { mutableStateOf("") }
    var lastClaimJson by remember { mutableStateOf("") }
    var lastSigHex by remember { mutableStateOf("") }
    var lastPrpJson by remember { mutableStateOf("") }

    // UI state
    var statusMessage by remember { mutableStateOf("") }
    var showIdDialog by remember { mutableStateOf(false) }
    var showVccResult by remember { mutableStateOf(false) }
    var vccResult by remember { mutableStateOf("") }
    var paymentResult by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    
    // Wallet connection dialogs
    var showSeedPhraseDialog by remember { mutableStateOf(false) }
    var showCustodialDialog by remember { mutableStateOf(false) }
    var selectedCustodialProvider by remember { mutableStateOf<String?>(null) }
    var showQRScanner by remember { mutableStateOf(false) }

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
                            did = mgr.createDid()
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

            // ===== Step 2: Connect =====
            StepCard(
                stepNumber = 2,
                title = "Connect",
                isComplete = step2Complete,
                isEnabled = step1Complete
            ) {
                if (!step2Complete) {
                    Text(
                        "Pick an option to Connect",
                        fontSize = 16.sp,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    // Start over chip
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        StartOverChip {
                            selectedWalletType = null
                            withdrawAddress = ""
                            lastNonce = ""
                            lastLoginId = ""
                            lastPreimage = ""
                            step2Complete = false
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // Cash App option
                    CashAppCard(
                        withdrawAddress = withdrawAddress,
                        onAddressChange = { withdrawAddress = it },
                        onPaste = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = clipboard.primaryClip?.getItemAt(0)?.text?.toString() ?: ""
                            if (clip.isNotEmpty()) {
                                withdrawAddress = clip
                                selectedWalletType = "cashapp"
                            }
                        },
                        onScanQR = {
                            showQRScanner = true
                        }
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    // Custodial Wallet button
                    GradientButton(
                        text = "Custodial Wallet",
                        pillText = "intermediate",
                        colors = listOf(Color(0xFF3B82F6), Color(0xFF8B5CF6)),
                        onClick = {
                            showCustodialDialog = true
                        }
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    // Non-Custodial Wallet button
                    GradientButton(
                        text = "Non-Custodial Wallet",
                        pillText = "advanced",
                        colors = listOf(Color(0xFF6366F1), Color(0xFF8B5CF6)),
                        onClick = {
                            showSeedPhraseDialog = true
                        }
                    )

                    // Connect via API button (after selecting wallet type)
                    if (selectedWalletType != null && withdrawAddress.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(16.dp))
                        GradientButton(
                            text = "Connect & Fetch Nonce",
                            colors = listOf(Color(0xFF10B981), Color(0xFF059669)),
                            onClick = {
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        val res = mgr.startLogin()
                                        withContext(Dispatchers.Main) {
                                            lastLoginId = res.loginId
                                            lastNonce = res.nonce
                                            step2Complete = true
                                            statusMessage = "Connected! Nonce received."
                                        }
                                    } catch (e: Exception) {
                                        withContext(Dispatchers.Main) {
                                            statusMessage = "Error: ${e.message}"
                                        }
                                    }
                                }
                            }
                        )
                    }
                } else {
                    // Connected state
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        StartOverChip {
                            selectedWalletType = null
                            withdrawAddress = ""
                            lastNonce = ""
                            lastLoginId = ""
                            lastPreimage = ""
                            step2Complete = false
                            step3Complete = false
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    CompletedStepContent(
                        message = "Wallet: ${selectedWalletType ?: "Connected"}\n${if (withdrawAddress.isNotEmpty()) withdrawAddress.take(20) + "..." else ""}",
                        onInfoClick = null
                    )

                    // Show login ID if we have one
                    if (lastLoginId.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "Login ID: ${lastLoginId.take(16)}...",
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color.Gray
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        // Settle (demo) button
                        if (lastPreimage.isEmpty()) {
                            OutlinedButton(
                                onClick = {
                                    scope.launch(Dispatchers.IO) {
                                        try {
                                            val bytes = ByteArray(32)
                                            java.security.SecureRandom().nextBytes(bytes)
                                            val preimage = bytes.joinToString("") { "%02x".format(it) }
                                            mgr.settleLoginDemo(lastLoginId, preimage)
                                            withContext(Dispatchers.Main) {
                                                lastPreimage = preimage
                                                statusMessage = "Payment settled (demo)"
                                            }
                                        } catch (e: Exception) {
                                            withContext(Dispatchers.Main) {
                                                statusMessage = "Settle error: ${e.message}"
                                            }
                                        }
                                    }
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Settle Payment (demo)")
                            }
                        } else {
                            StatusPill("Payment Settled", Color(0xFF10B981))
                        }
                    }
                }
            }

            // ===== Step 3: Prove =====
            StepCard(
                stepNumber = 3,
                title = "Prove",
                isComplete = step3Complete,
                isEnabled = step1Complete && step2Complete
            ) {
                Text(
                    "Press the button below to Prove your Signature and create your Verified Content Claim",
                    fontSize = 14.sp,
                    color = Color.Gray,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(16.dp))

                GradientButton(
                    text = "Generate Proof",
                    colors = listOf(Color(0xFFEF4444), Color(0xFFF97316)),
                    enabled = lastPreimage.isNotEmpty() || selectedWalletType != null,
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
                                val claimJson = mgr.buildOwnershipClaimJson(
                                    did = did,
                                    nonce = lastNonce.ifEmpty { "android-${System.currentTimeMillis()}" },
                                    walletType = selectedWalletType ?: "custodial",
                                    withdrawTo = withdrawAddress.ifEmpty { "lnbc1demo" },
                                    preimage = preimage
                                )

                                // Sign the claim
                                val sigHex = mgr.signOwnershipClaim(claimJson)

                                // Derive preimage_sha256
                                val preBytes = preimage.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                val md = java.security.MessageDigest.getInstance("SHA-256")
                                val preShaHex = md.digest(preBytes).joinToString("") { "%02x".format(it) }

                                // Build PRP
                                val prpJson = mgr.buildPrpJson(
                                    loginId = lastLoginId.ifEmpty { "android-${System.currentTimeMillis()}" },
                                    did = did,
                                    preimageSha256Hex = preShaHex
                                )

                                // Generate VCC (mock for now)
                                val vcc = JSONObject().apply {
                                    put("created_by", did)
                                    put("content_hash", "sha256_demo_${System.currentTimeMillis()}")
                                    put("ln_address", withdrawAddress.ifEmpty { "demo@wallet.com" })
                                    put("timestamp", System.currentTimeMillis())
                                }.toString()

                                // Mock payment result
                                val payment = JSONObject().apply {
                                    put("to", withdrawAddress.ifEmpty { "demo@wallet.com" })
                                    put("amount_sats", 100)
                                    put("preimage", preimage.take(16) + "...")
                                    put("status", "completed")
                                }.toString()

                                withContext(Dispatchers.Main) {
                                    lastClaimJson = claimJson
                                    lastSigHex = sigHex
                                    lastPrpJson = prpJson
                                    vccResult = vcc
                                    paymentResult = payment
                                    step3Complete = true
                                    showVccResult = true
                                    isLoading = false
                                    statusMessage = "Proof generated!"
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
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    )
                }

                // Show VCC result
                if (showVccResult && vccResult.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(16.dp))

                    // VCC Card
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

                    // Payment status
                    if (paymentResult.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(16.dp))
                        StatusPill("Payment Completed", Color(0xFF10B981))
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
                    vccResult = ""
                    paymentResult = ""
                    statusMessage = ""
                    step2Complete = false
                    step3Complete = false
                    showVccResult = false
                    selectedWalletType = null
                    withdrawAddress = ""
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
                did = mgr.regenerateKeyPair()
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
    
    // ===== Seed Phrase Entry Dialog =====
    if (showSeedPhraseDialog) {
        SeedPhraseEntryDialog(
            onDismiss = { showSeedPhraseDialog = false },
            onConfirm = { seedPhrase, passphrase ->
                scope.launch(Dispatchers.IO) {
                    try {
                        // Derive keys from seed phrase
                        val derivedAddress = mgr.deriveFromSeedPhrase(seedPhrase, passphrase)
                        withContext(Dispatchers.Main) {
                            withdrawAddress = derivedAddress
                            selectedWalletType = "non-custodial"
                            step2Complete = true
                            showSeedPhraseDialog = false
                            statusMessage = "Wallet connected via seed phrase"
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) {
                            statusMessage = "Error: ${e.message}"
                        }
                    }
                }
            }
        )
    }
    
    // ===== Custodial Wallet Selection Dialog =====
    if (showCustodialDialog) {
        CustodialWalletDialog(
            onDismiss = { showCustodialDialog = false },
            onSelect = { provider, address ->
                withdrawAddress = address
                selectedWalletType = "custodial"
                selectedCustodialProvider = provider
                step2Complete = true
                showCustodialDialog = false
                statusMessage = "Connected to $provider"
            }
        )
    }
    
    // ===== QR Scanner Dialog =====
    if (showQRScanner) {
        QRScannerDialog(
            onDismiss = { showQRScanner = false },
            onScanned = { scannedValue ->
                // Parse Bitcoin/Lightning address from QR
                val address = parseBitcoinAddress(scannedValue)
                withdrawAddress = address
                selectedWalletType = "cashapp"
                showQRScanner = false
                Toast.makeText(context, "Address scanned!", Toast.LENGTH_SHORT).show()
            }
        )
    }
}

/**
 * Parse a Bitcoin or Lightning address from a QR code value.
 * Handles formats like:
 * - bitcoin:bc1q...
 * - lightning:lnbc...
 * - Plain addresses
 */
private fun parseBitcoinAddress(raw: String): String {
    val trimmed = raw.trim()
    return when {
        trimmed.startsWith("bitcoin:", ignoreCase = true) -> {
            // bitcoin:address?amount=...
            val withoutScheme = trimmed.removePrefix("bitcoin:").removePrefix("BITCOIN:")
            withoutScheme.split("?").firstOrNull() ?: withoutScheme
        }
        trimmed.startsWith("lightning:", ignoreCase = true) -> {
            trimmed.removePrefix("lightning:").removePrefix("LIGHTNING:")
        }
        trimmed.startsWith("lnurl", ignoreCase = true) -> trimmed
        trimmed.startsWith("lnbc", ignoreCase = true) -> trimmed
        trimmed.startsWith("bc1", ignoreCase = true) -> trimmed
        trimmed.startsWith("1") || trimmed.startsWith("3") -> trimmed // Legacy BTC addresses
        else -> trimmed
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
    enabled: Boolean = true,
    pillText: String? = null
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
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    text = text,
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold
                )
                if (pillText != null) {
                    Spacer(modifier = Modifier.width(8.dp))
                    LevelPill(pillText, Color(0xFF10B981))
                }
            }
        }
    }
}

@Composable
fun LevelPill(text: String, color: Color) {
    Text(
        text = text,
        fontSize = 12.sp,
        fontWeight = FontWeight.SemiBold,
        color = color,
        modifier = Modifier
            .background(color.copy(alpha = 0.15f), RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp)
    )
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
fun StartOverChip(onClick: () -> Unit) {
    TextButton(onClick = onClick) {
        Box(
            modifier = Modifier
                .size(22.dp)
                .clip(CircleShape)
                .background(Color(0xFF10B981).copy(alpha = 0.12f))
                .border(1.dp, Color(0xFF10B981).copy(alpha = 0.45f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Default.Refresh,
                contentDescription = null,
                tint = Color(0xFF10B981),
                modifier = Modifier.size(14.dp)
            )
        }
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            "Start over",
            color = Color(0xFF10B981),
            fontSize = 14.sp,
            fontWeight = FontWeight.SemiBold
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
fun CashAppCard(
    withdrawAddress: String,
    onAddressChange: (String) -> Unit,
    onPaste: () -> Unit,
    onScanQR: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.6f))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("⚡", fontSize = 24.sp)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Cash App", fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                Spacer(modifier = Modifier.width(8.dp))
                LevelPill("easy", Color(0xFF10B981))
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                "Open Cash App → Bitcoin → Deposit → show QR. Scan it or paste the address.",
                fontSize = 12.sp,
                color = Color.Gray
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = onScanQR,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3B82F6))
                ) {
                    Text("📷 Scan QR")
                }

                OutlinedButton(
                    onClick = onPaste,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("📋 Paste")
                }
            }

            if (withdrawAddress.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = withdrawAddress,
                    onValueChange = onAddressChange,
                    label = { Text("Withdraw To") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
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

                // QR Code placeholder (simple text representation for now)
                Box(
                    modifier = Modifier
                        .size(200.dp)
                        .background(Color.White, RoundedCornerShape(8.dp))
                        .border(1.dp, Color.Gray, RoundedCornerShape(8.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    // Simple visual representation
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("📱", fontSize = 48.sp)
                        Text("QR Code", fontSize = 12.sp, color = Color.Gray)
                        Text(did.take(8) + "...", fontSize = 10.sp, color = Color.Gray)
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
fun SeedPhraseEntryDialog(
    onDismiss: () -> Unit,
    onConfirm: (seedPhrase: String, passphrase: String) -> Unit
) {
    var wordCount by remember { mutableStateOf(12) }
    var seedWords by remember { mutableStateOf(List(12) { "" }) }
    var passphrase by remember { mutableStateOf("") }
    var showPassphrase by remember { mutableStateOf(false) }
    var validationError by remember { mutableStateOf<String?>(null) }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.9f)
                .padding(8.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier
                    .padding(20.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    "Enter Seed Phrase",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    "Enter your 12 or 24 word recovery phrase",
                    fontSize = 14.sp,
                    color = Color.Gray,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Word count selector
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    FilterChip(
                        selected = wordCount == 12,
                        onClick = { 
                            wordCount = 12
                            seedWords = List(12) { if (it < seedWords.size) seedWords[it] else "" }
                        },
                        label = { Text("12 Words") }
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    FilterChip(
                        selected = wordCount == 24,
                        onClick = { 
                            wordCount = 24
                            seedWords = List(24) { if (it < seedWords.size) seedWords[it] else "" }
                        },
                        label = { Text("24 Words") }
                    )
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Word input grid (2 columns)
                for (row in 0 until (wordCount / 2)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        // Left column
                        val leftIdx = row
                        OutlinedTextField(
                            value = seedWords[leftIdx],
                            onValueChange = { newVal ->
                                seedWords = seedWords.toMutableList().also { 
                                    it[leftIdx] = newVal.lowercase().trim() 
                                }
                                validationError = null
                            },
                            label = { Text("${leftIdx + 1}") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            textStyle = LocalTextStyle.current.copy(fontSize = 14.sp)
                        )
                        
                        // Right column
                        val rightIdx = row + (wordCount / 2)
                        OutlinedTextField(
                            value = seedWords[rightIdx],
                            onValueChange = { newVal ->
                                seedWords = seedWords.toMutableList().also { 
                                    it[rightIdx] = newVal.lowercase().trim() 
                                }
                                validationError = null
                            },
                            label = { Text("${rightIdx + 1}") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            textStyle = LocalTextStyle.current.copy(fontSize = 14.sp)
                        )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Passphrase (optional)
                Text(
                    "Passphrase (optional)",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium
                )
                Spacer(modifier = Modifier.height(4.dp))
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("BIP39 Passphrase") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = if (showPassphrase) 
                        androidx.compose.ui.text.input.VisualTransformation.None 
                    else 
                        androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    trailingIcon = {
                        TextButton(onClick = { showPassphrase = !showPassphrase }) {
                            Text(if (showPassphrase) "Hide" else "Show", fontSize = 12.sp)
                        }
                    }
                )
                
                // Validation error
                if (validationError != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        validationError!!,
                        color = Color(0xFFEF4444),
                        fontSize = 12.sp
                    )
                }
                
                Spacer(modifier = Modifier.height(20.dp))
                
                // Action buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Cancel")
                    }
                    
                    Button(
                        onClick = {
                            // Validate all words are filled
                            val emptyWords = seedWords.filter { it.isBlank() }
                            if (emptyWords.isNotEmpty()) {
                                validationError = "Please fill in all ${wordCount} words"
                                return@Button
                            }
                            
                            // Join words and confirm
                            val phrase = seedWords.joinToString(" ")
                            onConfirm(phrase, passphrase)
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF10B981)
                        )
                    ) {
                        Text("Connect Wallet")
                    }
                }
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Security warning
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFFFEF3C7)
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Text("⚠️", fontSize = 16.sp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "Your seed phrase is stored securely on this device only. Never share it with anyone.",
                            fontSize = 12.sp,
                            color = Color(0xFF92400E)
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun CustodialWalletDialog(
    onDismiss: () -> Unit,
    onSelect: (provider: String, address: String) -> Unit
) {
    var selectedProvider by remember { mutableStateOf<String?>(null) }
    var lightningAddress by remember { mutableStateOf("") }
    
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            Column(
                modifier = Modifier.padding(24.dp)
            ) {
                Text(
                    "Connect Custodial Wallet",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    "Select your wallet provider",
                    fontSize = 14.sp,
                    color = Color.Gray,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(20.dp))
                
                // Wallet provider buttons
                WalletProviderButton(
                    name = "Strike",
                    iconResId = R.drawable.ic_strike,
                    description = "Lightning-native payments",
                    isSelected = selectedProvider == "Strike",
                    onClick = { selectedProvider = "Strike" }
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                WalletProviderButton(
                    name = "River",
                    iconResId = R.drawable.ic_river,
                    description = "Bitcoin brokerage with Lightning",
                    isSelected = selectedProvider == "River",
                    onClick = { selectedProvider = "River" }
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                WalletProviderButton(
                    name = "Coinbase",
                    iconResId = R.drawable.ic_coinbase,
                    description = "Popular crypto exchange",
                    isSelected = selectedProvider == "Coinbase",
                    onClick = { selectedProvider = "Coinbase" }
                )
                
                // Lightning address input (shown after provider selection)
                if (selectedProvider != null) {
                    Spacer(modifier = Modifier.height(20.dp))
                    
                    Text(
                        "Enter your $selectedProvider Lightning Address",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Medium
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    OutlinedTextField(
                        value = lightningAddress,
                        onValueChange = { lightningAddress = it },
                        label = { Text("Lightning Address") },
                        placeholder = { Text("you@${selectedProvider?.lowercase()}.com") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
                
                Spacer(modifier = Modifier.height(24.dp))
                
                // Action buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Cancel")
                    }
                    
                    Button(
                        onClick = {
                            if (selectedProvider != null && lightningAddress.isNotBlank()) {
                                onSelect(selectedProvider!!, lightningAddress)
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = selectedProvider != null && lightningAddress.isNotBlank(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF3B82F6)
                        )
                    ) {
                        Text("Connect")
                    }
                }
            }
        }
    }
}

@Composable
fun WalletProviderButton(
    name: String,
    iconResId: Int,
    description: String,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    val borderColor = if (isSelected) Color(0xFF3B82F6) else Color.Gray.copy(alpha = 0.3f)
    val bgColor = if (isSelected) Color(0xFF3B82F6).copy(alpha = 0.1f) else Color.Transparent
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .border(
                width = if (isSelected) 2.dp else 1.dp,
                color = borderColor,
                shape = RoundedCornerShape(12.dp)
            ),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = bgColor)
    ) {
        Row(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Image(
                painter = painterResource(id = iconResId),
                contentDescription = name,
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    name,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    description,
                    fontSize = 12.sp,
                    color = Color.Gray
                )
            }
            if (isSelected) {
                Icon(
                    Icons.Default.Check,
                    contentDescription = null,
                    tint = Color(0xFF3B82F6)
                )
            }
        }
    }
}
