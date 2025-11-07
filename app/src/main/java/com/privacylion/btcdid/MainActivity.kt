package com.privacylion.btcdid

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.privacylion.btcdid.ui.theme.BTC_DIDTheme
import org.json.JSONObject
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString

class MainActivity : ComponentActivity() {

    private fun hexToBytes(hex: String): ByteArray =
        hex.trim().chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun sha256HexBytes(hex: String): String {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val hash = md.digest(hexToBytes(hex))
        return hash.joinToString("") { "%02x".format(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val mgr = DidWalletManager(applicationContext)
        val activity = this

        setContent {
            BTC_DIDTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {

                    // ---- UI state ----
                    var stepCreateDone by remember { mutableStateOf(false) }
                    var stepConnectDone by remember { mutableStateOf(false) }
                    val clipboard = LocalClipboardManager.current
                    var lastNonce by remember { mutableStateOf("") }

                    var did by remember { mutableStateOf(mgr.getPublicDID() ?: "") }
                    if (did.isNotEmpty()) stepCreateDone = true

                    // After "Prove Ownership", we either show signature or error here:
                    var proveStatus by remember { mutableStateOf("") }
                    // will hold claim JSON and signature after prove
                    var lastClaimJson by remember { mutableStateOf("") }
                    var lastSigHex by remember { mutableStateOf("") }
                    var lastLoginId by remember { mutableStateOf("") }
                    var lastPreimage by remember { mutableStateOf("") }

                    // NEW: built PRP JSON
                    var lastPrpJson by remember { mutableStateOf("") }

                    // Diagnostics for Rust hashing demo:
                    var input by remember { mutableStateOf("test") }
                    var output by remember {
                        mutableStateOf(NativeBridge.sha256Hex("test"))
                    }

                    Column(Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState())) {

                        // ---- Header ----
                        Text(
                            "BTC_DID Android",
                            style = MaterialTheme.typography.titleLarge
                        )
                        Spacer(Modifier.height(12.dp))

                        Text(NativeBridge.helloFromRust())
                        Spacer(Modifier.height(4.dp))

                        // keystore health line from DidWalletManager
                        Text(
                            mgr.keystoreInfo(),
                            style = MaterialTheme.typography.bodySmall
                        )

                        Spacer(Modifier.height(16.dp))

                        // ===== Card 1: CREATE =====
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp)) {
                                Text(
                                    "1) Create",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Spacer(Modifier.height(8.dp))

                                // current DID text
                                Text(
                                    if (did.isEmpty()) "(no DID yet)"
                                    else did
                                )

                                Spacer(Modifier.height(8.dp))

                                Row {
                                    Button(onClick = {
                                        // Create a brand new DID (generate + wrap)
                                        proveStatus = "" // clear prove status
                                        did = mgr.createDid()
                                        stepCreateDone = true
                                    }) {
                                        Text("Create DID (hardware-wrapped)")
                                    }

                                    Spacer(Modifier.width(8.dp))

                                    Button(onClick = {
                                        // Re-read what's stored
                                        proveStatus = ""
                                        did = mgr.getPublicDID() ?: ""
                                        stepCreateDone = did.isNotEmpty()
                                    }) {
                                        Text("Show DID")
                                    }
                                }
                            }
                        }

                        Spacer(Modifier.height(12.dp))

                        // ===== Card 2: CONNECT =====
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp)) {
                                Text(
                                    "2) Connect",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Spacer(Modifier.height(8.dp))

                                Text(
                                    if (!stepCreateDone)
                                        "Select wallet (stub for now) — finish Create first"
                                    else
                                        "Select wallet (stub for now)"
                                )

                                Spacer(Modifier.height(8.dp))

                                Button(
                                    onClick = {
                                        if (stepCreateDone) {
                                            proveStatus = ""
                                            stepConnectDone = true
                                        }
                                    },
                                    enabled = stepCreateDone
                                ) {
                                    Text("Mark Connected")
                                }

                                Spacer(Modifier.height(8.dp))
                                Button(
                                    onClick = {
                                        proveStatus = "Fetching nonce..."
                                        Thread {
                                            try {
                                                val res = mgr.startLogin()
                                                activity.runOnUiThread {
                                                    lastLoginId = res.loginId
                                                    lastNonce = res.nonce
                                                    proveStatus = "Nonce ready."
                                                }
                                            } catch (t: Throwable) {
                                                activity.runOnUiThread {
                                                    proveStatus = "Nonce error: ${t.message}"
                                                }
                                            }
                                        }.start()
                                    },
                                    enabled = stepCreateDone
                                ) { Text("Fetch Nonce") }

                                Spacer(Modifier.height(8.dp))
                                Text(
                                    text = if (lastNonce.isEmpty()) "Nonce: (none)"
                                    else "Nonce: ${lastNonce}",
                                    style = MaterialTheme.typography.bodySmall
                                )

                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = if (lastLoginId.isEmpty()) "Login ID: (none)"
                                    else "Login ID: ${lastLoginId.take(24)}…",
                                    style = MaterialTheme.typography.bodySmall
                                )

                                Spacer(Modifier.height(8.dp))
                                Button(
                                    onClick = {
                                        if (lastLoginId.isEmpty()) {
                                            proveStatus = "No login_id yet — tap Fetch Nonce first."
                                            return@Button
                                        }
                                        clipboard.setText(AnnotatedString(lastLoginId))
                                        proveStatus = "Login ID copied."
                                    },
                                    enabled = lastLoginId.isNotEmpty()
                                ) { Text("Copy Login ID") }

                                Spacer(Modifier.height(8.dp))
                                Button(
                                    onClick = {
                                        if (lastLoginId.isBlank()) {
                                            proveStatus = "No login_id yet — tap Fetch Nonce first."
                                            return@Button
                                        }
                                        proveStatus = "Checking status..."
                                        Thread {
                                            try {
                                                val body = mgr.fetchLoginStatus(lastLoginId)
                                                runOnUiThread { proveStatus = "Status: $body" }
                                            } catch (t: Throwable) {
                                                runOnUiThread { proveStatus = "Status error: ${t.message}" }
                                            }
                                        }.start()
                                    },
                                    enabled = stepCreateDone
                                ) { Text("Check Status") }

                                Spacer(Modifier.height(8.dp))
                                Button(
                                    onClick = {
                                        if (lastLoginId.isBlank()) {
                                            proveStatus = "No login_id yet — tap Fetch Nonce first."
                                            return@Button
                                        }
                                        // make a random 32-byte hex preimage
                                        val bytes = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
                                        val preimage = bytes.joinToString("") { "%02x".format(it) }

                                        proveStatus = "Settling (demo)…"
                                        Thread {
                                            try {
                                                mgr.settleLoginDemo(lastLoginId, preimage)
                                                runOnUiThread {
                                                    lastPreimage = preimage
                                                    proveStatus = "Settled. Preimage saved."
                                                }
                                            } catch (t: Throwable) {
                                                runOnUiThread { proveStatus = "Settle error: ${t.message}" }
                                            }
                                        }.start()
                                    },
                                    enabled = stepCreateDone
                                ) { Text("Settle (demo)") }

                                Spacer(Modifier.height(8.dp))
                                Text(
                                    text = if (lastPreimage.isEmpty()) "Paid: false"
                                    else "Paid: true",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }

                        Spacer(Modifier.height(12.dp))

                        // ===== Card 3: PROVE =====
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp)) {
                                Text(
                                    "3) Prove",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Spacer(Modifier.height(8.dp))

                                val proveMessage = when {
                                    !stepCreateDone -> "Create a DID first"
                                    !stepConnectDone -> "Connect a wallet first"
                                    lastPreimage.isEmpty() -> "Awaiting payment (need preimage)"
                                    proveStatus.isEmpty() -> "Ready to build & sign claim"
                                    else -> proveStatus
                                }
                                Text(proveMessage)

                                Spacer(Modifier.height(8.dp))

                                Button(
                                    enabled = stepCreateDone && stepConnectDone && lastPreimage.isNotEmpty(),
                                    onClick = {
                                        val claimJson = mgr.buildOwnershipClaimJson(
                                            did = did,
                                            nonce = lastNonce.ifEmpty { "android-${System.currentTimeMillis()}" },
                                            walletType = "custodial",
                                            withdrawTo = "lnbc1mockpreimage",
                                            preimage = lastPreimage
                                        )

                                        val status = try {
                                            if (did.isEmpty()) {
                                                proveStatus = "Error: no DID available"
                                                return@Button
                                            }

                                            val sigHex = mgr.signOwnershipClaim(claimJson)

                                            // save for UI
                                            lastClaimJson = claimJson
                                            lastSigHex = sigHex

                                            "Success: claim signed"
                                        } catch (t: Throwable) {
                                            "Error during prove: ${t.message}"
                                        }

                                        proveStatus = status
                                    }
                                ) {
                                    Text("Prove Ownership (requires paid)")
                                }

                                Spacer(Modifier.height(12.dp))

                                Button(
                                    enabled = lastLoginId.isNotEmpty() && lastPreimage.isNotEmpty(),
                                    onClick = {
                                        try {
                                            val preimageSha256 = sha256HexBytes(lastPreimage)
                                            val prp = mgr.buildPrpJson(
                                                loginId = lastLoginId,
                                                did = did,
                                                preimageSha256Hex = preimageSha256,
                                                amountSats = 0L,          // demo
                                                userShare = 90,
                                                operatorShare = 10
                                            )
                                            lastPrpJson = prp
                                            proveStatus = "PRP ready."
                                        } catch (t: Throwable) {
                                            proveStatus = "PRP error: ${t.message}"
                                        }
                                    }
                                ) { Text("Build PRP (demo)") }

                                Spacer(Modifier.height(12.dp))

                                Button(
                                    enabled = lastClaimJson.isNotEmpty() && lastSigHex.isNotEmpty(),
                                    onClick = {
                                        try {
                                            val bundle = JSONObject()
                                                .put("schema", "pl/bundle/1")
                                                .put("type", "ownership_claim_bundle")
                                                .put("did", did)
                                                .put("sig_alg", "ES256K")
                                                .put("pubkey_hex", did.removePrefix("did:btcr:"))
                                                .put("claim", JSONObject(lastClaimJson))
                                                .put("signature_der_hex", lastSigHex)
                                            if (lastPrpJson.isNotEmpty()) {
                                                bundle.put("prp", JSONObject(lastPrpJson))
                                            }
                                            clipboard.setText(AnnotatedString(bundle.toString()))
                                            proveStatus = "Bundle copied."
                                        } catch (t: Throwable) {
                                            proveStatus = "Bundle error: ${t.message}"
                                        }
                                    }
                                ) { Text("Share bundle (demo)") }

                                Button(
                                    enabled = lastLoginId.isNotEmpty() && lastClaimJson.isNotEmpty() && lastSigHex.isNotEmpty(),
                                    onClick = {
                                        try {
                                            // Build the same bundle we copy to clipboard
                                            val bundle = JSONObject()
                                                .put("schema", "pl/bundle/1")
                                                .put("type", "ownership_claim_bundle")
                                                .put("did", did)
                                                .put("sig_alg", "ES256K")
                                                .put("pubkey_hex", did.removePrefix("did:btcr:"))
                                                .put("claim", JSONObject(lastClaimJson))
                                                .put("signature_der_hex", lastSigHex)
                                            if (lastPrpJson.isNotEmpty()) {
                                                bundle.put("prp", JSONObject(lastPrpJson))
                                            }

                                            proveStatus = "Sending bundle…"
                                            Thread {
                                                try {
                                                    val url = java.net.URL("https://api.beta.privacy-lion.com/v1/login/complete")
                                                    val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
                                                        requestMethod = "POST"
                                                        connectTimeout = 8000
                                                        readTimeout = 8000
                                                        doOutput = true
                                                        setRequestProperty("Content-Type", "application/json")
                                                        setRequestProperty("Accept", "application/json")
                                                    }

                                                    // Wrap with login_id for the API
                                                    val payload = JSONObject()
                                                        .put("login_id", lastLoginId)
                                                        .put("bundle", bundle)
                                                        .toString()

                                                    conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }

                                                    val code = conn.responseCode
                                                    val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
                                                        .bufferedReader(Charsets.UTF_8).use { it.readText() }

                                                    runOnUiThread {
                                                        proveStatus = "Complete: HTTP $code\n$body"
                                                    }
                                                } catch (t: Throwable) {
                                                    runOnUiThread { proveStatus = "Complete error: ${t.message}" }
                                                }
                                            }.start()
                                        } catch (t: Throwable) {
                                            proveStatus = "Bundle build error: ${t.message}"
                                        }
                                    }
                                ) { Text("Send bundle (demo)") }

                                Spacer(Modifier.height(12.dp))

                                if (lastClaimJson.isNotEmpty() && lastSigHex.isNotEmpty()) {
                                    Text(
                                        "Claim JSON:",
                                        style = MaterialTheme.typography.labelMedium
                                    )
                                    Text(
                                        lastClaimJson,
                                        style = MaterialTheme.typography.bodySmall
                                    )

                                    Spacer(Modifier.height(8.dp))

                                    Text(
                                        "Signature (DER hex):",
                                        style = MaterialTheme.typography.labelMedium
                                    )
                                    Text(
                                        lastSigHex,
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }

                                if (lastPrpJson.isNotEmpty()) {
                                    Spacer(Modifier.height(12.dp))
                                    Text(
                                        "PRP JSON:",
                                        style = MaterialTheme.typography.labelMedium
                                    )
                                    Text(
                                        lastPrpJson,
                                        style = MaterialTheme.typography.bodySmall
                                    )

                                    Spacer(Modifier.height(8.dp))
                                    Button(onClick = {
                                        clipboard.setText(AnnotatedString(lastPrpJson))
                                        proveStatus = "PRP copied."
                                    }) {
                                        Text("Copy PRP JSON")
                                    }
                                }
                            }
                        }

                        Spacer(Modifier.height(24.dp))

                        // ===== Rust hashing demo =====
                        OutlinedTextField(
                            value = input,
                            onValueChange = { input = it },
                            label = { Text("Input to hash") },
                            modifier = Modifier.fillMaxWidth()
                        )

                        Spacer(Modifier.height(8.dp))

                        Button(onClick = {
                            // dummy inputs just to exercise the JNI stub
                            val resp = mgr.generateStwoProof(
                                "sha256_eq",
                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            )

                            output = resp
                        }) {
                            Text("Run STWO proof demo")
                        }

                        Spacer(Modifier.height(8.dp))

                        Button(onClick = {
                            val outcome = "paid=true"
                            val payoutsJson = """{"user":90,"operator":10}"""
                            val oracleJson = """{"name":"local_oracle","pubkey":"deadbeef"}"""
                            val resp = mgr.createDlcContract(outcome, payoutsJson, oracleJson)
                            output = resp
                        }) {
                            Text("Create DLC (demo)")
                        }

                        Spacer(Modifier.height(8.dp))

                        Button(onClick = {
                            val outcome = "paid=true"
                            val resp = mgr.signDlcOutcome(outcome)
                            output = resp
                        }) {
                            Text("Sign DLC (demo)")
                        }
                    }
                }
            }
        }
    }
}
