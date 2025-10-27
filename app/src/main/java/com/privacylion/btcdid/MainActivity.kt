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

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val mgr = DidWalletManager(applicationContext)

        setContent {
            BTC_DIDTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {

                    // ---- UI state ----
                    var stepCreateDone by remember { mutableStateOf(false) }
                    var stepConnectDone by remember { mutableStateOf(false) }

                    var did by remember { mutableStateOf(mgr.getPublicDID() ?: "") }
                    if (did.isNotEmpty()) stepCreateDone = true

                    // After "Prove Ownership", we either show signature or error here:
                    var proveStatus by remember { mutableStateOf("") }

                    // Diagnostics for Rust hashing demo:
                    var input by remember { mutableStateOf("test") }
                    var output by remember {
                        mutableStateOf(NativeBridge.sha256Hex("test"))
                    }

                    Column(Modifier.padding(20.dp)) {

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
                                    !stepCreateDone -> "Connect a wallet first"
                                    !stepConnectDone -> "Connect a wallet first"
                                    proveStatus.isEmpty() -> "Ready to build & sign claim"
                                    else -> proveStatus
                                }
                                Text(proveMessage)

                                Spacer(Modifier.height(8.dp))

                                Button(
                                    enabled = stepCreateDone && stepConnectDone,
                                    onClick = {
                                        // We'll construct a mock claim and try to sign it.
                                        // Any failure: catch and store error in proveStatus instead of crashing the app.
                                        val claimJson =
                                            """{"wallet_type":"mock","paid":true}"""

                                        val status = try {
                                            val wrapped = mgr.loadWrapped()
                                                ?: return@Button run {
                                                    proveStatus = "Error: no wrapped key saved"
                                                }

                                            // Could throw if unwrap fails
                                            val priv = mgr.unwrapPrivateKey(wrapped)

                                            // Could throw if JNI mismatches
                                            val sigHex = NativeBridge.signMessageDerHex(
                                                priv,
                                                claimJson
                                            )

                                            // wipe plaintext key asap
                                            java.util.Arrays.fill(priv, 0)

                                            "Signature (DER hex): $sigHex"
                                        } catch (t: Throwable) {
                                            "Error during prove: ${t.message}"
                                        }

                                        proveStatus = status
                                    }
                                ) {
                                    Text("Prove Ownership (stub)")
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
                            output = NativeBridge.sha256Hex(input)
                        }) {
                            Text("Hash with Rust")
                        }

                        Spacer(Modifier.height(8.dp))
                        Text(output)
                    }
                }
            }
        }
    }
}
