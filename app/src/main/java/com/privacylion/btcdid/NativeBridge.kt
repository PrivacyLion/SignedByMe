// File: app/src/main/java/com/privacylion/btcdid/NativeBridge.kt
package com.privacylion.btcdid

object NativeBridge {
    init {
        System.loadLibrary("btcdid_core")
    }

    @JvmStatic external fun helloFromRust(): String
    @JvmStatic external fun sha256Hex(input: String): String

    // secp256k1 JNI
    @JvmStatic external fun generateSecp256k1PrivateKey(): ByteArray   // 32 bytes
    @JvmStatic external fun derivePublicKeyHex(priv: ByteArray): String // compressed SEC1 hex
    @JvmStatic external fun signMessageDerHex(priv: ByteArray, message: String): String // DER-hex signature

    // --- STWO / DLC placeholders (Rust side will provide these later) ---
    @JvmStatic external fun generateStwoProof(circuit: String, inputHashHex: String, outputHashHex: String): String
    external fun createDlcContract(outcome: String, payoutsJson: String, oracleJson: String): String
    external fun signDlcOutcome(outcome: String): String

}
