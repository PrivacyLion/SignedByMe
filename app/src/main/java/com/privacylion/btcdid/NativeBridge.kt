// File: app/src/main/java/com/privacylion/btcdid/NativeBridge.kt
package com.privacylion.btcdid

object NativeBridge {
    init {
        System.loadLibrary("btcdid_core")
    }

    // ============================================================================
    // Basic Functions
    // ============================================================================
    
    @JvmStatic external fun helloFromRust(): String
    @JvmStatic external fun sha256Hex(input: String): String

    // ============================================================================
    // Key Management (secp256k1)
    // ============================================================================
    
    /** Generate a random 32-byte secp256k1 private key */
    @JvmStatic external fun generateSecp256k1PrivateKey(): ByteArray
    
    /** Derive compressed public key hex (33 bytes) from private key */
    @JvmStatic external fun derivePublicKeyHex(priv: ByteArray): String
    
    /** Get x-only public key hex (32 bytes) for Taproot/Schnorr */
    @JvmStatic external fun getXOnlyPubkey(priv: ByteArray): String
    
    /** Sign message with ECDSA (returns DER hex signature) */
    @JvmStatic external fun signMessageDerHex(priv: ByteArray, message: String): String
    
    /** Sign message with Schnorr (returns 64-byte signature hex) */
    @JvmStatic external fun signSchnorr(priv: ByteArray, message: String): String

    // ============================================================================
    // STWO Prover (Zero-Knowledge Proofs)
    // ============================================================================
    
    /**
     * Generate a STWO proof for the specified circuit type.
     * 
     * Circuit types:
     * - "hash_integrity" / "HashIntegrity" - Prove input/output hash equality
     * - "content_transform" / "ContentTransform" - Prove media transformation
     * - "login_proof" / "LoginProof" - Prove login without relay
     * - "signature_validation" / "SignatureValidation" - Prove signature validity
     * - "payment_trigger_hash" / "PaymentTriggerHash" - Prove payment trigger
     * 
     * @param circuit The circuit type
     * @param inputHashHex Input hash (64 hex chars)
     * @param outputHashHex Output hash (64 hex chars)
     * @return JSON string with proof data
     */
    @JvmStatic external fun generateStwoProof(
        circuit: String, 
        inputHashHex: String, 
        outputHashHex: String
    ): String
    
    /**
     * Generate an Identity Proof binding DID to wallet ownership.
     * This is the core STWO proof for SignedByMe - generated in Step 3.
     * 
     * Proves (in zero knowledge):
     * 1. User controls the DID (knows private key)
     * 2. User controls the wallet (signed challenge)
     * 3. Binding is fresh (timestamp + expiry)
     * 
     * @param didPubkey The DID public key (hex)
     * @param walletAddress The wallet address (e.g., Spark address)
     * @param walletSignature Signature over a challenge proving wallet ownership
     * @param expiryDays How many days until the proof expires (default: 30)
     * @return JSON string with the identity proof
     */
    @JvmStatic external fun generateIdentityProof(
        didPubkey: String,
        walletAddress: String,
        walletSignature: String,
        expiryDays: Long
    ): String
    
    /**
     * Verify an Identity Proof is valid and not expired.
     * 
     * @param proofJson The proof JSON to verify
     * @return JSON with {valid: boolean, did_pubkey, wallet_address, expires_at, error?}
     */
    @JvmStatic external fun verifyIdentityProof(proofJson: String): String

    // ============================================================================
    // DLC (Discreet Log Contracts)
    // ============================================================================
    
    /**
     * Get the oracle's public key (x-only, 32 bytes hex)
     */
    @JvmStatic external fun oraclePubkeyHex(): String
    
    /**
     * Sign an outcome as the oracle (Schnorr signature)
     * @param outcome The outcome string (e.g., "paid=true", "refund=true")
     * @return JSON string with signature and attestation data
     */
    @JvmStatic external fun oracleSignOutcome(outcome: String): String
    
    /**
     * Create a DLC contract
     * @param outcome Expected outcome
     * @param payoutsJson JSON string with payout split {"user_pct": 90, "operator_pct": 10}
     * @param oracleJson JSON string with oracle info {"name": "...", "pubkey_hex": "..."}
     * @return JSON string with contract details
     */
    @JvmStatic external fun createDlcContract(
        outcome: String, 
        payoutsJson: String, 
        oracleJson: String
    ): String
    
    /**
     * Sign a DLC outcome
     * @param outcome The outcome to sign
     * @return JSON string with signature
     */
    @JvmStatic external fun signDlcOutcome(outcome: String): String

    // ============================================================================
    // Lightning Payments
    // ============================================================================
    
    /**
     * Generate a new preimage and payment hash
     * @return JSON string with preimage_hex and payment_hash
     */
    @JvmStatic external fun generatePreimage(): String
    
    /**
     * Verify a payment by checking preimage against payment hash
     * @param paymentHash The expected payment hash (64 hex chars)
     * @param preimageHex The preimage to verify (64 hex chars)
     * @return JSON string with verification result
     */
    @JvmStatic external fun verifyPayment(paymentHash: String, preimageHex: String): String
    
    /**
     * Create a Payment Request Package (PRP) for DLC-tagged payments
     * @param amountSats Amount in satoshis
     * @param description Payment description
     * @param payeeDid DID of the payee
     * @param payeeLnAddress Lightning address of the payee
     * @param expirySecs Expiry time in seconds
     * @return JSON string with PRP data and preimage
     */
    @JvmStatic external fun createPrp(
        amountSats: Long,
        description: String,
        payeeDid: String,
        payeeLnAddress: String,
        expirySecs: Long
    ): String
}
