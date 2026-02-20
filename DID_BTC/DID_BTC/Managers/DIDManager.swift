// DIDManager.swift - DID and STWO Proof Management
// SignedByMe iOS - Mirrors Android DidWalletManager.kt

import Foundation
import CryptoKit

/// Manages DID (Decentralized Identifier) creation, storage, and STWO proofs.
/// This is the core identity manager for SignedByMe.
@MainActor
final class DIDManager: ObservableObject {
    
    // MARK: - Published Properties
    
    @Published private(set) var publicDID: String?
    @Published private(set) var isLoading = false
    @Published private(set) var stwoProofGenerated = false
    @Published private(set) var membershipEnrolled = false
    @Published private(set) var witnessLoaded = false
    
    // MARK: - Private Properties
    
    private let keychain = KeychainManager.shared
    private var cachedPrivateKey: Data?
    
    // MARK: - Constants
    
    private let didPrefix = "did:btcr:"
    private let proofExpiryDays: Int64 = 30
    
    // MARK: - Initialization
    
    init() {
        Task {
            await loadExistingIdentity()
        }
    }
    
    // MARK: - DID Management
    
    /// Create a new DID (generates secp256k1 keypair)
    func createDID() async throws -> String {
        isLoading = true
        defer { isLoading = false }
        
        // Generate secp256k1 private key using Rust
        let privateKey = NativeBridge.generateSecp256k1PrivateKey()
        guard privateKey.count == 32 else {
            throw DIDError.keyGenerationFailed
        }
        
        // Derive public key
        let publicKeyHex = NativeBridge.derivePublicKeyHex(privateKey)
        guard !publicKeyHex.starts(with: "error") else {
            throw DIDError.keyDerivationFailed
        }
        
        // Store private key in Keychain
        try keychain.save(privateKey, for: .didPrivateKey, requireBiometric: false)
        
        // Store public key for quick access
        try keychain.save(publicKeyHex, for: .didPublicKey)
        
        // Create DID string
        let did = "\(didPrefix)\(publicKeyHex)"
        
        // Update state
        publicDID = did
        cachedPrivateKey = privateKey
        
        print("✅ Created DID: \(did.prefix(30))...")
        return did
    }
    
    /// Get existing public DID (loads from Keychain if needed)
    func getPublicDID() async throws -> String? {
        if let cached = publicDID {
            return cached
        }
        
        // Try to load from Keychain
        guard let publicKeyHex = try? keychain.loadString(.didPublicKey) else {
            return nil
        }
        
        let did = "\(didPrefix)\(publicKeyHex)"
        publicDID = did
        return did
    }
    
    /// Get public key hex (without did:btcr: prefix)
    func getPublicKeyHex() throws -> String {
        if let publicKeyHex = try? keychain.loadString(.didPublicKey) {
            return publicKeyHex
        }
        
        // Derive from private key
        let privateKey = try loadPrivateKey()
        return NativeBridge.derivePublicKeyHex(privateKey)
    }
    
    /// Load private key from Keychain
    private func loadPrivateKey() throws -> Data {
        if let cached = cachedPrivateKey {
            return cached
        }
        
        let privateKey = try keychain.load(.didPrivateKey)
        cachedPrivateKey = privateKey
        return privateKey
    }
    
    /// Load existing identity on startup
    private func loadExistingIdentity() async {
        if let publicKeyHex = try? keychain.loadString(.didPublicKey) {
            publicDID = "\(didPrefix)\(publicKeyHex)"
            stwoProofGenerated = keychain.hasStwoProof
            membershipEnrolled = keychain.hasMembership
            witnessLoaded = keychain.exists(.witnessData)
            print("📱 Loaded existing DID: \(publicDID?.prefix(30) ?? "nil")...")
        }
    }
    
    /// Delete DID and all associated data
    func deleteDID() throws {
        try keychain.delete(.didPrivateKey)
        try keychain.delete(.didPublicKey)
        try keychain.delete(.stwoProof)
        try keychain.delete(.stwoProofHash)
        try keychain.delete(.leafSecret)
        try keychain.delete(.witnessData)
        
        publicDID = nil
        cachedPrivateKey = nil
        stwoProofGenerated = false
        membershipEnrolled = false
        witnessLoaded = false
    }
    
    // MARK: - Signing
    
    /// Sign a message with ECDSA (DER format)
    func signMessage(_ message: String) throws -> String {
        let privateKey = try loadPrivateKey()
        let signature = NativeBridge.signMessageDerHex(privateKey, message: message)
        guard !signature.starts(with: "error") else {
            throw DIDError.signingFailed(signature)
        }
        return signature
    }
    
    /// Sign a message with Schnorr (BIP340)
    func signSchnorr(_ message: String) throws -> String {
        let privateKey = try loadPrivateKey()
        let signature = NativeBridge.signSchnorr(privateKey, message: message)
        guard !signature.starts(with: "error") else {
            throw DIDError.signingFailed(signature)
        }
        return signature
    }
    
    // MARK: - STWO Proofs (Step 3 Onboarding)
    
    /// Generate STWO identity proof binding DID to wallet
    /// Called in Step 3 of onboarding (heavy operation, done once)
    func generateStwoProof(walletAddress: String) async throws -> String {
        isLoading = true
        defer { isLoading = false }
        
        let publicKeyHex = try getPublicKeyHex()
        
        // Create wallet signature (proves wallet ownership)
        let challenge = "signedby.me:identity:\(publicKeyHex):\(Int(Date().timeIntervalSince1970))"
        let walletSignature = try signMessage(challenge)
        
        // Check if real STWO is available
        let hasReal = NativeBridge.hasRealStwo()
        print("🔐 Generating STWO proof (real=\(hasReal))...")
        
        let proofJson: String
        if hasReal {
            // Generate real Circle STARK proof
            proofJson = NativeBridge.generateRealIdentityProof(
                didPubkeyHex: publicKeyHex,
                walletAddress: walletAddress,
                paymentHashHex: String(repeating: "0", count: 64), // Placeholder for Step 3
                expiryDays: proofExpiryDays
            )
        } else {
            // Fallback to mock proof
            proofJson = NativeBridge.generateIdentityProof(
                didPubkey: publicKeyHex,
                walletAddress: walletAddress,
                walletSignature: walletSignature,
                expiryDays: proofExpiryDays
            )
        }
        
        // Check for errors
        if proofJson.contains("\"status\":\"error\"") {
            throw DIDError.proofGenerationFailed(proofJson)
        }
        
        // Compute proof hash
        let proofHash = NativeBridge.sha256Hex(proofJson)
        
        // Store proof and hash
        try keychain.save(proofJson, for: .stwoProof)
        try keychain.save(proofHash, for: .stwoProofHash)
        
        stwoProofGenerated = true
        print("✅ STWO proof generated (hash: \(proofHash.prefix(16))...)")
        
        return proofJson
    }
    
    /// Get stored STWO proof
    func getStwoProof() throws -> String {
        return try keychain.loadString(.stwoProof)
    }
    
    /// Get stored STWO proof hash
    func getStwoProofHash() throws -> String {
        return try keychain.loadString(.stwoProofHash)
    }
    
    // MARK: - Login Proofs (V3 with full bindings)
    
    /// Generate login proof for a specific session
    /// Called at login time (fast operation)
    func generateLoginProof(
        session: LoginSession,
        paymentHash: String,
        walletAddress: String
    ) async throws -> String {
        let publicKeyHex = try getPublicKeyHex()
        
        // Calculate expiry (session expiry or 10 minutes, whichever is sooner)
        let tenMinutes = Int64(Date().timeIntervalSince1970) + 600
        let expiresAt = min(session.expiresAt ?? tenMinutes, tenMinutes)
        
        // Generate v3 proof with full bindings
        let proofJson = NativeBridge.generateRealIdentityProofV3(
            didPubkeyHex: publicKeyHex,
            walletAddress: walletAddress,
            paymentHashHex: paymentHash,
            amountSats: session.amountSats,
            expiresAt: expiresAt,
            eaDomain: session.domain,
            nonceHex: session.nonce
        )
        
        // Check for errors
        if proofJson.contains("\"status\":\"error\"") {
            throw DIDError.proofGenerationFailed(proofJson)
        }
        
        print("✅ Login proof generated for \(session.domain)")
        return proofJson
    }
    
    // MARK: - Membership Proofs
    
    /// Generate or retrieve leaf secret for membership
    func getOrCreateLeafSecret() throws -> Data {
        // Try to load existing
        if let existing = try? keychain.load(.leafSecret) {
            return existing
        }
        
        // Generate new 32-byte secret
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        guard status == errSecSuccess else {
            throw DIDError.randomGenerationFailed
        }
        
        let secret = Data(bytes)
        try keychain.save(secret, for: .leafSecret)
        
        print("🔑 Generated new leaf secret")
        return secret
    }
    
    /// Compute leaf commitment for enrollment
    func computeLeafCommitment() throws -> Data {
        let leafSecret = try getOrCreateLeafSecret()
        guard let commitment = NativeBridge.computeLeafCommitment(leafSecret) else {
            throw DIDError.commitmentComputationFailed
        }
        return commitment
    }
    
    /// Store witness data after fetching from API
    func storeWitness(_ witness: WitnessData) throws {
        try keychain.save(witness, for: .witnessData)
        witnessLoaded = true
        print("✅ Witness stored (root: \(witness.rootId.prefix(16))...)")
    }
    
    /// Load stored witness
    func loadWitness() throws -> WitnessData {
        return try keychain.load(WitnessData.self, for: .witnessData)
    }
    
    /// Generate membership proof for login
    func generateMembershipProof(
        session: LoginSession,
        paymentHash: Data,
        walletAddress: String
    ) async throws -> Data {
        let leafSecret = try getOrCreateLeafSecret()
        let witness = try loadWitness()
        let publicKeyHex = try getPublicKeyHex()
        
        // Decode DID pubkey from hex
        guard let didPubkey = Data(hex: publicKeyHex) else {
            throw DIDError.invalidHex
        }
        
        // Calculate expiry
        let expiresAt = session.expiresAt ?? Int64(Date().timeIntervalSince1970 + 600)
        
        // Decode nonce from hex
        guard let nonce = Data(hex: session.nonce), nonce.count == 16 else {
            throw DIDError.invalidNonce
        }
        
        // Compute V4 binding hash
        guard let bindingHash = NativeBridge.computeBindingHashV4(
            didPubkey: didPubkey,
            walletAddress: walletAddress,
            clientId: session.clientId,
            sessionId: session.sessionId,
            paymentHash: paymentHash,
            amountSats: session.amountSats,
            expiresAt: expiresAt,
            nonce: nonce,
            eaDomain: session.domain,
            purposeId: 1, // Allowlist
            rootId: witness.rootId
        ) else {
            throw DIDError.bindingHashFailed
        }
        
        // Convert witness path to format expected by proveMembership
        let merklePath: [[UInt8]] = witness.siblings.map { siblingHex in
            Data(hex: siblingHex)?.map { $0 } ?? [UInt8](repeating: 0, count: 32)
        }
        
        let pathIndices: [UInt8] = witness.pathIndices.map { UInt8($0) }
        
        guard let root = Data(hex: witness.root) else {
            throw DIDError.invalidHex
        }
        
        // Generate membership proof
        guard let proof = NativeBridge.proveMembership(
            leafSecret: leafSecret,
            merklePath: merklePath,
            pathIndices: pathIndices,
            root: root,
            bindingHash: bindingHash,
            purposeId: 1
        ) else {
            throw DIDError.membershipProofFailed
        }
        
        print("✅ Membership proof generated (\(proof.count) bytes)")
        return proof
    }
    
    /// Mark membership as enrolled (after successful API call)
    func markMembershipEnrolled() {
        membershipEnrolled = true
    }
}

// MARK: - Errors

enum DIDError: Error, LocalizedError {
    case keyGenerationFailed
    case keyDerivationFailed
    case signingFailed(String)
    case proofGenerationFailed(String)
    case randomGenerationFailed
    case commitmentComputationFailed
    case bindingHashFailed
    case membershipProofFailed
    case invalidHex
    case invalidNonce
    case notSetUp
    
    var errorDescription: String? {
        switch self {
        case .keyGenerationFailed: return "Failed to generate private key"
        case .keyDerivationFailed: return "Failed to derive public key"
        case .signingFailed(let msg): return "Signing failed: \(msg)"
        case .proofGenerationFailed(let msg): return "Proof generation failed: \(msg)"
        case .randomGenerationFailed: return "Failed to generate random bytes"
        case .commitmentComputationFailed: return "Failed to compute commitment"
        case .bindingHashFailed: return "Failed to compute binding hash"
        case .membershipProofFailed: return "Failed to generate membership proof"
        case .invalidHex: return "Invalid hex string"
        case .invalidNonce: return "Invalid session nonce"
        case .notSetUp: return "DID not set up"
        }
    }
}
