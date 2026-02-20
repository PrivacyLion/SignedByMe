// LoginViewModel.swift - Login Flow Coordinator
// SignedByMe iOS

import Foundation
import SwiftUI

/// Login flow state
enum LoginState: Equatable {
    case idle
    case scanning
    case sessionLoaded(LoginSession)
    case generatingProof
    case creatingInvoice
    case submitting
    case waitingForPayment
    case success(satsEarned: Int64)
    case error(String)
    
    var isProcessing: Bool {
        switch self {
        case .generatingProof, .creatingInvoice, .submitting, .waitingForPayment:
            return true
        default:
            return false
        }
    }
}

/// Coordinates the login flow
@MainActor
final class LoginViewModel: ObservableObject {
    
    // MARK: - Published Properties
    
    @Published var state: LoginState = .idle
    @Published var session: LoginSession?
    @Published var progress: LoginProgress = .none
    @Published var satsEarned: Int64 = 0
    @Published var showBackupPrompt = false
    
    // MARK: - Dependencies
    
    private let didManager: DIDManager
    private let walletManager: BreezWalletManager
    private let keychain = KeychainManager.shared
    
    // MARK: - Initialization
    
    init(
        didManager: DIDManager = DIDManager(),
        walletManager: BreezWalletManager = BreezWalletManager()
    ) {
        self.didManager = didManager
        self.walletManager = walletManager
    }
    
    // MARK: - QR / Deep Link Handling
    
    /// Handle scanned QR code
    func handleQRCode(_ content: String) {
        // Try to parse as URL (deep link)
        if let url = URL(string: content), let session = LoginSession(deepLink: url) {
            handleSession(session)
            return
        }
        
        // Try to parse as JWT
        if let session = LoginSession(jwt: content) {
            handleSession(session)
            return
        }
        
        state = .error("Invalid QR code")
    }
    
    /// Handle deep link URL
    func handleDeepLink(_ url: URL) {
        guard let session = LoginSession(deepLink: url) else {
            state = .error("Invalid login link")
            return
        }
        handleSession(session)
    }
    
    /// Process loaded session
    private func handleSession(_ session: LoginSession) {
        // Check if expired
        if session.isExpired {
            state = .error("Session expired")
            return
        }
        
        self.session = session
        state = .sessionLoaded(session)
    }
    
    // MARK: - Login Flow
    
    enum LoginProgress: String {
        case none = ""
        case generatingProof = "Generating proof..."
        case generatingMembership = "Generating membership proof..."
        case creatingInvoice = "Creating invoice..."
        case submitting = "Submitting..."
        case waitingForPayment = "Getting paid..."
        case settlingDlc = "Settling contract..."
    }
    
    /// Execute full login flow
    func login() async {
        guard let session = session else {
            state = .error("No session loaded")
            return
        }
        
        do {
            // Step 1: Create Lightning invoice
            state = .creatingInvoice
            progress = .creatingInvoice
            
            let invoice = try await walletManager.createInvoice(
                amountSats: session.amountSats,
                description: "SignedByMe login to \(session.displayName)"
            )
            
            // Parse payment hash from invoice (simplified - real impl would parse BOLT11)
            let paymentHash = NativeBridge.sha256Hex(invoice)
            
            // Step 2: Generate STWO v3 proof
            state = .generatingProof
            progress = .generatingProof
            
            guard let sparkAddress = walletManager.sparkAddress else {
                throw LoginError.walletNotReady
            }
            
            let stwoProof = try await didManager.generateLoginProof(
                session: session,
                paymentHash: paymentHash,
                walletAddress: sparkAddress
            )
            
            // Step 3: Generate membership proof (if required)
            var membershipProofData: Data?
            if session.requireMembership {
                progress = .generatingMembership
                
                guard let paymentHashData = Data(hex: paymentHash) else {
                    throw LoginError.invalidPaymentHash
                }
                
                membershipProofData = try await didManager.generateMembershipProof(
                    session: session,
                    paymentHash: paymentHashData,
                    walletAddress: sparkAddress
                )
            }
            
            // Step 4: Submit to API
            state = .submitting
            progress = .submitting
            
            let invoiceResponse = try await APIService.shared.submitLoginInvoice(
                sessionToken: session.rawToken ?? session.sessionId,
                stwoProof: stwoProof,
                invoice: invoice,
                membershipProof: membershipProofData
            )
            
            guard invoiceResponse.isSuccess, let sessionId = invoiceResponse.sessionId else {
                throw LoginError.submissionFailed(invoiceResponse.error ?? "Unknown error")
            }
            
            // Step 5: Wait for payment
            state = .waitingForPayment
            progress = .waitingForPayment
            
            let pollResponse = try await APIService.shared.waitForPayment(
                sessionId: sessionId,
                timeoutSeconds: 120
            )
            
            guard pollResponse.isPaid else {
                throw LoginError.paymentTimeout
            }
            
            // Step 6: DLC settlement (background)
            progress = .settlingDlc
            await settleDlc(outcome: "auth_verified")
            
            // Success!
            let earned = pollResponse.satsEarned ?? session.amountSats
            satsEarned = earned
            state = .success(satsEarned: earned)
            
            // Check if should prompt for backup
            checkBackupPrompt()
            
            // Record login timestamp
            try? keychain.save(String(Date().timeIntervalSince1970), for: .lastLoginTimestamp)
            
        } catch {
            state = .error(error.localizedDescription)
        }
        
        progress = .none
    }
    
    /// Settle DLC after successful payment
    private func settleDlc(outcome: String) async {
        // Sign outcome
        let signatureJson = NativeBridge.oracleSignOutcome(outcome)
        print("🔏 DLC settled: \(outcome)")
    }
    
    /// Check if should prompt for backup
    private func checkBackupPrompt() {
        // Prompt for backup after first successful login if not backed up
        let isFirstLogin = !keychain.exists(.lastLoginTimestamp)
        let notBackedUp = !keychain.exists(.backupCompleted)
        
        if isFirstLogin && notBackedUp {
            showBackupPrompt = true
        }
    }
    
    // MARK: - Reset
    
    /// Reset to idle state
    func reset() {
        state = .idle
        session = nil
        progress = .none
    }
    
    /// Start scanning
    func startScan() {
        state = .scanning
    }
    
    /// Cancel scan
    func cancelScan() {
        state = .idle
    }
}

// MARK: - Errors

enum LoginError: Error, LocalizedError {
    case walletNotReady
    case invalidPaymentHash
    case submissionFailed(String)
    case paymentTimeout
    case membershipRequired
    
    var errorDescription: String? {
        switch self {
        case .walletNotReady: return "Wallet is not ready"
        case .invalidPaymentHash: return "Invalid payment hash"
        case .submissionFailed(let msg): return "Login failed: \(msg)"
        case .paymentTimeout: return "Payment timed out"
        case .membershipRequired: return "Membership verification required"
        }
    }
}
