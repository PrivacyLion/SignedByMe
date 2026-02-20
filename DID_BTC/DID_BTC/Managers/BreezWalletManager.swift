// BreezWalletManager.swift - Lightning Wallet Integration
// SignedByMe iOS - Mirrors Android BreezWalletManager.kt
// Uses Breez SDK Spark for Lightning payments

import Foundation
import Combine

/// Wallet connection state
enum WalletState: Equatable {
    case disconnected
    case connecting
    case connected(balance: Int64)
    case error(String)
    
    var isConnected: Bool {
        if case .connected = self { return true }
        return false
    }
}

/// Manages Breez SDK Spark wallet for Lightning payments
@MainActor
final class BreezWalletManager: ObservableObject {
    
    // MARK: - Published Properties
    
    @Published private(set) var state: WalletState = .disconnected
    @Published private(set) var balanceSats: Int64 = 0
    @Published private(set) var sparkAddress: String?
    @Published private(set) var transactions: [WalletTransaction] = []
    @Published private(set) var btcPriceUsd: Double = 0
    
    // MARK: - Private Properties
    
    private let keychain = KeychainManager.shared
    private var isInitialized = false
    
    // Note: In production, import BreezSDK and use real SDK calls
    // For now, we define the interface for when SDK is integrated
    
    // MARK: - Initialization
    
    init() {
        Task {
            await loadExistingWallet()
        }
    }
    
    // MARK: - Wallet Setup
    
    /// Create a new wallet with BIP39 mnemonic
    func createWallet() async throws -> [String] {
        state = .connecting
        
        do {
            // Generate 12-word BIP39 mnemonic
            let mnemonic = generateMnemonic()
            
            // Store mnemonic securely
            try keychain.save(mnemonic.joined(separator: " "), for: .walletMnemonic)
            
            // Initialize SDK with mnemonic
            try await initializeSDK(mnemonic: mnemonic)
            
            print("✅ Created new wallet")
            return mnemonic
        } catch {
            state = .error(error.localizedDescription)
            throw error
        }
    }
    
    /// Restore wallet from mnemonic
    func restoreWallet(mnemonic: [String]) async throws {
        state = .connecting
        
        guard mnemonic.count == 12 || mnemonic.count == 24 else {
            throw WalletError.invalidMnemonic
        }
        
        do {
            // Store mnemonic
            try keychain.save(mnemonic.joined(separator: " "), for: .walletMnemonic)
            
            // Initialize SDK
            try await initializeSDK(mnemonic: mnemonic)
            
            print("✅ Restored wallet from mnemonic")
        } catch {
            state = .error(error.localizedDescription)
            throw error
        }
    }
    
    /// Load existing wallet on app start
    private func loadExistingWallet() async {
        guard let mnemonicString = try? keychain.loadString(.walletMnemonic) else {
            print("📱 No existing wallet found")
            return
        }
        
        let mnemonic = mnemonicString.split(separator: " ").map(String.init)
        
        do {
            state = .connecting
            try await initializeSDK(mnemonic: mnemonic)
            print("📱 Loaded existing wallet")
        } catch {
            state = .error(error.localizedDescription)
            print("❌ Failed to load wallet: \(error)")
        }
    }
    
    /// Initialize Breez SDK
    private func initializeSDK(mnemonic: [String]) async throws {
        // TODO: Replace with real Breez SDK initialization
        // Example Breez SDK Swift code:
        // let config = BreezConfig(...)
        // let sdk = try await BreezSDK.connect(config: config, mnemonic: mnemonic.joined(separator: " "))
        
        // For now, simulate initialization
        try await Task.sleep(nanoseconds: 500_000_000)
        
        // Mock values - replace with real SDK calls
        balanceSats = 0
        sparkAddress = "sp1q\(UUID().uuidString.prefix(32).lowercased())"
        state = .connected(balance: balanceSats)
        isInitialized = true
        
        // Fetch BTC price
        await fetchBtcPrice()
    }
    
    // MARK: - Invoice Management
    
    /// Create a Lightning invoice for receiving
    func createInvoice(amountSats: Int64, description: String) async throws -> String {
        guard isInitialized else {
            throw WalletError.notInitialized
        }
        
        // TODO: Replace with real Breez SDK call
        // let invoice = try await sdk.receivePayment(amountSats: amountSats, description: description)
        // return invoice.bolt11
        
        // Mock invoice for development
        let mockInvoice = "lnbc\(amountSats)n1p\(UUID().uuidString.prefix(50).lowercased())"
        print("📝 Created invoice for \(amountSats) sats")
        return mockInvoice
    }
    
    /// Parse and pay a BOLT11 invoice
    func payInvoice(_ bolt11: String) async throws -> String {
        guard isInitialized else {
            throw WalletError.notInitialized
        }
        
        // TODO: Replace with real Breez SDK call
        // let payment = try await sdk.sendPayment(bolt11: bolt11)
        // return payment.paymentPreimage
        
        // Mock payment for development
        try await Task.sleep(nanoseconds: 1_000_000_000)
        let mockPreimage = "mock_preimage_\(UUID().uuidString)"
        print("💸 Paid invoice")
        return mockPreimage
    }
    
    /// Check if a payment has been received (by payment hash)
    func isPaymentReceived(paymentHash: String) async -> Bool {
        guard isInitialized else { return false }
        
        // TODO: Replace with real Breez SDK call
        // return await sdk.isPaymentReceived(paymentHash: paymentHash)
        
        // Mock check
        return false
    }
    
    // MARK: - Balance & Transactions
    
    /// Refresh wallet balance
    func refreshBalance() async throws {
        guard isInitialized else {
            throw WalletError.notInitialized
        }
        
        // TODO: Replace with real Breez SDK call
        // let nodeInfo = try await sdk.nodeInfo()
        // balanceSats = nodeInfo.channelsBalanceSats + nodeInfo.onchainBalanceSats
        
        state = .connected(balance: balanceSats)
    }
    
    /// Fetch transaction history
    func fetchTransactions() async throws {
        guard isInitialized else {
            throw WalletError.notInitialized
        }
        
        // TODO: Replace with real Breez SDK call
        // let payments = try await sdk.listPayments()
        // transactions = payments.map { ... }
        
        // Mock transactions for development
        transactions = []
    }
    
    // MARK: - Mnemonic
    
    /// Get mnemonic for backup display (requires biometric)
    func getMnemonic() async throws -> [String] {
        // Require biometric auth
        let authenticated = try await keychain.authenticateWithBiometrics(
            reason: "Authenticate to view recovery phrase"
        )
        guard authenticated else {
            throw WalletError.authenticationFailed
        }
        
        let mnemonicString = try keychain.loadString(.walletMnemonic)
        return mnemonicString.split(separator: " ").map(String.init)
    }
    
    /// Delete wallet (for testing/reset)
    func deleteWallet() throws {
        try keychain.delete(.walletMnemonic)
        try keychain.delete(.walletSeed)
        
        state = .disconnected
        balanceSats = 0
        sparkAddress = nil
        transactions = []
        isInitialized = false
    }
    
    // MARK: - BTC Price
    
    /// Fetch current BTC price
    func fetchBtcPrice() async {
        do {
            btcPriceUsd = try await APIService.shared.getBtcPrice()
        } catch {
            print("⚠️ Failed to fetch BTC price: \(error)")
        }
    }
    
    /// Convert sats to USD
    func satsToUsd(_ sats: Int64) -> Double {
        guard btcPriceUsd > 0 else { return 0 }
        return Double(sats) / 100_000_000 * btcPriceUsd
    }
    
    /// Format sats for display
    func formatSats(_ sats: Int64) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        return formatter.string(from: NSNumber(value: sats)) ?? "\(sats)"
    }
    
    /// Format USD for display
    func formatUsd(_ amount: Double) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .currency
        formatter.currencyCode = "USD"
        return formatter.string(from: NSNumber(value: amount)) ?? "$\(amount)"
    }
    
    // MARK: - Private Helpers
    
    /// Generate BIP39 mnemonic
    private func generateMnemonic() -> [String] {
        // BIP39 word list (abbreviated - full list has 2048 words)
        // TODO: Use proper BIP39 library
        let wordList = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
            "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
            "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
            "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
            "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
            "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among"
        ]
        
        // Generate random 12 words
        var mnemonic: [String] = []
        for _ in 0..<12 {
            let randomIndex = Int.random(in: 0..<wordList.count)
            mnemonic.append(wordList[randomIndex])
        }
        
        return mnemonic
    }
}

// MARK: - Wallet Errors

enum WalletError: Error, LocalizedError {
    case notInitialized
    case invalidMnemonic
    case authenticationFailed
    case invoiceFailed
    case paymentFailed
    case insufficientBalance
    
    var errorDescription: String? {
        switch self {
        case .notInitialized: return "Wallet not initialized"
        case .invalidMnemonic: return "Invalid recovery phrase"
        case .authenticationFailed: return "Authentication failed"
        case .invoiceFailed: return "Failed to create invoice"
        case .paymentFailed: return "Payment failed"
        case .insufficientBalance: return "Insufficient balance"
        }
    }
}

// MARK: - Computed Properties

extension BreezWalletManager {
    
    /// Check if wallet is set up
    var hasWallet: Bool {
        keychain.hasWallet
    }
    
    /// Balance formatted for display
    var formattedBalance: String {
        formatSats(balanceSats)
    }
    
    /// Balance in USD formatted
    var formattedUsdBalance: String {
        formatUsd(satsToUsd(balanceSats))
    }
}
