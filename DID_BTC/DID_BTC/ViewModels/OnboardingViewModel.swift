// OnboardingViewModel.swift - Onboarding Flow Coordinator
// SignedByMe iOS

import Foundation
import SwiftUI

/// Current step in onboarding
enum OnboardingStep: Int, CaseIterable {
    case welcome = 0
    case wallet = 1
    case identity = 2
    case complete = 3
    
    var title: String {
        switch self {
        case .welcome: return "Welcome"
        case .wallet: return "Wallet"
        case .identity: return "Identity"
        case .complete: return "Complete"
        }
    }
    
    var subtitle: String {
        switch self {
        case .welcome: return "Get paid to Log In"
        case .wallet: return "Set up your wallet"
        case .identity: return "Create your identity"
        case .complete: return "You're all set!"
        }
    }
}

/// Coordinates the 3-step onboarding flow
@MainActor
final class OnboardingViewModel: ObservableObject {
    
    // MARK: - Published Properties
    
    @Published var currentStep: OnboardingStep = .welcome
    @Published var isLoading = false
    @Published var error: String?
    
    // Step 2 - Wallet
    @Published var walletOption: WalletSetupOption = .create
    @Published var mnemonic: [String] = []
    @Published var restoreMnemonic: String = ""
    @Published var backupPassword: String = ""
    @Published var mnemonicVerified = false
    @Published var biometricEnabled = false
    @Published var backupToICloud = false
    
    // Step 3 - Identity
    @Published var identityProgress: IdentitySetupProgress = .notStarted
    @Published var stwoProofGenerated = false
    @Published var membershipEnrolled = false
    @Published var witnessLoaded = false
    
    // MARK: - Dependencies
    
    private let didManager: DIDManager
    private let walletManager: BreezWalletManager
    private let backupManager: iCloudBackupManager
    private let keychain = KeychainManager.shared
    
    // MARK: - Initialization
    
    init(
        didManager: DIDManager = DIDManager(),
        walletManager: BreezWalletManager = BreezWalletManager(),
        backupManager: iCloudBackupManager = iCloudBackupManager()
    ) {
        self.didManager = didManager
        self.walletManager = walletManager
        self.backupManager = backupManager
        
        // Check if already set up
        Task {
            await checkExistingSetup()
        }
    }
    
    // MARK: - Setup Check
    
    private func checkExistingSetup() async {
        if keychain.hasIdentity && keychain.hasWallet && keychain.hasStwoProof {
            currentStep = .complete
        } else if keychain.hasWallet {
            currentStep = .identity
        } else if keychain.hasIdentity {
            currentStep = .wallet
        }
    }
    
    // MARK: - Step 1: Welcome
    
    func startOnboarding() {
        currentStep = .wallet
    }
    
    // MARK: - Step 2: Wallet Setup
    
    enum WalletSetupOption {
        case create
        case restore
        case restoreFromCloud
    }
    
    /// Create new wallet
    func createWallet() async {
        isLoading = true
        error = nil
        
        do {
            mnemonic = try await walletManager.createWallet()
            isLoading = false
        } catch {
            self.error = error.localizedDescription
            isLoading = false
        }
    }
    
    /// Restore wallet from mnemonic
    func restoreFromMnemonic() async {
        isLoading = true
        error = nil
        
        let words = restoreMnemonic
            .lowercased()
            .split(separator: " ")
            .map(String.init)
            .filter { !$0.isEmpty }
        
        guard words.count == 12 || words.count == 24 else {
            error = "Please enter 12 or 24 words"
            isLoading = false
            return
        }
        
        do {
            try await walletManager.restoreWallet(mnemonic: words)
            mnemonic = words
            isLoading = false
        } catch {
            self.error = error.localizedDescription
            isLoading = false
        }
    }
    
    /// Restore from iCloud backup
    func restoreFromCloud() async {
        isLoading = true
        error = nil
        
        guard !backupPassword.isEmpty else {
            error = "Please enter your backup password"
            isLoading = false
            return
        }
        
        do {
            let words = try await backupManager.restore(password: backupPassword)
            try await walletManager.restoreWallet(mnemonic: words)
            mnemonic = words
            isLoading = false
        } catch {
            self.error = error.localizedDescription
            isLoading = false
        }
    }
    
    /// Enable biometric protection
    func enableBiometric() async {
        do {
            let success = try await keychain.authenticateWithBiometrics(
                reason: "Enable \(keychain.biometricTypeName) for SignedByMe"
            )
            if success {
                biometricEnabled = true
                try keychain.save("true", for: .biometricEnabled)
            }
        } catch {
            self.error = "Failed to enable biometric: \(error.localizedDescription)"
        }
    }
    
    /// Backup wallet to iCloud
    func backupToCloud(password: String) async {
        isLoading = true
        error = nil
        
        do {
            try await backupManager.backup(password: password)
            backupToICloud = true
            isLoading = false
        } catch {
            self.error = error.localizedDescription
            isLoading = false
        }
    }
    
    /// Complete wallet setup and proceed to identity
    func completeWalletSetup() {
        currentStep = .identity
    }
    
    // MARK: - Step 3: Identity Setup
    
    enum IdentitySetupProgress: String {
        case notStarted = "Not started"
        case creatingDID = "Creating identity..."
        case generatingProof = "Generating proof..."
        case enrollingMembership = "Enrolling..."
        case fetchingWitness = "Finalizing..."
        case complete = "Complete"
    }
    
    /// Run full identity setup (DID + STWO + Membership)
    func setupIdentity() async {
        isLoading = true
        error = nil
        
        do {
            // Step 3a: Create DID
            identityProgress = .creatingDID
            _ = try await didManager.createDID()
            
            // Step 3b: Generate STWO proof
            identityProgress = .generatingProof
            guard let sparkAddress = walletManager.sparkAddress else {
                throw OnboardingError.walletNotReady
            }
            _ = try await didManager.generateStwoProof(walletAddress: sparkAddress)
            stwoProofGenerated = true
            
            // Step 3c: Enroll in membership
            identityProgress = .enrollingMembership
            try await enrollMembership()
            membershipEnrolled = true
            
            // Step 3d: Fetch witness
            identityProgress = .fetchingWitness
            try await fetchWitness()
            witnessLoaded = true
            
            // Done!
            identityProgress = .complete
            isLoading = false
            
            // Short delay then move to complete
            try await Task.sleep(nanoseconds: 500_000_000)
            currentStep = .complete
            
        } catch {
            self.error = error.localizedDescription
            isLoading = false
        }
    }
    
    /// Enroll for membership
    private func enrollMembership() async throws {
        let commitment = try didManager.computeLeafCommitment()
        let didPubkey = try didManager.getPublicKeyHex()
        
        let response = try await APIService.shared.enrollMembership(
            leafCommitment: commitment,
            didPubkey: didPubkey
        )
        
        if !response.isSuccess {
            throw OnboardingError.enrollmentFailed(response.message ?? "Unknown error")
        }
        
        didManager.markMembershipEnrolled()
    }
    
    /// Fetch membership witness
    private func fetchWitness() async throws {
        let commitment = try didManager.computeLeafCommitment()
        let witness = try await APIService.shared.fetchWitness(leafCommitment: commitment)
        try didManager.storeWitness(witness)
    }
    
    // MARK: - Complete
    
    /// Finish onboarding and go to main app
    func finishOnboarding() {
        // App will observe currentStep = .complete and show main UI
    }
}

// MARK: - Errors

enum OnboardingError: Error, LocalizedError {
    case walletNotReady
    case enrollmentFailed(String)
    case witnessFailed
    
    var errorDescription: String? {
        switch self {
        case .walletNotReady: return "Wallet is not ready"
        case .enrollmentFailed(let msg): return "Enrollment failed: \(msg)"
        case .witnessFailed: return "Failed to fetch membership data"
        }
    }
}
