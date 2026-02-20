// SignedByMeApp.swift - App Entry Point
// SignedByMe iOS

import SwiftUI

@main
struct SignedByMeApp: App {
    
    // MARK: - State Objects
    
    @StateObject private var didManager = DIDManager()
    @StateObject private var walletManager = BreezWalletManager()
    @StateObject private var backupManager = iCloudBackupManager()
    @StateObject private var onboardingVM = OnboardingViewModel()
    @StateObject private var loginVM = LoginViewModel()
    
    // MARK: - Body
    
    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(didManager)
                .environmentObject(walletManager)
                .environmentObject(backupManager)
                .environmentObject(onboardingVM)
                .environmentObject(loginVM)
                .onOpenURL { url in
                    handleDeepLink(url)
                }
        }
    }
    
    // MARK: - Deep Link Handling
    
    private func handleDeepLink(_ url: URL) {
        print("📱 Received deep link: \(url)")
        
        // Handle signedby.me:// URLs
        if url.scheme == "signedby.me" || url.scheme == "signedby" {
            loginVM.handleDeepLink(url)
        }
    }
}

// MARK: - Root View

struct RootView: View {
    @EnvironmentObject var onboardingVM: OnboardingViewModel
    @EnvironmentObject var didManager: DIDManager
    
    var body: some View {
        Group {
            if onboardingVM.currentStep == .complete {
                MainTabView()
            } else {
                OnboardingContainerView()
            }
        }
        .animation(.easeInOut, value: onboardingVM.currentStep)
    }
}

// MARK: - Main Tab View

struct MainTabView: View {
    @State private var selectedTab = 0
    
    var body: some View {
        TabView(selection: $selectedTab) {
            LoginView()
                .tabItem {
                    Label("Login", systemImage: "qrcode.viewfinder")
                }
                .tag(0)
            
            WalletView()
                .tabItem {
                    Label("Wallet", systemImage: "bitcoinsign.circle")
                }
                .tag(1)
            
            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
                .tag(2)
        }
        .tint(.orange)
    }
}

// MARK: - Placeholder Settings View

struct SettingsView: View {
    @EnvironmentObject var didManager: DIDManager
    @EnvironmentObject var walletManager: BreezWalletManager
    @EnvironmentObject var backupManager: iCloudBackupManager
    
    var body: some View {
        NavigationStack {
            List {
                Section("Identity") {
                    if let did = didManager.publicDID {
                        LabeledContent("DID") {
                            Text(String(did.suffix(20)))
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                    
                    LabeledContent("STWO Proof") {
                        Image(systemName: didManager.stwoProofGenerated ? "checkmark.circle.fill" : "xmark.circle")
                            .foregroundStyle(didManager.stwoProofGenerated ? .green : .red)
                    }
                    
                    LabeledContent("Membership") {
                        Image(systemName: didManager.membershipEnrolled ? "checkmark.circle.fill" : "xmark.circle")
                            .foregroundStyle(didManager.membershipEnrolled ? .green : .red)
                    }
                }
                
                Section("Wallet") {
                    LabeledContent("Status") {
                        Text(walletManager.state.isConnected ? "Connected" : "Disconnected")
                            .foregroundStyle(walletManager.state.isConnected ? .green : .secondary)
                    }
                    
                    if let address = walletManager.sparkAddress {
                        LabeledContent("Spark Address") {
                            Text(String(address.suffix(16)))
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                
                Section("Backup") {
                    LabeledContent("iCloud Backup") {
                        Text(backupManager.isBackedUp ? "Enabled" : "Not backed up")
                            .foregroundStyle(backupManager.isBackedUp ? .green : .orange)
                    }
                    
                    if backupManager.isBackedUp {
                        LabeledContent("Last Backup") {
                            Text(backupManager.formattedLastBackup)
                                .foregroundStyle(.secondary)
                        }
                    }
                    
                    NavigationLink("View Recovery Phrase") {
                        RecoveryPhraseView()
                    }
                }
                
                Section("About") {
                    LabeledContent("Version") {
                        Text("1.0.0")
                            .foregroundStyle(.secondary)
                    }
                    
                    LabeledContent("Real STWO") {
                        Text(NativeBridge.hasRealStwo() ? "Yes" : "No")
                            .foregroundStyle(NativeBridge.hasRealStwo() ? .green : .orange)
                    }
                    
                    Link("Privacy Policy", destination: URL(string: "https://signedby.me/privacy")!)
                    Link("Terms of Service", destination: URL(string: "https://signedby.me/terms")!)
                }
                
                Section {
                    Button("Reset App", role: .destructive) {
                        // TODO: Implement reset
                    }
                }
            }
            .navigationTitle("Settings")
        }
    }
}

// MARK: - Recovery Phrase View

struct RecoveryPhraseView: View {
    @EnvironmentObject var walletManager: BreezWalletManager
    @State private var mnemonic: [String] = []
    @State private var isLoading = false
    @State private var error: String?
    @State private var isRevealed = false
    
    var body: some View {
        VStack(spacing: 24) {
            if isLoading {
                ProgressView()
            } else if let error = error {
                Text(error)
                    .foregroundStyle(.red)
            } else if !mnemonic.isEmpty && isRevealed {
                seedPhraseGrid
            } else {
                revealButton
            }
        }
        .padding()
        .navigationTitle("Recovery Phrase")
        .navigationBarTitleDisplayMode(.inline)
    }
    
    private var revealButton: some View {
        VStack(spacing: 16) {
            Image(systemName: "eye.slash.fill")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            
            Text("Your recovery phrase is hidden for security")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            
            Button("Reveal Recovery Phrase") {
                loadMnemonic()
            }
            .buttonStyle(.borderedProminent)
        }
    }
    
    private var seedPhraseGrid: some View {
        LazyVGrid(columns: [
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible())
        ], spacing: 12) {
            ForEach(Array(mnemonic.enumerated()), id: \.offset) { index, word in
                HStack {
                    Text("\(index + 1).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(width: 24, alignment: .trailing)
                    Text(word)
                        .font(.body.monospaced())
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemBackground))
                .cornerRadius(8)
            }
        }
    }
    
    private func loadMnemonic() {
        isLoading = true
        Task {
            do {
                mnemonic = try await walletManager.getMnemonic()
                isRevealed = true
            } catch {
                self.error = error.localizedDescription
            }
            isLoading = false
        }
    }
}

// MARK: - Preview

#Preview {
    RootView()
        .environmentObject(DIDManager())
        .environmentObject(BreezWalletManager())
        .environmentObject(iCloudBackupManager())
        .environmentObject(OnboardingViewModel())
        .environmentObject(LoginViewModel())
}
