// WalletSetupView.swift - Step 2: Wallet Setup
// SignedByMe iOS

import SwiftUI

struct WalletSetupView: View {
    @EnvironmentObject var viewModel: OnboardingViewModel
    @EnvironmentObject var backupManager: iCloudBackupManager
    
    @State private var showMnemonic = false
    @State private var showRestoreOptions = false
    @State private var backupPassword = ""
    @State private var confirmBackupPassword = ""
    
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Header
                VStack(spacing: 8) {
                    stepBadge(number: 2)
                    Text("Set Up Wallet")
                        .font(.title.bold())
                    Text("Connect a Lightning wallet to receive payments")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(.top, 24)
                
                if viewModel.mnemonic.isEmpty {
                    setupOptions
                } else if !showMnemonic {
                    mnemonicCreated
                } else {
                    mnemonicDisplay
                }
                
                // Error display
                if let error = viewModel.error {
                    Text(error)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .padding()
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(12)
                }
            }
            .padding(.horizontal, 24)
        }
    }
    
    // MARK: - Setup Options
    
    private var setupOptions: some View {
        VStack(spacing: 16) {
            // Create new wallet
            SetupOptionCard(
                icon: "plus.circle.fill",
                title: "Create New Wallet",
                subtitle: "Generate a new Lightning wallet",
                color: .blue,
                isLoading: viewModel.isLoading && viewModel.walletOption == .create
            ) {
                viewModel.walletOption = .create
                Task {
                    await viewModel.createWallet()
                    if !viewModel.mnemonic.isEmpty {
                        showMnemonic = true
                    }
                }
            }
            
            // Restore from seed
            SetupOptionCard(
                icon: "arrow.clockwise.circle.fill",
                title: "Restore from Phrase",
                subtitle: "Enter your 12 or 24 word phrase",
                color: .orange
            ) {
                showRestoreOptions = true
                viewModel.walletOption = .restore
            }
            
            // Restore from iCloud
            if backupManager.isICloudAvailable && backupManager.isBackedUp {
                SetupOptionCard(
                    icon: "icloud.fill",
                    title: "Restore from iCloud",
                    subtitle: "Restore your previous backup",
                    color: .cyan,
                    isLoading: viewModel.isLoading && viewModel.walletOption == .restoreFromCloud
                ) {
                    viewModel.walletOption = .restoreFromCloud
                    showRestoreOptions = true
                }
            }
        }
        .sheet(isPresented: $showRestoreOptions) {
            RestoreWalletSheet(
                option: viewModel.walletOption,
                restoreMnemonic: $viewModel.restoreMnemonic,
                backupPassword: $viewModel.backupPassword,
                onRestore: {
                    Task {
                        if viewModel.walletOption == .restoreFromCloud {
                            await viewModel.restoreFromCloud()
                        } else {
                            await viewModel.restoreFromMnemonic()
                        }
                        if !viewModel.mnemonic.isEmpty {
                            showRestoreOptions = false
                        }
                    }
                },
                isLoading: viewModel.isLoading,
                error: viewModel.error
            )
            .presentationDetents([.medium, .large])
        }
    }
    
    // MARK: - Mnemonic Created
    
    private var mnemonicCreated: some View {
        VStack(spacing: 20) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 60))
                .foregroundStyle(.green)
            
            Text("Wallet Created!")
                .font(.title2.bold())
            
            Text("Your wallet has been created. Back up your recovery phrase now.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            
            Button {
                showMnemonic = true
            } label: {
                Label("View Recovery Phrase", systemImage: "eye")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 50)
                    .background(Color.blue)
                    .cornerRadius(12)
            }
            
            Button("Skip for Now") {
                viewModel.completeWalletSetup()
            }
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
        .padding(.top, 32)
    }
    
    // MARK: - Mnemonic Display
    
    private var mnemonicDisplay: some View {
        VStack(spacing: 20) {
            Text("Your Recovery Phrase")
                .font(.title3.bold())
            
            Text("Write these words down and keep them safe. You'll need them to recover your wallet.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            
            // Word grid
            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
                GridItem(.flexible())
            ], spacing: 12) {
                ForEach(Array(viewModel.mnemonic.enumerated()), id: \.offset) { index, word in
                    HStack {
                        Text("\(index + 1).")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(width: 20, alignment: .trailing)
                        Text(word)
                            .font(.body.monospaced())
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(8)
                }
            }
            
            // Copy button
            Button {
                UIPasteboard.general.string = viewModel.mnemonic.joined(separator: " ")
            } label: {
                Label("Copy to Clipboard", systemImage: "doc.on.doc")
                    .font(.subheadline)
            }
            .buttonStyle(.bordered)
            
            Divider()
                .padding(.vertical)
            
            // Biometric option
            if KeychainManager.shared.isBiometricAvailable {
                Toggle(isOn: $viewModel.biometricEnabled) {
                    Label("Enable \(KeychainManager.shared.biometricTypeName)", systemImage: "faceid")
                }
                .onChange(of: viewModel.biometricEnabled) { _, newValue in
                    if newValue {
                        Task { await viewModel.enableBiometric() }
                    }
                }
            }
            
            // iCloud backup option
            if backupManager.isICloudAvailable {
                Toggle(isOn: $viewModel.backupToICloud) {
                    Label("Back up to iCloud", systemImage: "icloud")
                }
                
                if viewModel.backupToICloud && backupPassword.isEmpty {
                    VStack(spacing: 12) {
                        SecureField("Create backup password", text: $backupPassword)
                            .textFieldStyle(.roundedBorder)
                        SecureField("Confirm password", text: $confirmBackupPassword)
                            .textFieldStyle(.roundedBorder)
                        
                        if !backupPassword.isEmpty && backupPassword != confirmBackupPassword {
                            Text("Passwords don't match")
                                .font(.caption)
                                .foregroundStyle(.red)
                        }
                    }
                }
            }
            
            // Continue button
            Button {
                Task {
                    if viewModel.backupToICloud && !backupPassword.isEmpty {
                        await viewModel.backupToCloud(password: backupPassword)
                    }
                    viewModel.completeWalletSetup()
                }
            } label: {
                Text("Continue")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 50)
                    .background(
                        LinearGradient(colors: [.blue, .purple], startPoint: .leading, endPoint: .trailing)
                    )
                    .cornerRadius(12)
            }
            .disabled(viewModel.backupToICloud && backupPassword != confirmBackupPassword)
        }
        .padding(.top, 16)
    }
    
    // MARK: - Helpers
    
    private func stepBadge(number: Int) -> some View {
        Text("\(number)")
            .font(.headline)
            .foregroundColor(.white)
            .frame(width: 36, height: 36)
            .background(
                LinearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing)
            )
            .clipShape(Circle())
    }
}

// MARK: - Setup Option Card

struct SetupOptionCard: View {
    let icon: String
    let title: String
    let subtitle: String
    let color: Color
    var isLoading: Bool = false
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 16) {
                Image(systemName: icon)
                    .font(.title)
                    .foregroundStyle(color)
                    .frame(width: 50, height: 50)
                    .background(color.opacity(0.1))
                    .cornerRadius(12)
                
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.headline)
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                
                Spacer()
                
                if isLoading {
                    ProgressView()
                } else {
                    Image(systemName: "chevron.right")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(16)
            .background(Color(.secondarySystemBackground))
            .cornerRadius(16)
        }
        .disabled(isLoading)
    }
}

// MARK: - Restore Sheet

struct RestoreWalletSheet: View {
    let option: OnboardingViewModel.WalletSetupOption
    @Binding var restoreMnemonic: String
    @Binding var backupPassword: String
    let onRestore: () -> Void
    let isLoading: Bool
    let error: String?
    
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if option == .restoreFromCloud {
                    // iCloud restore
                    VStack(spacing: 16) {
                        Image(systemName: "icloud.fill")
                            .font(.largeTitle)
                            .foregroundStyle(.cyan)
                        
                        Text("Enter your backup password")
                            .font(.headline)
                        
                        SecureField("Backup password", text: $backupPassword)
                            .textFieldStyle(.roundedBorder)
                    }
                } else {
                    // Mnemonic restore
                    VStack(spacing: 16) {
                        Text("Enter your 12 or 24 word recovery phrase")
                            .font(.headline)
                        
                        TextEditor(text: $restoreMnemonic)
                            .frame(height: 120)
                            .font(.body.monospaced())
                            .padding(8)
                            .background(Color(.secondarySystemBackground))
                            .cornerRadius(12)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                    }
                }
                
                if let error = error {
                    Text(error)
                        .font(.callout)
                        .foregroundStyle(.red)
                }
                
                Button(action: onRestore) {
                    if isLoading {
                        ProgressView()
                            .tint(.white)
                    } else {
                        Text("Restore Wallet")
                    }
                }
                .font(.headline)
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .frame(height: 50)
                .background(Color.blue)
                .cornerRadius(12)
                .disabled(isLoading || (option == .restore && restoreMnemonic.isEmpty) || (option == .restoreFromCloud && backupPassword.isEmpty))
                
                Spacer()
            }
            .padding()
            .navigationTitle("Restore Wallet")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}

// MARK: - Preview

#Preview {
    WalletSetupView()
        .environmentObject(OnboardingViewModel())
        .environmentObject(iCloudBackupManager())
}
