// LoginView.swift - Main Login Screen
// SignedByMe iOS

import SwiftUI
import AVFoundation

struct LoginView: View {
    @EnvironmentObject var viewModel: LoginViewModel
    @EnvironmentObject var walletManager: BreezWalletManager
    
    var body: some View {
        NavigationStack {
            ZStack {
                // Background
                Color(.systemGroupedBackground)
                    .ignoresSafeArea()
                
                VStack(spacing: 0) {
                    switch viewModel.state {
                    case .idle:
                        idleView
                    case .scanning:
                        scannerView
                    case .sessionLoaded(let session):
                        sessionPreview(session)
                    case .generatingProof, .creatingInvoice, .submitting, .waitingForPayment:
                        processingView
                    case .success(let sats):
                        successView(sats: sats)
                    case .error(let message):
                        errorView(message: message)
                    }
                }
            }
            .navigationTitle("Login")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $viewModel.showBackupPrompt) {
                BackupPromptSheet()
            }
        }
    }
    
    // MARK: - Idle View
    
    private var idleView: some View {
        VStack(spacing: 32) {
            Spacer()
            
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 80))
                .foregroundStyle(
                    LinearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
            
            VStack(spacing: 8) {
                Text("Scan to Log In")
                    .font(.title2.bold())
                
                Text("Scan a SignedByMe QR code to authenticate and get paid")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            
            Spacer()
            
            Button {
                viewModel.startScan()
            } label: {
                Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 56)
                    .background(
                        LinearGradient(colors: [.blue, .purple], startPoint: .leading, endPoint: .trailing)
                    )
                    .cornerRadius(16)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
        }
    }
    
    // MARK: - Scanner View
    
    private var scannerView: some View {
        QRScannerView(
            onScan: { code in
                viewModel.handleQRCode(code)
            },
            onCancel: {
                viewModel.cancelScan()
            }
        )
    }
    
    // MARK: - Session Preview
    
    private func sessionPreview(_ session: LoginSession) -> some View {
        VStack(spacing: 24) {
            Spacer()
            
            // Enterprise info
            VStack(spacing: 12) {
                Image(systemName: "building.2.fill")
                    .font(.system(size: 50))
                    .foregroundStyle(.blue)
                
                Text(session.displayName)
                    .font(.title.bold())
                
                Text(session.domain)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            
            // Payment amount
            VStack(spacing: 4) {
                Text("\(session.amountSats)")
                    .font(.system(size: 48, weight: .bold, design: .rounded))
                    .foregroundStyle(
                        LinearGradient(colors: [.orange, .yellow], startPoint: .leading, endPoint: .trailing)
                    )
                
                Text("sats")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                
                if walletManager.btcPriceUsd > 0 {
                    Text("≈ \(walletManager.formatUsd(walletManager.satsToUsd(session.amountSats)))")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 24)
            
            // Session info
            VStack(spacing: 12) {
                SessionInfoRow(icon: "clock.fill", label: "Expires", value: session.expiryDescription)
                
                if session.requireMembership {
                    SessionInfoRow(icon: "person.badge.shield.checkmark.fill", label: "Membership", value: "Required")
                }
            }
            .padding()
            .background(Color(.secondarySystemBackground))
            .cornerRadius(16)
            .padding(.horizontal, 24)
            
            Spacer()
            
            // Action buttons
            VStack(spacing: 12) {
                Button {
                    Task {
                        await viewModel.login()
                    }
                } label: {
                    Label("Log In & Get Paid", systemImage: "bolt.fill")
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .frame(height: 56)
                        .background(
                            LinearGradient(colors: [.orange, .red], startPoint: .leading, endPoint: .trailing)
                        )
                        .cornerRadius(16)
                }
                
                Button("Cancel") {
                    viewModel.reset()
                }
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
        }
    }
    
    // MARK: - Processing View
    
    private var processingView: some View {
        VStack(spacing: 32) {
            Spacer()
            
            // Progress animation
            ZStack {
                Circle()
                    .stroke(Color.gray.opacity(0.2), lineWidth: 8)
                    .frame(width: 120, height: 120)
                
                Circle()
                    .trim(from: 0, to: progressValue)
                    .stroke(
                        LinearGradient(colors: [.orange, .red], startPoint: .topLeading, endPoint: .bottomTrailing),
                        style: StrokeStyle(lineWidth: 8, lineCap: .round)
                    )
                    .frame(width: 120, height: 120)
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 0.3), value: progressValue)
                
                VStack {
                    Image(systemName: progressIcon)
                        .font(.title)
                        .foregroundStyle(.orange)
                    
                    if viewModel.state == .waitingForPayment {
                        Text("⚡")
                            .font(.largeTitle)
                    }
                }
            }
            
            VStack(spacing: 8) {
                Text(viewModel.progress.rawValue)
                    .font(.headline)
                
                if let session = viewModel.session {
                    Text("Logging in to \(session.displayName)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            
            Spacer()
            
            // Cancel button (only before payment)
            if viewModel.state != .waitingForPayment {
                Button("Cancel") {
                    viewModel.reset()
                }
                .foregroundStyle(.secondary)
                .padding(.bottom, 32)
            }
        }
    }
    
    private var progressValue: CGFloat {
        switch viewModel.progress {
        case .none: return 0
        case .generatingProof: return 0.2
        case .generatingMembership: return 0.4
        case .creatingInvoice: return 0.5
        case .submitting: return 0.7
        case .waitingForPayment: return 0.9
        case .settlingDlc: return 0.95
        }
    }
    
    private var progressIcon: String {
        switch viewModel.progress {
        case .generatingProof, .generatingMembership: return "shield.fill"
        case .creatingInvoice: return "doc.fill"
        case .submitting: return "arrow.up.circle.fill"
        case .waitingForPayment: return "bolt.fill"
        case .settlingDlc: return "checkmark.seal.fill"
        default: return "circle.fill"
        }
    }
    
    // MARK: - Success View
    
    private func successView(sats: Int64) -> some View {
        VStack(spacing: 32) {
            Spacer()
            
            // Celebration
            ZStack {
                Circle()
                    .fill(Color.green.opacity(0.1))
                    .frame(width: 140, height: 140)
                
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 80))
                    .foregroundStyle(.green)
            }
            
            VStack(spacing: 8) {
                Text("You earned")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text("\(sats)")
                        .font(.system(size: 56, weight: .bold, design: .rounded))
                    Text("sats")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                }
                .foregroundStyle(
                    LinearGradient(colors: [.orange, .yellow], startPoint: .leading, endPoint: .trailing)
                )
                
                if walletManager.btcPriceUsd > 0 {
                    Text("≈ \(walletManager.formatUsd(walletManager.satsToUsd(sats)))")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
            
            if let session = viewModel.session {
                Text("Logged in to \(session.displayName)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            Button {
                viewModel.reset()
            } label: {
                Text("Done")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 56)
                    .background(Color.green)
                    .cornerRadius(16)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
        }
    }
    
    // MARK: - Error View
    
    private func errorView(message: String) -> some View {
        VStack(spacing: 24) {
            Spacer()
            
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 60))
                .foregroundStyle(.red)
            
            VStack(spacing: 8) {
                Text("Login Failed")
                    .font(.title2.bold())
                
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            
            Spacer()
            
            VStack(spacing: 12) {
                Button {
                    if viewModel.session != nil {
                        Task {
                            await viewModel.login()
                        }
                    } else {
                        viewModel.startScan()
                    }
                } label: {
                    Text("Try Again")
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .frame(height: 56)
                        .background(Color.blue)
                        .cornerRadius(16)
                }
                
                Button("Cancel") {
                    viewModel.reset()
                }
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
        }
    }
}

// MARK: - Session Info Row

struct SessionInfoRow: View {
    let icon: String
    let label: String
    let value: String
    
    var body: some View {
        HStack {
            Image(systemName: icon)
                .foregroundStyle(.secondary)
                .frame(width: 24)
            
            Text(label)
                .foregroundStyle(.secondary)
            
            Spacer()
            
            Text(value)
                .fontWeight(.medium)
        }
    }
}

// MARK: - Backup Prompt Sheet

struct BackupPromptSheet: View {
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 60))
                    .foregroundStyle(.orange)
                
                Text("Back Up Your Wallet")
                    .font(.title2.bold())
                
                Text("You just earned your first sats! Make sure to back up your wallet to protect your funds.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                
                Spacer()
                
                VStack(spacing: 12) {
                    NavigationLink {
                        RecoveryPhraseView()
                    } label: {
                        Text("Back Up Now")
                            .font(.headline)
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .frame(height: 50)
                            .background(Color.blue)
                            .cornerRadius(12)
                    }
                    
                    Button("Remind Me Later") {
                        dismiss()
                    }
                    .foregroundStyle(.secondary)
                }
            }
            .padding()
            .navigationTitle("Important")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Skip") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium])
    }
}

// MARK: - Preview

#Preview {
    LoginView()
        .environmentObject(LoginViewModel())
        .environmentObject(BreezWalletManager())
}
