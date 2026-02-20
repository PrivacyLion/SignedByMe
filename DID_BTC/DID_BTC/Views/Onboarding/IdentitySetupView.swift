// IdentitySetupView.swift - Step 3: Identity & STWO Proof
// SignedByMe iOS

import SwiftUI

struct IdentitySetupView: View {
    @EnvironmentObject var viewModel: OnboardingViewModel
    
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Header
                VStack(spacing: 8) {
                    stepBadge(number: 3)
                    Text("Verify Identity")
                        .font(.title.bold())
                    Text("Create your decentralized identity and generate a zero-knowledge proof")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(.top, 24)
                
                if viewModel.identityProgress == .complete {
                    completionView
                } else if viewModel.isLoading {
                    progressView
                } else {
                    setupView
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
    
    // MARK: - Setup View
    
    private var setupView: some View {
        VStack(spacing: 24) {
            // What happens
            VStack(alignment: .leading, spacing: 16) {
                Text("What happens next:")
                    .font(.headline)
                
                SetupStepRow(
                    number: 1,
                    title: "Create DID",
                    subtitle: "Your decentralized identifier",
                    isComplete: false,
                    isActive: true
                )
                
                SetupStepRow(
                    number: 2,
                    title: "Generate STWO Proof",
                    subtitle: "Zero-knowledge proof binding identity to wallet",
                    isComplete: false,
                    isActive: false
                )
                
                SetupStepRow(
                    number: 3,
                    title: "Enroll Membership",
                    subtitle: "Join the verification network",
                    isComplete: false,
                    isActive: false
                )
                
                SetupStepRow(
                    number: 4,
                    title: "Fetch Witness",
                    subtitle: "Get your membership proof data",
                    isComplete: false,
                    isActive: false
                )
            }
            .padding()
            .background(Color(.secondarySystemBackground))
            .cornerRadius(16)
            
            // Real STWO badge
            if NativeBridge.hasRealStwo() {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                    Text("Real Circle STARK proofs enabled")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(12)
                .background(Color.green.opacity(0.1))
                .cornerRadius(8)
            }
            
            // Start button
            Button {
                Task {
                    await viewModel.setupIdentity()
                }
            } label: {
                Text("Create Identity")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 56)
                    .background(
                        LinearGradient(colors: [.orange, .red], startPoint: .leading, endPoint: .trailing)
                    )
                    .cornerRadius(16)
            }
        }
        .padding(.top, 16)
    }
    
    // MARK: - Progress View
    
    private var progressView: some View {
        VStack(spacing: 32) {
            // Animated progress circle
            ZStack {
                Circle()
                    .stroke(Color.gray.opacity(0.2), lineWidth: 8)
                    .frame(width: 100, height: 100)
                
                Circle()
                    .trim(from: 0, to: progressValue)
                    .stroke(
                        LinearGradient(colors: [.orange, .red], startPoint: .topLeading, endPoint: .bottomTrailing),
                        style: StrokeStyle(lineWidth: 8, lineCap: .round)
                    )
                    .frame(width: 100, height: 100)
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 0.5), value: progressValue)
                
                if viewModel.identityProgress == .complete {
                    Image(systemName: "checkmark")
                        .font(.largeTitle.bold())
                        .foregroundStyle(.green)
                } else {
                    ProgressView()
                        .scaleEffect(1.5)
                }
            }
            
            Text(viewModel.identityProgress.rawValue)
                .font(.headline)
                .foregroundStyle(.secondary)
            
            // Step status
            VStack(alignment: .leading, spacing: 12) {
                SetupStepRow(
                    number: 1,
                    title: "Create DID",
                    subtitle: "Your decentralized identifier",
                    isComplete: viewModel.identityProgress.rawValue != OnboardingViewModel.IdentitySetupProgress.creatingDID.rawValue,
                    isActive: viewModel.identityProgress == .creatingDID
                )
                
                SetupStepRow(
                    number: 2,
                    title: "Generate STWO Proof",
                    subtitle: "Zero-knowledge proof",
                    isComplete: viewModel.stwoProofGenerated,
                    isActive: viewModel.identityProgress == .generatingProof
                )
                
                SetupStepRow(
                    number: 3,
                    title: "Enroll Membership",
                    subtitle: "Join the network",
                    isComplete: viewModel.membershipEnrolled,
                    isActive: viewModel.identityProgress == .enrollingMembership
                )
                
                SetupStepRow(
                    number: 4,
                    title: "Fetch Witness",
                    subtitle: "Get membership data",
                    isComplete: viewModel.witnessLoaded,
                    isActive: viewModel.identityProgress == .fetchingWitness
                )
            }
            .padding()
            .background(Color(.secondarySystemBackground))
            .cornerRadius(16)
        }
        .padding(.top, 32)
    }
    
    // MARK: - Completion View
    
    private var completionView: some View {
        VStack(spacing: 24) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 80))
                .foregroundStyle(.green)
            
            Text("You're All Set!")
                .font(.title.bold())
            
            Text("Your identity has been created and verified. You're ready to start getting paid to log in!")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            
            // Summary
            VStack(alignment: .leading, spacing: 12) {
                CompletionRow(icon: "key.fill", title: "DID Created", color: .blue)
                CompletionRow(icon: "shield.fill", title: "STWO Proof Generated", color: .orange)
                CompletionRow(icon: "person.badge.shield.checkmark.fill", title: "Membership Enrolled", color: .green)
                CompletionRow(icon: "doc.badge.gearshape.fill", title: "Witness Loaded", color: .purple)
            }
            .padding()
            .background(Color(.secondarySystemBackground))
            .cornerRadius(16)
            
            Button {
                viewModel.finishOnboarding()
            } label: {
                Text("Start Using SignedByMe")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 56)
                    .background(
                        LinearGradient(colors: [.green, .mint], startPoint: .leading, endPoint: .trailing)
                    )
                    .cornerRadius(16)
            }
        }
        .padding(.top, 32)
    }
    
    // MARK: - Helpers
    
    private var progressValue: CGFloat {
        switch viewModel.identityProgress {
        case .notStarted: return 0
        case .creatingDID: return 0.25
        case .generatingProof: return 0.5
        case .enrollingMembership: return 0.75
        case .fetchingWitness: return 0.9
        case .complete: return 1.0
        }
    }
    
    private func stepBadge(number: Int) -> some View {
        Text("\(number)")
            .font(.headline)
            .foregroundColor(.white)
            .frame(width: 36, height: 36)
            .background(
                LinearGradient(colors: [.orange, .red], startPoint: .topLeading, endPoint: .bottomTrailing)
            )
            .clipShape(Circle())
    }
}

// MARK: - Setup Step Row

struct SetupStepRow: View {
    let number: Int
    let title: String
    let subtitle: String
    let isComplete: Bool
    let isActive: Bool
    
    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(backgroundColor)
                    .frame(width: 32, height: 32)
                
                if isComplete {
                    Image(systemName: "checkmark")
                        .font(.caption.bold())
                        .foregroundStyle(.white)
                } else if isActive {
                    ProgressView()
                        .scaleEffect(0.7)
                        .tint(.white)
                } else {
                    Text("\(number)")
                        .font(.caption.bold())
                        .foregroundStyle(.white)
                }
            }
            
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.bold())
                    .foregroundStyle(isComplete || isActive ? .primary : .secondary)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
        }
    }
    
    private var backgroundColor: Color {
        if isComplete { return .green }
        if isActive { return .blue }
        return .gray.opacity(0.4)
    }
}

// MARK: - Completion Row

struct CompletionRow: View {
    let icon: String
    let title: String
    let color: Color
    
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .frame(width: 24)
            
            Text(title)
                .font(.subheadline)
            
            Spacer()
            
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
        }
    }
}

// MARK: - Preview

#Preview {
    IdentitySetupView()
        .environmentObject(OnboardingViewModel())
}
