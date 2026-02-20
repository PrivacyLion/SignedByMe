// OnboardingContainerView.swift - Onboarding Flow Container
// SignedByMe iOS

import SwiftUI

struct OnboardingContainerView: View {
    @EnvironmentObject var viewModel: OnboardingViewModel
    
    var body: some View {
        ZStack {
            // Background gradient
            LinearGradient(
                colors: [
                    Color(red: 0.97, green: 0.98, blue: 1.0),
                    Color(red: 0.94, green: 0.96, blue: 0.99),
                    Color(red: 0.90, green: 0.94, blue: 0.98)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()
            
            VStack(spacing: 0) {
                // Progress indicator
                OnboardingProgressView(currentStep: viewModel.currentStep)
                    .padding(.top, 16)
                    .padding(.horizontal, 24)
                
                // Content
                TabView(selection: $viewModel.currentStep) {
                    WelcomeView()
                        .tag(OnboardingStep.welcome)
                    
                    WalletSetupView()
                        .tag(OnboardingStep.wallet)
                    
                    IdentitySetupView()
                        .tag(OnboardingStep.identity)
                }
                .tabViewStyle(.page(indexDisplayMode: .never))
                .animation(.easeInOut, value: viewModel.currentStep)
            }
        }
        .preferredColorScheme(.light)
    }
}

// MARK: - Progress View

struct OnboardingProgressView: View {
    let currentStep: OnboardingStep
    
    var body: some View {
        HStack(spacing: 8) {
            ForEach(OnboardingStep.allCases.filter { $0 != .complete }, id: \.self) { step in
                Capsule()
                    .fill(step.rawValue <= currentStep.rawValue ? Color.blue : Color.gray.opacity(0.3))
                    .frame(height: 4)
            }
        }
    }
}

// MARK: - Welcome View

struct WelcomeView: View {
    @EnvironmentObject var viewModel: OnboardingViewModel
    
    var body: some View {
        VStack(spacing: 32) {
            Spacer()
            
            // Logo / Icon
            Image(systemName: "bitcoinsign.circle.fill")
                .font(.system(size: 80))
                .foregroundStyle(
                    LinearGradient(colors: [.orange, .yellow], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .shadow(color: .orange.opacity(0.3), radius: 20)
            
            // Title
            VStack(spacing: 12) {
                Text("SignedByMe")
                    .font(.system(size: 42, weight: .bold))
                    .foregroundStyle(
                        LinearGradient(colors: [.blue, .purple], startPoint: .leading, endPoint: .trailing)
                    )
                
                Text("Get paid to Log In")
                    .font(.title2)
                    .foregroundStyle(.secondary)
            }
            
            // Features
            VStack(alignment: .leading, spacing: 16) {
                FeatureRow(icon: "key.fill", title: "Own Your Identity", subtitle: "Decentralized, secure, private")
                FeatureRow(icon: "bolt.fill", title: "Earn Sats", subtitle: "Get paid every time you log in")
                FeatureRow(icon: "lock.shield.fill", title: "Zero-Knowledge", subtitle: "Prove without revealing")
            }
            .padding(.horizontal, 32)
            .padding(.top, 24)
            
            Spacer()
            
            // Get Started button
            Button {
                viewModel.startOnboarding()
            } label: {
                Text("Get Started")
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
}

struct FeatureRow: View {
    let icon: String
    let title: String
    let subtitle: String
    
    var body: some View {
        HStack(spacing: 16) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(.blue)
                .frame(width: 40, height: 40)
                .background(Color.blue.opacity(0.1))
                .cornerRadius(10)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.headline)
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Preview

#Preview {
    OnboardingContainerView()
        .environmentObject(OnboardingViewModel())
}
