// File: ContentView.swift
import SwiftUI
import UIKit
import CoreImage
import CoreImage.CIFilterBuiltins

@main
struct BTCDIDAuthApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @StateObject private var didManager = DIDWalletManager()
    @State private var claimResult: String = "No claim yet"
    @State private var nonce: String = "SampleNonce123"
    @State private var withdrawTo: String = "lnbc1..."
    @State private var isLoading: Bool = false
    @State private var showIDSheet = false
    private let showZKDevControls = false
    @State private var showCopiedToast = false
    
    // States for advanced features
    @State private var inputHash: String = "input_hash"
    @State private var outputHash: String = "output_hash"
    @State private var circuit: String = "hash_integrity"
    @State private var proofResult: String = "No proof yet"
    @State private var vccContentURL: String = "https://example.com/content"
    @State private var vccLnAddress: String = "ln@address.com"
    @State private var vccResult: String = "No VCC yet"
    @State private var dlcOutcome: String = "auth_verified"
    @State private var dlcResult: String = "No DLC yet"
    @State private var dlcSignatureResult: String = "No DLC signature yet"
    @State private var showStep2Alert = false
    @State private var paymentResult: String = "No payment yet"
    @State private var showFullVCC = false
    @State private var showFullPayment = false
    @State private var unlockTokenResult: String = "No unlock token yet"
    
    // Wallet selection states
    @State private var selectedWalletType: WalletType?
    @State private var lightningAddress: String = ""
    @State private var custodialUsername: String = ""
    @State private var breezSetup: String = ""
    @State private var showQRScanner = false
    @State private var showOtherWallets = false
    @State private var showCustodialPicker = false
    @State private var showNonCustodialPicker = false
    @State private var chosenCustodial: String? = nil
    @State private var chosenNonCustodial: String? = nil
    @State private var connectError: String? = nil
    
    // Step completion tracking
    @State private var step1Complete = false
    @State private var step2Complete = false
    @State private var step3Complete = false
    
    // Add this debug line:
    init() { print("🟡 isLoading initial state: \(isLoading)") }
    
    var body: some View {
        print("🟡 ContentView body is rendering")
        return ZStack {
            // Clean gradient background
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
            
            ScrollView(showsIndicators: false) {
                VStack(spacing: 32) {
                    // Header
                    headerSection
                    
                    // Step 1: Create
                    stepCard(
                        stepNumber: 1,
                        title: "Create",
                        subtitle: "",
                        isComplete: step1Complete,
                        isEnabled: true
                    ) {
                        step1Content
                    }
                    
                    // Step 2: Connect
                    stepCard(
                        stepNumber: 2,
                        title: "Connect",
                        subtitle: "",
                        isComplete: step2Complete,
                        isEnabled: step1Complete
                    ) {
                        step2Content
                    }
                    
                    // Step 3: Prove
                    stepCard(
                        stepNumber: 3,
                        title: "Prove",
                        subtitle: "",
                        isComplete: step3Complete,
                        isEnabled: step1Complete && hasStep2Info()
                    ) {
                        step3Content
                    }
                    
                    Spacer(minLength: 60)
                }
                .padding(.horizontal, 24)
                .padding(.top, 20)
            }
        }
        .overlay(alignment: .bottom) {
            if showCopiedToast {
                Text("Copied")
                    .font(.footnote.weight(.semibold))
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(Capsule().fill(.ultraThinMaterial))
                    .shadow(radius: 6)
                    .padding(.bottom, 18)
            }
        }
        .preferredColorScheme(.light)
        .onAppear {
            checkExistingSetup()
        }
        
        .confirmationDialog(
            "Choose a custodial wallet",
            isPresented: $showCustodialPicker,
            titleVisibility: .visible
        ) {
            Button("Coinbase") {
                selectedWalletType = .custodial
                chosenCustodial = "Coinbase"
            }
            Button("Binance") {
                selectedWalletType = .custodial
                chosenCustodial = "Binance"
            }
            Button("Strike") {
                selectedWalletType = .custodial
                chosenCustodial = "Strike"
            }
            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog(
            "Choose a non-custodial wallet",
            isPresented: $showNonCustodialPicker,
            titleVisibility: .visible
        ) {
            Button("Breez (Embedded)") {
                selectedWalletType = .embedded
                chosenNonCustodial = "Breez"
                step2Complete = true
            }
            Button("Lightning (Phoenix/Zeus)") {
                selectedWalletType = .lightning
                chosenNonCustodial = "Lightning"
            }
            Button("Cancel", role: .cancel) {}
        }
        
        .sheet(isPresented: $showQRScanner) {
            QRPayDestinationScanner(
                onResult: { dest in
                    switch dest {
                    case .onChain(let address, _):
                        if selectedWalletType == .lightning { lightningAddress = address }
                        else { custodialUsername = address }
                    case .lightningInvoice(let invoice):
                        if selectedWalletType == .lightning { lightningAddress = invoice }
                        else { custodialUsername = invoice }
                    case .lnurl(let lnurl):
                        if selectedWalletType == .lightning { lightningAddress = lnurl }
                        else { custodialUsername = lnurl }
                    case .lightningAddress(let addr):
                        if selectedWalletType == .lightning { lightningAddress = addr }
                        else { custodialUsername = addr }
                    }
                    step2Complete = true
                    showQRScanner = false
                },
                onCancel: { showQRScanner = false }
            )
        }
        
        .sheet(isPresented: $showIDSheet) {
            let full = didManager.publicDID ?? "Unavailable"
            let qr   = makeQRCode(full)
            
            VStack(spacing: 16) {
                Text("Your Signature")
                    .font(.title3)
                    .fontWeight(.semibold)
                
                if let qr {
                    Image(uiImage: qr)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 200, height: 200)
                        .padding(.bottom, 4)
                }
                
                Text(truncatedDID(full))
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
                    .monospaced()
                
                ScrollView {
                    Text(full)
                        .font(.footnote)
                        .textSelection(.enabled)
                        .monospaced()
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 120)
                
                HStack(spacing: 12) {
                    Button {
                        UIPasteboard.general.string = full
                    } label: {
                        Label("Copy ID", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.bordered)
                    
                    Button(role: .destructive) {
                        regenerateKeyPair()
                        showIDSheet = false
                    } label: {
                        Label("Regenerate", systemImage: "arrow.clockwise.circle")
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
            .padding()
            .presentationDetents([.medium, .large])
        }
    }
    
    // MARK: - Header Section
    private var headerSection: some View {
        VStack(spacing: 16) {
            Text("SignedByMe")
                .font(.system(size: 36, weight: .bold))
                .foregroundStyle(
                    LinearGradient(colors: [.blue, .purple], startPoint: .leading, endPoint: .trailing)
                )
        }
    }
    
    // MARK: - Step Card Builder
    private func stepCard<Content: View>(
        stepNumber: Int,
        title: String,
        subtitle: String,
        isComplete: Bool,
        isEnabled: Bool,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(spacing: 0) {
            // Step header
            HStack(alignment: .center, spacing: 16) {
                ZStack {
                    Circle()
                        .fill(stepBackgroundColor(isComplete: isComplete, isEnabled: isEnabled))
                        .frame(width: 60, height: 60)
                        .shadow(color: stepShadowColor(isComplete: isComplete, isEnabled: isEnabled), radius: 8, x: 0, y: 4)
                    
                    if isComplete {
                        Image(systemName: "checkmark")
                            .font(.system(size: 24, weight: .bold))
                            .foregroundColor(.white)
                    } else {
                        Text("\(stepNumber)")
                            .font(.system(size: 24, weight: .bold))
                            .foregroundColor(isEnabled ? .white : .gray)
                    }
                }
                
                VStack(alignment: .center, spacing: 4) {
                    Text(title)
                        .font(.system(size: 28, weight: .bold))
                        .foregroundColor(isEnabled ? .primary : .gray)
                        .baselineOffset(-13)
                    
                    Text(subtitle)
                        .font(.system(size: 18))
                        .foregroundColor(.secondary)
                }
                
                Spacer()
            }
            .padding(.horizontal, 24)
            .padding(.top, 24)
            
            // Step content
            if isEnabled || isComplete {
                content()
                    .padding(.horizontal, 24)
                    .padding(.bottom, 24)
                    .padding(.top, 20)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 24)
                .fill(.ultraThinMaterial)
                .shadow(color: .black.opacity(isEnabled ? 0.08 : 0.03), radius: 15, x: 0, y: 8)
        )
        .opacity(isEnabled ? 1.0 : 0.6)
    }
    
    // MARK: - Step 1 Content (Identity Creation)
    private var step1Content: some View {
        VStack(spacing: 20) {
            if !step1Complete {
                VStack(spacing: 16) {
                    Text("To Create a Signature press the button below.")
                        .font(.system(size: 16))
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                    
                    bigActionButton(
                        title: "Generate",
                        icon: "plus.circle.fill",
                        colors: [.blue, .purple]
                    ) {
                        generateKeyPair()
                    }
                    
                    if didManager.publicDID != nil {
                        bigActionButton(
                            title: "Regenerate",
                            icon: "arrow.clockwise.circle.fill",
                            colors: [.orange, .red]
                        ) {
                            regenerateKeyPair()
                        }
                    }
                }
            } else {
                completedStepView(
                    title: "Success!",
                    details: "  ",
                    resetAction: {
                        step1Complete = false
                        step2Complete = false
                        step3Complete = false
                    },
                    resetLabel: "Reset Signature",
                    showInfo: true
                )
            }
        }
    }
    
    // MARK: - Step 2 Content (Connect Wallet) — Cash App first
    private var step2Content: some View {
        VStack(spacing: 20) {
            
            if !step2Complete {
                VStack(spacing: 16) {
                    
                    Text("Pick an option to Connect")
                    
                    HStack {
                        Spacer()
                        startOverChip()   // stays green with a circled icon
                    }
                    
                    .font(.body)
                    .foregroundColor(.primary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    
                    // Show an error (if you set one) and give a retry
                    if let err = connectError {
                        resultCard(title: "Connection failed", content: err)
                        Button("Try again") { resetConnectStep() }
                            .font(.footnote)
                            .foregroundColor(.secondary)
                    }
                    
                    // CASH APP QUICK PATH
                    VStack(spacing: 12) {
                        HStack {
                            Image(systemName: "bolt.badge.a")
                                .font(.title2)
                                .foregroundColor(.green)
                            Text("Cash App")
                                .font(.title3).fontWeight(.semibold)
                            levelPill("easy", color: .green)
                                .scaleEffect(1.15)
                                .padding(.leading, 6)
                            Spacer()
                            
                        }
                        
                        Text("Open Cash App → Bitcoin → Deposit → show QR. Scan it or paste the address.")
                            .font(.footnote)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.leading)
                        
                        HStack(spacing: 12) {
                            Button {
                                selectedWalletType = .custodial
                                showQRScanner = true
                            } label: {
                                Label("Scan QR", systemImage: "qrcode.viewfinder")
                                    .frame(maxWidth: .infinity)
                                    .padding()
                                    .background(Color.blue)
                                    .foregroundColor(.white)
                                    .cornerRadius(12)
                            }
                            
                            Button {
                                selectedWalletType = .custodial
                                if let clip = UIPasteboard.general.string, !clip.isEmpty {
                                    custodialUsername = clip
                                    step2Complete = true
                                }
                            } label: {
                                Label("Paste", systemImage: "doc.on.clipboard")
                                    .frame(maxWidth: .infinity)
                                    .padding()
                                    .background(Color.gray.opacity(0.2))
                                    .foregroundColor(.primary)
                                    .cornerRadius(12)
                            }
                        }
                        
                        if !custodialUsername.isEmpty && selectedWalletType == .custodial {
                            inputField(
                                title: "Withdraw To (detected)",
                                placeholder: "bc1… or lnbc1…",
                                text: $custodialUsername
                            )
                        }
                    }
                    .padding(16)
                    .background(RoundedRectangle(cornerRadius: 16).fill(.ultraThinMaterial))
                    
                    // TWO EQUAL CTA BUTTONS
                    VStack(spacing: 12) {
                        // 1) Custodial button → pick Coinbase/Binance/Strike
                        bigActionButton(
                            title: "Custodial Wallet",
                            pillText: "intermediate",
                            colors: [.blue, .purple]
                        ) {
                            showCustodialPicker = true
                        }
                        
                        if let c = chosenCustodial, selectedWalletType == .custodial {
                            Text("Selected: \(c)")
                                .font(.footnote)
                                .foregroundColor(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        
                        if selectedWalletType == .custodial {
                            HStack(spacing: 12) {
                                Button {
                                    showQRScanner = true
                                } label: {
                                    Label("Scan QR", systemImage: "qrcode.viewfinder")
                                        .frame(maxWidth: .infinity)
                                        .padding()
                                        .background(Color.blue)
                                        .foregroundColor(.white)
                                        .cornerRadius(12)
                                }
                                Button {
                                    if let clip = UIPasteboard.general.string, !clip.isEmpty {
                                        custodialUsername = clip
                                    }
                                } label: {
                                    Label("Paste", systemImage: "doc.on.clipboard")
                                        .frame(maxWidth: .infinity)
                                        .padding()
                                        .background(Color.gray.opacity(0.2))
                                        .foregroundColor(.primary)
                                        .cornerRadius(12)
                                }
                            }
                            
                            if !custodialUsername.isEmpty {
                                inputField(
                                    title: "Withdraw To",
                                    placeholder: "bc1… or lnbc1…",
                                    text: $custodialUsername
                                )
                            }
                        }
                        
                        // 2) Non-custodial button → pick Breez/LN
                        bigActionButton(
                            title: "Non-Custodial Wallet",
                            pillText: "hard",
                            colors: [.indigo, .purple]
                        ) {
                            showNonCustodialPicker = true
                        }
                        
                        if let nc = chosenNonCustodial {
                            Text("Selected: \(nc)")
                                .font(.footnote)
                                .foregroundColor(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        
                        if selectedWalletType == .embedded {
                            Text("Set up Breez on this device. Seed words are generated locally — back them up.")
                                .font(.footnote)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.leading)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        
                        if selectedWalletType == .lightning {
                            HStack(spacing: 12) {
                                Button {
                                    showQRScanner = true
                                } label: {
                                    Label("Scan QR", systemImage: "qrcode.viewfinder")
                                        .frame(maxWidth: .infinity)
                                        .padding()
                                        .background(Color.blue)
                                        .foregroundColor(.white)
                                        .cornerRadius(12)
                                }
                                Button {
                                    if let clip = UIPasteboard.general.string, !clip.isEmpty {
                                        lightningAddress = clip
                                    }
                                } label: {
                                    Label("Paste", systemImage: "doc.on.clipboard")
                                        .frame(maxWidth: .infinity)
                                        .padding()
                                        .background(Color.gray.opacity(0.2))
                                        .foregroundColor(.primary)
                                        .cornerRadius(12)
                                }
                            }
                            
                            inputField(
                                title: "Lightning Address / Invoice",
                                placeholder: "user@domain or lnbc1…",
                                text: $lightningAddress
                            )
                        }
                    }
                }
                
            } else {
                VStack(spacing: 12) {
                    HStack {
                        Spacer()
                        startOverChip(title: "Start over") { resetConnectStep() } // ✅ shows after connect too
                    }
                    
                    completedStepView(
                        title: "Wallet Connected!",
                        details: getConnectedWalletDetails(),
                        resetAction: {
                            step2Complete = false
                            step3Complete = false
                            selectedWalletType = nil
                            lightningAddress = ""
                            custodialUsername = ""
                            breezSetup = ""
                        },
                        resetLabel: "Change Wallet"
                    )
                }
            }
        }
    }
    
    private var connectDisabled: Bool {
        let w = selectedWalletType ?? .custodial
        switch w {
        case .embedded:
            return false
        case .custodial:
            return custodialUsername.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .lightning:
            return lightningAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }
    
    // MARK: - Step 3 Content (Authentication)
    private var step3Content: some View {
        VStack(alignment: .center, spacing: 16) {
            Text("Press the button below to Prove your Signature and create your Verified Content Claim")
                .font(.system(size: 16))
                .foregroundColor(.primary)
                .kerning(0)
                .lineSpacing(2)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.top, 4)
            
            featureCard {
                VStack(spacing: 16) {
                    
                    // DEV-ONLY inputs (hidden for users)
                    if showZKDevControls {
                        inputField(title: "Input Hash",  placeholder: "input_hash",     text: $inputHash)
                        inputField(title: "Output Hash", placeholder: "output_hash",    text: $outputHash)
                        inputField(title: "Circuit",     placeholder: "hash_integrity", text: $circuit)
                    }
                    
                    // SINGLE atomic action
                    bigActionButton(
                        title: "Generate Proof",
                        colors: [.red, .orange]
                    ) { proveAndGenerateVCC() }
                    
                    // DEV-ONLY: show proof details
                    if showZKDevControls, proofResult != "No proof yet" {
                        resultCard(title: "Proof Result", content: proofResult)
                    }
                    
                    // USER: show VCC (preview = also what gets copied/shared)
                    if vccResult != "No VCC yet" {
                        VStack(alignment: .leading, spacing: 12) {
                            
                            // ✅ Header pill — matches "Payment Completed"
                            statusPill("Verified Content Claim")
                            
                            // PREVIEW (tap to copy the SAME text)
                            Text(vccShortJSON)
                                .font(.system(.callout, design: .monospaced))
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                                .truncationMode(.tail)
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(
                                    RoundedRectangle(cornerRadius: 12)
                                        .fill(Color(.secondarySystemBackground))
                                )
                                .onTapGesture { copyVCCToClipboard() }
                                .contextMenu {
                                    Button("Copy full JSON") {
#if canImport(UIKit)
                                        UIPasteboard.general.string = vccResult
#endif
                                    }
                                }
                            
                            HStack(spacing: 12) {
                                Button { copyVCCToClipboard() } label: {
                                    Label("Copy", systemImage: "doc.on.doc")
                                        .frame(maxWidth: .infinity)
                                }
                                .buttonStyle(.bordered)
                                
                                if #available(iOS 16.0, *) {
                                    ShareLink(item: vccShortJSON) {
                                        Label("Share", systemImage: "square.and.arrow.up")
                                            .frame(maxWidth: .infinity)
                                    }
                                    .buttonStyle(.bordered)
                                }
                            }
                            
                            // Full JSON (collapsed by default)
                            DisclosureGroup(showFullVCC ? "Hide full JSON" : "Show full JSON", isExpanded: $showFullVCC) {
                                ScrollView {
                                    Text(vccResult)
                                        .font(.system(.footnote, design: .monospaced))
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .frame(maxHeight: 140)
                            }
                            
                            // Payment pill + “Show full Payment”
                            if paymentResult != "No payment yet" {
                                paymentSummaryCard
                                paymentDetailsDisclosure
                            }
                        }
                    }
                }
            }
        }
        .alert("Complete Step 2", isPresented: $showStep2Alert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Please connect a wallet in Step 2 before proving.")
        }
    }
    
    // MARK: - Helper Views (unchanged from your file)
    private func bigActionButton(
        title: String,
        icon: String? = nil,
        pillText: String? = nil,
        colors: [Color],
        minHeight: CGFloat = 56,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 10) {
                if let icon, !icon.isEmpty {
                    Image(systemName: icon).font(.headline)
                }
                Text(title)
                    .font(.system(size: 16, weight: .semibold))
                    .multilineTextAlignment(.center)
                    .lineLimit(2)
                    .minimumScaleFactor(0.95)
                
                if let pill = pillText {
                    levelPill(pill, color: .green)
                }
            }
            .foregroundColor(.white)
            .frame(maxWidth: .infinity, minHeight: minHeight)
            .padding(.horizontal, 12)
            .background(LinearGradient(colors: colors, startPoint: .leading, endPoint: .trailing))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .shadow(color: colors.first?.opacity(0.28) ?? .clear, radius: 10, x: 0, y: 5)
        }
    }
    
    private func inputField(title: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 16, weight: .medium)).foregroundColor(.primary)
            TextField(placeholder, text: text)
                .font(.system(size: 16))
                .padding(16)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(.background.opacity(0.7))
                        .stroke(.gray.opacity(0.2), lineWidth: 1)
                )
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        }
    }
    
    private func completedStepView(
        title: String,
        details: String,
        resetAction: @escaping () -> Void,
        resetLabel: String,
        showInfo: Bool = false
    ) -> some View {
        // Fallback so the box never looks empty
        let safeDetails = details.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        ? "Tap (i) to view your Signature"
        : details
        
        return VStack(spacing: 12) {
            HStack(spacing: 8) {
                Text(safeDetails)
                    .font(.system(size: 14, design: .monospaced))
                    .foregroundColor(.primary)
                Spacer()
                if showInfo {
                    Button { showIDSheet = true } label: {
                        Image(systemName: "info.circle")
                            .font(.body)
                    }
                    .buttonStyle(.plain)
                    .foregroundColor(.blue)
                }
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(.background.opacity(0.7))
                    .stroke(.gray.opacity(0.2), lineWidth: 1)
            )
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    
    private func featureCard<Content: View>(
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            content()
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(.ultraThinMaterial)
                .shadow(color: .black.opacity(0.05), radius: 12, x: 0, y: 6)
        )
    }
    
    private func resultCard(title: String, content: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
            Text(content)
                .font(.body)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12).fill(Color(.secondarySystemBackground)))
        .shadow(radius: 1)
    }
    
    private func statusPill(_ title: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundColor(.green)
            Text(title)
                .font(.headline).fontWeight(.semibold)
                .foregroundColor(.primary)
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        // Force identical bright white card in light mode (avoids material tint)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.white)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color.black.opacity(0.10), lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.06), radius: 4, x: 0, y: 1)
    }
    
    private var paymentSummaryCard: some View {
        statusPill("Payment Completed")
    }
    
    private var paymentDetailsDisclosure: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut) { showFullPayment.toggle() }
            } label: {
                HStack {
                    Text(showFullPayment ? "Hide full Payment" : "Show full Payment")
                        .font(.body)
                        .foregroundColor(.blue)
                    Spacer()
                    Image(systemName: "chevron.right")
                        .rotationEffect(.degrees(showFullPayment ? 90 : 0))
                        .font(.subheadline.weight(.semibold)) // between footnote and callout
                        .imageScale(.medium)                  // same scale as the top one
                        .foregroundColor(.primary)
                }
                .padding(.vertical, 2)
            }
            
            if showFullPayment {
                ScrollView {
                    Text(paymentResult)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundColor(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 6)
                }
                .frame(maxHeight: 140)
            }
        }
    }
    
    private func startOverChip(
        title: String = "Start over",
        action: (() -> Void)? = nil
    ) -> some View {
        Button(action: action ?? startOver) {
            HStack(spacing: 6) {
                Image(systemName: "arrow.counterclockwise")
                    .font(.caption.bold())
                    .frame(width: 22, height: 22)
                    .background(Circle().fill(Color.green.opacity(0.12)))
                    .overlay(Circle().stroke(Color.green.opacity(0.45), lineWidth: 1))
                Text(title)
                    .font(.footnote.weight(.semibold))
            }
            .foregroundColor(.green)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Capsule().fill(Color.green.opacity(0.08)))
        }
    }
    
    private func levelPill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.footnote).fontWeight(.semibold)
            .padding(.vertical, 5)
            .padding(.horizontal, 10)
            .background(color.opacity(0.14))
            .foregroundColor(color)
            .clipShape(Capsule())
    }
    
    // Reset Step 2 state
    private func startOver() {
        selectedWalletType = nil
        lightningAddress = ""
        custodialUsername = ""
        breezSetup = ""
        step2Complete = false
    }
    
    // Small green chip with a circular icon
    private func startOverChip(title: String = "Start over") -> some View {
        Button(action: startOver) {
            HStack(spacing: 6) {
                Image(systemName: "arrow.counterclockwise")
                    .font(.caption.bold())
                    .frame(width: 22, height: 22)
                    .background(Circle().fill(Color.green.opacity(0.12)))
                    .overlay(Circle().stroke(Color.green.opacity(0.45), lineWidth: 1))
                Text(title)
                    .font(.footnote.weight(.semibold))
            }
            .foregroundColor(.green)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Capsule().fill(Color.green.opacity(0.10)))
        }
        .buttonStyle(.plain)
    }
    
    private func walletTypeButton(
        title: String,
        subtitle: String,
        icon: String,
        walletType: WalletType,
        isSelected: Bool
    ) -> some View {
        Button(action: { selectedWalletType = walletType }) {
            HStack(spacing: 16) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(isSelected ? Color.blue.opacity(0.2) : Color.gray.opacity(0.1))
                        .frame(width: 50, height: 50)
                    Image(systemName: icon)
                        .font(.title2)
                        .foregroundColor(isSelected ? .blue : .gray)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.headline).fontWeight(.semibold).foregroundColor(.primary)
                    Text(subtitle).font(.subheadline).foregroundColor(.secondary)
                }
                Spacer()
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .font(.title2)
                    .foregroundColor(isSelected ? .blue : .gray)
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(.ultraThinMaterial)
                    .stroke(isSelected ? .blue.opacity(0.5) : .clear, lineWidth: 2)
            )
        }
        .buttonStyle(PlainButtonStyle())
    }
    
    // MARK: - Helper Functions
    private func stepBackgroundColor(isComplete: Bool, isEnabled: Bool) -> LinearGradient {
        if isComplete {
            return LinearGradient(colors: [.green, .mint], startPoint: .topLeading, endPoint: .bottomTrailing)
        } else if isEnabled {
            return LinearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing)
        } else {
            return LinearGradient(colors: [.gray, .gray], startPoint: .topLeading, endPoint: .bottomTrailing)
        }
    }
    
    private func stepShadowColor(isComplete: Bool, isEnabled: Bool) -> Color {
        if isComplete { return .green.opacity(0.3) }
        else if isEnabled { return .blue.opacity(0.3) }
        else { return .clear }
    }
    
    private func getWalletDisplayName(_ walletType: WalletType) -> String {
        switch walletType {
        case .lightning: return "Lightning Wallet"
        case .embedded:  return "Breez Wallet"
        case .custodial: return "Custodial Wallet"
        }
    }
    
    private func getInputText(_ walletType: WalletType) -> String {
        switch walletType {
        case .lightning: return lightningAddress
        case .embedded:  return breezSetup
        case .custodial: return custodialUsername
        }
    }
    
    private func getConnectedWalletDetails() -> String {
        guard let walletType = selectedWalletType else { return "No wallet selected" }
        switch walletType {
        case .lightning: return lightningAddress
        case .embedded:  return breezSetup
        case .custodial: return custodialUsername
        }
    }
    
    private func resetConnectStep() {
        selectedWalletType = nil
        lightningAddress = ""
        custodialUsername = ""
        breezSetup = ""
        showQRScanner = false
        showCustodialPicker = false
        showNonCustodialPicker = false
        chosenCustodial = nil
        chosenNonCustodial = nil
        connectError = nil
        step2Complete = false
    }
    
    private let ciContext = CIContext()
    private let qrFilter  = CIFilter.qrCodeGenerator()
    
    private func makeQRCode(_ string: String) -> UIImage? {
        let data = Data(string.utf8)
        qrFilter.setValue(data, forKey: "inputMessage")
        guard let output = qrFilter.outputImage?
            .transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cgimg = ciContext.createCGImage(output, from: output.extent)
        else { return nil }
        return UIImage(cgImage: cgimg)
    }
    
    private func truncatedDID(_ did: String) -> String {
        guard did.count > 14 else { return did }
        return "\(did.prefix(8))…\(did.suffix(6))"
    }
    
    private func resolvedWithdrawTo() -> String {
        if let custodial = chosenCustodial {
            return "\(custodial.lowercased())@example.com"
        } else if !lightningAddress.isEmpty {
            return lightningAddress
        } else {
            return "lnbc1q_default_withdraw"
        }
    }
    
    private func mockCashAppPayment(to: String, sats: Int) async throws -> String {
        do {
            try await Task.sleep(nanoseconds: 500_000_000)
            let preimage = "mock_preimage_\(UUID().uuidString.prefix(8))"
            let payment: [String: Any] = [
                "to": to,
                "amount_sats": sats,
                "preimage": preimage,
                "timestamp": Int(Date().timeIntervalSince1970)
            ]
            let jsonData = try JSONSerialization.data(withJSONObject: payment, options: .prettyPrinted)
            if let result = String(data: jsonData, encoding: .utf8) {
                return result
            } else {
                throw NSError(domain: "EncodingError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to encode payment to string"])
            }
        } catch {
            throw NSError(domain: "MockPaymentError", code: -2, userInfo: [NSLocalizedDescriptionKey: "Error during mock payment simulation: \(error.localizedDescription)"])
        }
    }
    
    private struct VCCPayload: Decodable {
        let content_hash: String?
        let created_by: String?
        let ln_address: String?
    }
    
    private func ellipsize(_ s: String, head: Int = 12, tail: Int = 6) -> String {
        guard s.count > head + tail + 1 else { return s }
        return "\(s.prefix(head))…\(s.suffix(tail))"
    }
    
    /// Compact, readable JSON used for BOTH display and copy/share
    private var vccShortJSON: String {
        guard vccResult != "No VCC yet",
              let data = vccResult.data(using: .utf8),
              let payload = try? JSONDecoder().decode(VCCPayload.self, from: data)
        else {
            // fallback: short version of whatever string we have
            return #"{"vcc":"\#(ellipsize(vccResult, head: 40, tail: 8))"}"#
        }
        let hash   = payload.content_hash.map { ellipsize($0) } ?? "—"
        let issuer = payload.created_by.map { ellipsize($0) } ?? "—"
        let to     = payload.ln_address.map { ellipsize($0, head: 10, tail: 8) } ?? "—"
        return #"{"hash":"\#(hash)","issuer":"\#(issuer)","to":"\#(to)"}"#
    }
    
    private func copyVCCToClipboard() {
#if canImport(UIKit)
        UIPasteboard.general.string = vccResult
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
#endif
        withAnimation(.spring(response: 0.25)) { showCopiedToast = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            withAnimation(.easeOut(duration: 0.2)) { showCopiedToast = false }
        }
    }
    
    // MARK: - Action Functions
    private func checkExistingSetup() {
        Task {
            do {
                if let publicDID = try didManager.getPublicDID(), !publicDID.isEmpty {
                    await MainActor.run {
                        step1Complete = true
                        print("Found existing DID: \(publicDID)")
                    }
                } else {
                    print("No existing DID found - user needs to generate")
                }
            } catch {
                print("No existing setup found: \(error)")
            }
        }
    }
    
    private func generateKeyPair() {
        isLoading = true
        Task {
            do {
                let result = try didManager.generateKeyPair()
                print("Generated DID: \(result)")
                await MainActor.run {
                    didManager.objectWillChange.send()
                    step1Complete = true
                    isLoading = false
                }
            } catch {
                await MainActor.run { isLoading = false }
            }
        }
    }
    
    private func regenerateKeyPair() {
        isLoading = true
        Task {
            do {
                _ = try didManager.regenerateKeyPair()
                await MainActor.run {
                    step1Complete = true
                    step2Complete = false
                    step3Complete = false
                    isLoading = false
                }
            } catch {
                await MainActor.run { isLoading = false }
            }
        }
    }
    
    private func connectWallet() { step2Complete = true }
    
    private func verifyIdentity() {
        isLoading = true
        Task {
            do {
                let mockWallet = MockLightningWallet()
                let (signature, preimage) = try await didManager.verifyIdentity(withNonce: nonce, lightningWallet: mockWallet, withdrawTo: withdrawTo)
                await MainActor.run {
                    claimResult = "Verified: Signature=\(signature.prefix(16))..., Preimage=\(preimage.prefix(16))..."
                    step3Complete = true
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    claimResult = "Verify Error: \(error.localizedDescription)"
                    isLoading = false
                }
            }
        }
    }
    
    private func proveOwnership() {
        isLoading = true
        Task {
            do {
                let claim = try await didManager.proveOwnership(walletType: .embedded, withdrawTo: withdrawTo)
                await MainActor.run {
                    claimResult = claim
                    step3Complete = true
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    claimResult = "Error: \(error.localizedDescription)"
                    isLoading = false
                }
            }
        }
    }
    
    private func generateSTWOProof() {
        isLoading = true
        Task {
            do {
                let (proof, signed) = try await didManager.generateComputationProof(
                    input: Data(inputHash.utf8),
                    output: Data(outputHash.utf8),
                    circuit: circuit
                )
                await MainActor.run {
                    proofResult = "Proof: \(proof.prefix(50))..., Signed: \(signed.prefix(20))..."
                    isLoading = false
                }
            } catch {
                await MainActor.run { isLoading = false }
            }
        }
    }
    
    private func createDLCContract() {
        isLoading = true
        Task {
            do {
                let contract = try didManager.createDLC(outcome: dlcOutcome, payout: [0.9, 0.1], oraclePubKey: didManager.publicDID ?? "")
                await MainActor.run {
                    dlcResult = contract
                    isLoading = false
                }
            } catch {
                await MainActor.run { isLoading = false }
            }
        }
    }
    
    private func generateVCC() {
        isLoading = true
        Task {
            do {
                let vcc = try await didManager.generateVCC(contentURL: vccContentURL, lnAddress: vccLnAddress)
                await MainActor.run {
                    vccResult = vcc
                    isLoading = false
                }
            } catch {
                await MainActor.run { isLoading = false }
            }
        }
    }
    
    private func hasStep2Info() -> Bool {
        // Accept LN invoice, LN address, or a “bc1…” address in your Step-2 destination
        let dest = getConnectedWalletDetails().trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !dest.isEmpty else { return false }
        return dest.hasPrefix("lnbc") || dest.contains("@") || dest.hasPrefix("bc1")
    }
    
    // Step 3 action — generates the VCC and marks payment as completed so the pill shows
    private func proveAndGenerateVCC() {
        // Same gating you already use
        guard hasStep2Info() else { showStep2Alert = true; return }

        // Defaults for inputs
        if vccContentURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            vccContentURL = "https://example.com/content"
        }
        if vccLnAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            vccLnAddress = resolvedWithdrawTo()
        }

        isLoading = true

        Task {
            do {
                // Mock a viewer-side payment so the UI shows "Payment Completed"
                let dest = resolvedWithdrawTo()
                let unlockPaymentJSON = try await mockCashAppPayment(to: dest, sats: 100)

                // Generate the claim (same as before)
                let vcc = try await didManager.generateVCC(
                    contentURL: vccContentURL,
                    lnAddress: vccLnAddress
                )

                await MainActor.run {
                    vccResult = vcc
                    paymentResult = unlockPaymentJSON      // <<< this flips the pill on
                    step3Complete = true
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    vccResult = "Error: \(error.localizedDescription)"
                    isLoading = false
                    step3Complete = false
                }
            }
        }
    }
    
    // Defaults for VCC inputs
    private func vccDefaultsAndFlow() {
        if vccContentURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            vccContentURL = "https://example.com/content"
        }
        
        if vccLnAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            vccLnAddress = resolvedWithdrawTo()
        }
        
        isLoading = true
        Task {
            do {
                print("🟡 Task started - generating initial VCC")
                let initialVCC = try await didManager.generateVCC(contentURL: vccContentURL, lnAddress: vccLnAddress)
                let dest = resolvedWithdrawTo()
                
                // 🔸 MOCK CASH APP PAYMENT for VCC anchoring (if custodial)
                var paymentJSON: String = ""
                if selectedWalletType == .custodial {
                    paymentJSON = try await mockCashAppPayment(to: dest, sats: 1) // 1-sat micro for anchoring
                    print("🟡 Custodial payment JSON: \(paymentJSON.prefix(50))...")
                }
                
                // 🔸 MOCK VIEWER-SIDE PAYMENT for content unlock
                let unlockPaymentJSON = try await mockCashAppPayment(to: dest, sats: 100) // Mock 100-sat payment for unlock
                print("🟡 Unlock payment JSON: \(unlockPaymentJSON.prefix(50))...")
                guard let paymentData = unlockPaymentJSON.data(using: .utf8) else {
                    throw NSError(domain: "PaymentError", code: -3, userInfo: [NSLocalizedDescriptionKey: "Failed to encode payment JSON"])
                }
                let paymentDict = try JSONSerialization.jsonObject(with: paymentData, options: []) as? [String: Any]
                let paymentPreimage = paymentDict?["preimage"] as? String ?? "mock_preimage"
                print("🟡 Payment preimage: \(paymentPreimage.prefix(8))...")
                
                // 🔸 MOCK ORACLE SIGNING for paid=true
                let dlcOutcome = "paid=true"
                let signature = try didManager.signDLCOutcome(outcome: dlcOutcome)
                print("🟡 DLC signature: \(signature.prefix(20))...")
                
                // 🔸 MOCK UNLOCK TOKEN DELIVERY
                let claimIdOrHash = "test_hash_\(UUID().uuidString.prefix(8))"
                let unlockToken = try await didManager.deliverUnlockToken(claimIdOrHash: claimIdOrHash, paymentPreimage: paymentPreimage)
                print("🟡 Unlock token generated")
                
                // 🔸 MOCK VERIFICATION RECEIPT
                let receipt = try await didManager.generateVerificationReceipt(claimIdOrHash: claimIdOrHash, paymentPreimage: paymentPreimage)
                print("🟡 Verification receipt generated")
                
                // 🔹 ZK PROOF
                let (proof, signed) = try await didManager.generateComputationProof(
                    input: Data(inputHash.utf8),
                    output: Data(outputHash.utf8),
                    circuit: circuit
                )
                print("🟡 ZK proof generated")
                
                // 🔹 VCC with splits
                let mockSplits: [(did: String, percentage: Double)] = [("did:btcr:mock_user2", 0.10)]
                let vcc = try await didManager.generateVCC(
                    contentURL: vccContentURL,
                    lnAddress: vccLnAddress,
                    originClaim: nil,
                    splits: mockSplits
                )
                print("🟡 Final VCC with splits generated")
                
                // Update UI state on MainActor
                await MainActor.run {
                    vccResult = vcc
                    if selectedWalletType == .custodial {
                        paymentResult = paymentJSON.isEmpty ? unlockPaymentJSON : paymentJSON
                    } else {
                        paymentResult = unlockPaymentJSON
                    }
                    dlcSignatureResult = "DLC Signature: \(signature.prefix(20))..."
                    unlockTokenResult = unlockToken
                    proofResult = "Proof: \(proof.prefix(50))..., Signed: \(signed.prefix(20))..."
                    print("Verification Receipt: \(receipt)")
                    step3Complete = true
                    isLoading = false
                    print("🟡 All steps complete - UI updated")
                }
            } catch {
                print("🟡 Error in proveAndGenerateVCC: \(error.localizedDescription)") // Console for debugging
                await MainActor.run {
                    claimResult = "Error: \(error.localizedDescription)"
                    isLoading = false
                    step3Complete = false
                }
            }
        }
    }
    
    struct ContentView_Previews: PreviewProvider {
        static var previews: some View { ContentView() }
    }
    
    // TEMP STUB – replace with real implementation later
    struct QRPayDestinationScanner: View {
        enum PayDestination {
            case onChain(address: String, amountBTC: Double?)
            case lightningInvoice(String)
            case lnurl(String)
            case lightningAddress(String)
        }
        var onResult: (PayDestination) -> Void
        var onCancel: () -> Void = {}
        
        var body: some View {
            VStack(spacing: 16) {
                Text("Scanner placeholder")
                Button("Mock: Paste bc1…") {
                    onResult(.onChain(address: "bc1qexample...", amountBTC: nil))
                }
                Button("Cancel") { onCancel() }
            }
            .padding()
        }
    }
}
