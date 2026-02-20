// WalletView.swift - Wallet Tab
// SignedByMe iOS

import SwiftUI

struct WalletView: View {
    @EnvironmentObject var walletManager: BreezWalletManager
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    // Balance card
                    balanceCard
                    
                    // Action buttons
                    actionButtons
                    
                    // Transactions
                    transactionsSection
                }
                .padding()
            }
            .navigationTitle("Wallet")
            .refreshable {
                try? await walletManager.refreshBalance()
                await walletManager.fetchBtcPrice()
            }
        }
    }
    
    // MARK: - Balance Card
    
    private var balanceCard: some View {
        VStack(spacing: 8) {
            Text("Balance")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(walletManager.formattedBalance)
                    .font(.system(size: 48, weight: .bold, design: .rounded))
                Text("sats")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }
            
            if walletManager.btcPriceUsd > 0 {
                Text("≈ \(walletManager.formattedUsdBalance)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            
            // Connection status
            HStack(spacing: 6) {
                Circle()
                    .fill(walletManager.state.isConnected ? .green : .orange)
                    .frame(width: 8, height: 8)
                Text(walletManager.state.isConnected ? "Connected" : "Connecting...")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 8)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 32)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(
                    LinearGradient(
                        colors: [Color.orange.opacity(0.15), Color.yellow.opacity(0.1)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
        )
    }
    
    // MARK: - Action Buttons
    
    private var actionButtons: some View {
        HStack(spacing: 16) {
            NavigationLink {
                ReceiveView()
            } label: {
                VStack(spacing: 8) {
                    Image(systemName: "arrow.down.circle.fill")
                        .font(.title)
                    Text("Receive")
                        .font(.subheadline)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 20)
                .background(Color(.secondarySystemBackground))
                .cornerRadius(16)
            }
            .buttonStyle(.plain)
            
            NavigationLink {
                SendView()
            } label: {
                VStack(spacing: 8) {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title)
                    Text("Send")
                        .font(.subheadline)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 20)
                .background(Color(.secondarySystemBackground))
                .cornerRadius(16)
            }
            .buttonStyle(.plain)
        }
    }
    
    // MARK: - Transactions
    
    private var transactionsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Recent Activity")
                .font(.headline)
            
            if walletManager.transactions.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "tray")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("No transactions yet")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 40)
            } else {
                ForEach(walletManager.transactions) { tx in
                    TransactionRow(transaction: tx)
                }
            }
        }
    }
}

// MARK: - Transaction Row

struct TransactionRow: View {
    let transaction: WalletTransaction
    
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: transaction.type == .receive ? "arrow.down.circle.fill" : "arrow.up.circle.fill")
                .font(.title2)
                .foregroundStyle(transaction.type == .receive ? .green : .orange)
            
            VStack(alignment: .leading, spacing: 4) {
                Text(transaction.description ?? (transaction.type == .receive ? "Received" : "Sent"))
                    .font(.subheadline)
                Text(transaction.timestamp, style: .relative)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            Text("\(transaction.type == .receive ? "+" : "-")\(transaction.amountSats) sats")
                .font(.subheadline.monospacedDigit())
                .foregroundStyle(transaction.type == .receive ? .green : .primary)
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }
}

// MARK: - Receive View

struct ReceiveView: View {
    @EnvironmentObject var walletManager: BreezWalletManager
    @State private var invoiceAmount = ""
    @State private var generatedInvoice: String?
    
    var body: some View {
        VStack(spacing: 24) {
            if let address = walletManager.sparkAddress {
                VStack(spacing: 16) {
                    Text("Your Spark Address")
                        .font(.headline)
                    
                    // QR Code placeholder
                    Image(systemName: "qrcode")
                        .font(.system(size: 150))
                        .foregroundStyle(.secondary)
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(16)
                    
                    Text(address)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    
                    Button {
                        UIPasteboard.general.string = address
                    } label: {
                        Label("Copy Address", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.bordered)
                }
            }
            
            Divider()
            
            VStack(spacing: 12) {
                Text("Create Invoice")
                    .font(.headline)
                
                TextField("Amount (sats)", text: $invoiceAmount)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.numberPad)
                
                Button("Generate Invoice") {
                    // TODO: Generate invoice
                }
                .buttonStyle(.borderedProminent)
                .disabled(invoiceAmount.isEmpty)
            }
            
            Spacer()
        }
        .padding()
        .navigationTitle("Receive")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Send View

struct SendView: View {
    @EnvironmentObject var walletManager: BreezWalletManager
    @State private var invoice = ""
    
    var body: some View {
        VStack(spacing: 24) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Lightning Invoice")
                    .font(.headline)
                
                TextEditor(text: $invoice)
                    .frame(height: 100)
                    .font(.caption.monospaced())
                    .padding(8)
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(12)
                
                HStack {
                    Button {
                        if let clip = UIPasteboard.general.string {
                            invoice = clip
                        }
                    } label: {
                        Label("Paste", systemImage: "doc.on.clipboard")
                    }
                    .buttonStyle(.bordered)
                    
                    Button {
                        // TODO: Scan QR
                    } label: {
                        Label("Scan", systemImage: "qrcode.viewfinder")
                    }
                    .buttonStyle(.bordered)
                }
            }
            
            Spacer()
            
            Button {
                // TODO: Pay invoice
            } label: {
                Text("Pay Invoice")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 50)
                    .background(Color.orange)
                    .cornerRadius(12)
            }
            .disabled(invoice.isEmpty)
        }
        .padding()
        .navigationTitle("Send")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Preview

#Preview {
    WalletView()
        .environmentObject(BreezWalletManager())
}
