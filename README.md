# SignedByMe

**Get Paid to Log In** — Bitcoin-based identity verification where users earn sats for authentication.

## How It Works

1. User sets up DID + Lightning wallet in the app (one-time onboarding)
2. User generates STWO proof binding their DID ↔ Wallet
3. Enterprise shows "Sign in with SignedByMe" QR or deep link
4. User scans → app creates Lightning invoice
5. Enterprise pays invoice → sats go to user's wallet
6. STWO proof + payment binding sent to API → User verified AND got paid

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Enterprise     │     │  SignedByMe     │     │  User's         │
│  Web App        │────▶│  API            │◀────│  Mobile App     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │  Lightning      │
                                                │  Network        │
                                                └─────────────────┘
```

---

## Flow Diagrams

### Onboarding Flow (One-Time Setup)

```mermaid
sequenceDiagram
    participant User
    participant App as SignedByMe App
    participant Keystore as Android Keystore
    participant Breez as Breez SDK
    participant Rust as STWO Prover (Rust)

    Note over User,Rust: Step 1: Create DID
    User->>App: Tap "Create DID"
    App->>Rust: generateSecp256k1PrivateKey()
    Rust-->>App: Private key bytes
    App->>Rust: derivePublicKeyHex(privKey)
    Rust-->>App: Public key (DID)
    App->>Keystore: Wrap & store private key
    Keystore-->>App: Encrypted key stored
    App-->>User: ✓ DID Created

    Note over User,Rust: Step 2: Create Lightning Wallet
    User->>App: Tap "Create Wallet"
    App->>Breez: Generate mnemonic (12 words)
    Breez-->>App: Mnemonic phrase
    App->>Keystore: Encrypt & store mnemonic
    App->>Breez: initializeWallet(mnemonic)
    Breez-->>App: Wallet ready, node connected
    App-->>User: ✓ Wallet Created (show balance)

    Note over User,Rust: Step 3: Generate STWO Proof
    User->>App: Tap "Generate Proof"
    App->>App: Get DID pubkey + wallet address
    App->>Rust: generateRealIdentityProofV3(didPubkey, walletAddr, domain)
    Rust->>Rust: Run STWO Circle STARK prover
    Rust-->>App: Identity proof JSON + proof_hash
    App->>Keystore: Store encrypted proof
    App-->>User: ✓ Setup Complete!
```

### Login Flow (Get Paid to Verify)

```mermaid
sequenceDiagram
    participant Enterprise as Enterprise Web App
    participant API as SignedByMe API
    participant App as SignedByMe Mobile App
    participant Breez as Breez SDK (Lightning)
    participant Rust as STWO Prover

    Note over Enterprise,Rust: Enterprise Initiates Login
    Enterprise->>API: POST /v1/session/create
    API-->>Enterprise: session_id, amount, client_id
    Enterprise->>Enterprise: Display QR code or deep link
    Note right of Enterprise: signedby.me://login?session=xxx&amount=500

    Note over Enterprise,Rust: User Scans & Creates Invoice
    App->>App: Scan QR or receive deep link
    App->>App: Parse session_id, enterprise_name, amount
    App->>Breez: createInvoice(amount, "SignedByMe Login")
    Breez-->>App: BOLT11 invoice + payment_hash
    
    Note over Enterprise,Rust: Submit Invoice + Proof to API
    App->>App: Create payment binding (payment_hash + nonce)
    App->>Rust: Sign binding with DID key
    Rust-->>App: Binding signature
    App->>API: POST /v1/login/invoice
    Note right of App: {invoice, stwo_proof, binding_sig, did_pubkey}
    API-->>App: OK, waiting for payment
    API-->>Enterprise: Invoice ready for payment

    Note over Enterprise,Rust: Enterprise Pays, User Receives
    Enterprise->>Breez: Pay BOLT11 invoice
    Breez->>Breez: Lightning payment routes
    Breez-->>App: Payment received event
    App->>App: Verify payment_hash matches
    
    Note over Enterprise,Rust: Settlement & Verification
    App->>API: POST /v1/login/settle
    Note right of App: {session_id, payment_hash, preimage}
    API->>API: Verify STWO proof + payment binding
    API-->>Enterprise: Login verified ✓
    API-->>App: Settlement confirmed
    App-->>App: Show "Earned 500 sats!" 🎉
```

### Membership Proof Flow (Optional)

```mermaid
sequenceDiagram
    participant App as SignedByMe App
    participant API as SignedByMe API
    participant Rust as Membership Prover

    Note over App,Rust: Auto-Enrollment (during Step 3)
    App->>App: Generate leaf_secret
    App->>Rust: computeLeafCommitment(leaf_secret)
    Rust-->>App: leaf_commitment
    App->>API: POST /v1/membership/enroll
    Note right of App: {did_pubkey, leaf_commitment}
    API-->>App: enrollment_id, root_id
    App->>App: Store enrollment locally

    Note over App,Rust: At Login (if membership required)
    App->>API: GET /v1/membership/witness?client_id=X&root_id=Y
    API-->>App: Merkle witness (siblings, index)
    App->>Rust: proveMembership(leaf_secret, witness, root)
    Rust->>Rust: Poseidon hash + Merkle proof
    Rust-->>App: Membership proof JSON
    App->>API: Include membership_proof in login request
    API->>API: Verify membership without learning identity
```

---

## Cryptographic Chain

```
DID Private Key ──sign──▶ Identity Proof (STWO)
        │                         │
        │                         ▼
        │                   proof_hash
        │                         │
        ▼                         ▼
Payment Binding ◀────────── binding_hash
        │
        ├── payment_hash (from invoice)
        ├── nonce (from API)
        └── signature (DID signs binding)

At verification:
✓ STWO proof is valid (DID owns wallet)
✓ Binding signature matches DID
✓ Payment hash matches paid invoice
✓ Nonce prevents replay
```

---

## Project Structure

```
btc-did/
├── app/                          # Android app (Kotlin)
│   └── src/main/java/.../
│       ├── MainActivity.kt       # Main UI (4,600 lines)
│       ├── SplashActivity.kt     # Animated cursive S splash
│       ├── DidWalletManager.kt   # DID + proof management
│       ├── BreezWalletManager.kt # Lightning wallet
│       ├── NativeBridge.kt       # Rust JNI bindings
│       └── BackupStateManager.kt # Backup prompts
├── native/btcdid_core/           # Rust library
│   └── src/
│       ├── lib.rs                # JNI exports
│       ├── stwo_*.rs             # STWO prover
│       └── membership.rs         # Merkle proofs
├── api/                          # FastAPI backend
│   └── app/
│       ├── main.py
│       └── routes/
│           ├── login_invoice.py
│           └── membership.py
└── docs/
```

---

## URLs

- **Deep Link:** `signedby.me://login?session=xxx&amount=500`
- **API Base:** `https://api.beta.privacy-lion.com`
- **Demo Site:** `https://beta.privacy-lion.com`

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Mobile App | Kotlin + Jetpack Compose |
| Lightning | Breez SDK |
| ZK Proofs | STWO (Circle STARKs) |
| Native Crypto | Rust + secp256k1 |
| API | FastAPI (Python) |
| Membership | Poseidon hash + Merkle trees |

---

## Status

- ✅ Android app complete
- ✅ Real STWO proofs (~1ms on device)
- ✅ Merkle membership proofs
- ✅ API deployed
- ⏳ iOS version (in progress)

---

*Built by [Privacy Lion](https://privacy-lion.com)*
