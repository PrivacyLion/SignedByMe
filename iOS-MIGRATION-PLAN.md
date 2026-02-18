# iOS Migration Plan - SignedByMe

## Overview
Match Android app feature-for-feature. ~8,100 lines of Kotlin → Swift/SwiftUI

---

## 1. Splash Screen ✨
**Android:** `SplashActivity.kt` (199 lines)

**iOS needs:**
- [ ] Launch screen with blue→purple gradient
- [ ] Animated cursive S drawing (Core Graphics path + CAShapeLayer animation)
- [ ] 2.5 second draw duration
- [ ] Transition to main app

**SwiftUI approach:** Custom `Shape` with `trim()` animation

---

## 2. Native Rust Library 🦀
**Android:** `NativeBridge.kt` (336 lines) + JNI bindings

**iOS needs:**
- [ ] Compile Rust lib for iOS targets (aarch64-apple-ios, x86_64-apple-ios)
- [ ] Create Swift bindings via C FFI (or use UniFFI)
- [ ] All 25+ native functions:
  - `generateSecp256k1PrivateKey()`
  - `derivePublicKeyHex()`
  - `signSchnorr()` / `signMessageDerHex()`
  - `generateRealIdentityProofV3()` (STWO proof)
  - `verifyRealIdentityProof()`
  - `proveMembership()` / `verifyMembership()`
  - `computeBindingHashV4()`
  - `createDlcContract()` / `signDlcOutcome()`
  - Oracle functions

---

## 3. DID & Wallet Manager 🔐
**Android:** `DidWalletManager.kt` (1,324 lines)

**iOS needs:**
- [ ] **Keychain storage** (replaces Android Keystore)
- [ ] DID creation/derivation from seed phrase (BIP39)
- [ ] Private key wrapping/unwrapping with Secure Enclave
- [ ] Identity proof generation & storage
- [ ] Payment binding signatures
- [ ] Login proof generation (V3 with STWO)
- [ ] Membership enrollment & witness storage
- [ ] Leaf secret generation & commitment

---

## 4. Lightning Wallet (Breez SDK) ⚡
**Android:** `BreezWalletManager.kt` (593 lines)

**iOS needs:**
- [ ] Breez SDK iOS integration (they have Swift bindings)
- [ ] Wallet initialization from mnemonic
- [ ] Balance tracking (StateFlow → Combine/ObservableObject)
- [ ] Invoice creation with description
- [ ] Payment sending (bolt11 & lightning address)
- [ ] Payment history
- [ ] Mnemonic backup/restore
- [ ] Encrypted mnemonic storage in Keychain

---

## 5. Main UI Screens 📱
**Android:** `MainActivity.kt` (4,626 lines)

### 5a. Onboarding Screen
- [ ] 3-step setup flow with progress indicator
- [ ] Step 1: Create DID (generate or restore)
- [ ] Step 2: Create Lightning wallet (with restore option)
- [ ] Step 3: Generate STWO proof binding DID↔Wallet
- [ ] Status pills (✓ completed states)
- [ ] Seed phrase display dialog
- [ ] DID info dialog
- [ ] Wallet info dialog

### 5b. Login Screen
- [ ] QR code scanner for session
- [ ] Deep link handling (`signedby.me://login?session=...`)
- [ ] Session info display (enterprise, amount)
- [ ] Invoice generation & auto-send to API
- [ ] Payment received detection
- [ ] Membership proof generation (if required)
- [ ] Settlement confirmation
- [ ] Transaction history list
- [ ] Receive dialog (show QR, share invoice)
- [ ] Send dialog (scan/paste invoice, lightning address)
- [ ] Transaction detail dialog

---

## 6. Backup System 💾
**Android:** `GoogleDriveBackupManager.kt` (289 lines) + `BackupStateManager.kt` (132 lines)

**iOS needs:**
- [ ] **iCloud Drive backup** (replaces Google Drive)
- [ ] Password-protected encrypted backup
- [ ] Backup state tracking (first login, reminder logic)
- [ ] Backup prompt bottom sheet (after first successful login)
- [ ] Restore from backup flow
- [ ] Progressive reminder backoff

---

## 7. QR Scanner 📷
**Android:** `QRScannerDialog.kt` (242 lines)

**iOS needs:**
- [ ] AVFoundation camera access
- [ ] QR code detection (CIDetector or Vision framework)
- [ ] Overlay UI with scan region
- [ ] Permission handling

---

## 8. DLC Manager 📜
**Android:** `DlcManager.kt` (363 lines)

**iOS needs:**
- [ ] DLC contract creation via native lib
- [ ] Outcome signing
- [ ] Oracle attestation verification
- [ ] Settlement receipt handling

---

## 9. API Integration 🌐
**iOS needs:**
- [ ] `POST /v1/login/invoice` - send invoice + proof
- [ ] `POST /v1/login/settle` - notify settlement
- [ ] `GET /v1/membership/enroll` - auto-enrollment
- [ ] `GET /v1/membership/witness` - fetch witness
- [ ] BTC price fetch for USD conversion

---

## 10. Deep Links & URL Schemes
**iOS needs:**
- [ ] Register `signedby.me://` URL scheme
- [ ] Handle `signedby.me://login?session=...&amount=...`
- [ ] Universal links for `https://signedby.me/login/...`

---

## 11. UI Components (SwiftUI)
- [ ] `GradientButton` - blue→purple gradient with white text
- [ ] `StatusPill` - colored pill badges
- [ ] `StepCard` - expandable step containers
- [ ] `TransactionRow` - payment history rows
- [ ] `DetailRow` - label/value pairs
- [ ] `SeedWordChip` - numbered seed word display

---

## Priority Order

### Phase 1: Core (Week 1)
1. Rust library iOS build + Swift bindings
2. Keychain storage for keys
3. DID creation
4. Basic UI scaffold

### Phase 2: Wallet (Week 2)
5. Breez SDK integration
6. Wallet creation/restore
7. Invoice creation
8. Payment detection

### Phase 3: Login Flow (Week 3)
9. QR scanner
10. Deep link handling
11. Login screen UI
12. API integration

### Phase 4: Polish (Week 4)
13. Splash screen animation
14. iCloud backup
15. Transaction history
16. Send/Receive dialogs

---

## Files to Reference

| Android | iOS Equivalent |
|---------|---------------|
| `MainActivity.kt` | `ContentView.swift` + ViewModels |
| `DidWalletManager.kt` | `DidWalletManager.swift` |
| `BreezWalletManager.kt` | `BreezWalletManager.swift` |
| `NativeBridge.kt` | `NativeBridge.swift` (FFI) |
| `SplashActivity.kt` | `SplashView.swift` |
| `BackupStateManager.kt` | `BackupStateManager.swift` |
| `GoogleDriveBackupManager.kt` | `ICloudBackupManager.swift` |

---

## Notes
- Use **SwiftUI** for all UI (matches Jetpack Compose paradigm)
- Use **Combine** for reactive state (matches Kotlin Flow)
- Use **Keychain** for secure storage (matches Android Keystore)
- Breez SDK has official Swift bindings
- May need to use **UniFFI** for Rust→Swift bindings (cleaner than manual C FFI)

---

*Generated: Feb 18, 2026*
