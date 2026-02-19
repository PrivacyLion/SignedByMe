# Third-Party Licenses

SignedByMe uses the following open-source components. All licenses are permissive (MIT, Apache 2.0, BSD, CC0) and compatible with commercial use.

---

## License Summary

| Component | License | Copyleft? | Commercial OK? |
|-----------|---------|-----------|----------------|
| STWO (StarkWare) | Apache 2.0 | No | ✅ Yes |
| secp256k1 | MIT | No | ✅ Yes |
| bitcoin-rs | CC0 | No | ✅ Yes |
| Breez SDK | MIT | No | ✅ Yes |
| BIP39 (Zcash) | MIT | No | ✅ Yes |
| AndroidX/Compose | Apache 2.0 | No | ✅ Yes |
| Google ML Kit | Apache 2.0 | No | ✅ Yes |
| ZXing | Apache 2.0 | No | ✅ Yes |
| FastAPI | MIT | No | ✅ Yes |
| Pydantic | MIT | No | ✅ Yes |
| PyJWT | MIT | No | ✅ Yes |
| coincurve | MIT/Apache 2.0 | No | ✅ Yes |
| All Rust crates | MIT/Apache 2.0 | No | ✅ Yes |

**No GPL/LGPL/copyleft licenses are used.** All dependencies allow commercial use and proprietary distribution.

---

## Rust Dependencies (native/btcdid_core)

### STWO (Circle STARK Prover)
- **Project:** https://github.com/starkware-libs/stwo
- **Copyright:** 2024 StarkWare Industries Ltd.
- **License:** Apache 2.0
- **Usage:** Zero-knowledge proof generation and verification

### secp256k1
- **Project:** https://github.com/rust-bitcoin/rust-secp256k1
- **Copyright:** 2014-2024 Andrew Poelstra, rust-bitcoin developers
- **License:** CC0 (Public Domain)
- **Usage:** Elliptic curve cryptography for DID signatures

### bitcoin
- **Project:** https://github.com/rust-bitcoin/rust-bitcoin
- **Copyright:** 2014-2024 rust-bitcoin developers
- **License:** CC0 (Public Domain)
- **Usage:** Bitcoin primitives, Schnorr signatures

### lightning-invoice
- **Project:** https://github.com/lightningdevkit/rust-lightning
- **Copyright:** 2018-2024 Lightning Dev Kit developers
- **License:** MIT/Apache 2.0
- **Usage:** Lightning invoice parsing and generation

### k256
- **Project:** https://github.com/RustCrypto/elliptic-curves
- **Copyright:** RustCrypto developers
- **License:** MIT/Apache 2.0
- **Usage:** secp256k1 curve operations

### sha2
- **Project:** https://github.com/RustCrypto/hashes
- **Copyright:** RustCrypto developers
- **License:** MIT/Apache 2.0
- **Usage:** SHA-256 hashing

### serde / serde_json
- **Project:** https://github.com/serde-rs/serde
- **Copyright:** 2014-2024 Erick Tryzelaar, David Tolnay
- **License:** MIT/Apache 2.0
- **Usage:** Serialization/deserialization

### Other Rust Crates
All other Rust dependencies (clap, jni, anyhow, hex, rand_core, getrandom, itertools, num-traits, tracing, bincode, base64) are licensed under MIT and/or Apache 2.0.

---

## Android Dependencies

### Breez SDK Spark
- **Project:** https://github.com/AcinonyxScan/breez-sdk
- **Copyright:** 2022-2024 Breez Technology Ltd.
- **License:** MIT
- **Usage:** Lightning Network wallet integration

### kotlin-bip39
- **Project:** https://github.com/AcinonyxScan/kotlin-bip39
- **Copyright:** 2020-2023 Zcash
- **License:** MIT
- **Usage:** BIP39 mnemonic seed phrase generation

### AndroidX Libraries
- **Project:** https://developer.android.com/jetpack/androidx
- **Copyright:** Google LLC
- **License:** Apache 2.0
- **Components:** core-ktx, lifecycle, activity-compose, compose-*, camera-*, biometric, fragment

### Jetpack Compose
- **Project:** https://developer.android.com/jetpack/compose
- **Copyright:** Google LLC
- **License:** Apache 2.0
- **Usage:** UI framework

### ML Kit Barcode Scanning
- **Project:** https://developers.google.com/ml-kit
- **Copyright:** Google LLC
- **License:** Apache 2.0
- **Usage:** QR code scanning

### ZXing
- **Project:** https://github.com/zxing/zxing
- **Copyright:** 2007-2024 ZXing authors
- **License:** Apache 2.0
- **Usage:** QR code generation

### Google Play Services Auth
- **Project:** https://developers.google.com/identity
- **Copyright:** Google LLC
- **License:** Google Play Services Terms
- **Usage:** Google Sign-In for Drive backup

### Google Drive API
- **Project:** https://developers.google.com/drive
- **Copyright:** Google LLC
- **License:** Apache 2.0
- **Usage:** Cloud backup functionality

---

## Python Dependencies (API Server)

### FastAPI
- **Project:** https://github.com/tiangolo/fastapi
- **Copyright:** 2018-2024 Sebastián Ramírez
- **License:** MIT
- **Usage:** Web framework

### Uvicorn
- **Project:** https://github.com/encode/uvicorn
- **Copyright:** 2017-2024 Encode
- **License:** BSD 3-Clause
- **Usage:** ASGI server

### Pydantic
- **Project:** https://github.com/pydantic/pydantic
- **Copyright:** 2017-2024 Samuel Colvin
- **License:** MIT
- **Usage:** Data validation

### PyJWT
- **Project:** https://github.com/jpadilla/pyjwt
- **Copyright:** 2015-2024 José Padilla
- **License:** MIT
- **Usage:** JWT encoding/decoding

### slowapi
- **Project:** https://github.com/laurentS/slowapi
- **Copyright:** 2020-2024 Laurent Savaete
- **License:** MIT
- **Usage:** Rate limiting

### coincurve
- **Project:** https://github.com/ofek/coincurve
- **Copyright:** 2017-2024 Ofek Lev
- **License:** MIT/Apache 2.0
- **Usage:** secp256k1 bindings for signature verification

### passlib
- **Project:** https://github.com/glic3rern/passlib
- **Copyright:** 2008-2024 Assurance Technologies
- **License:** BSD
- **Usage:** Password hashing utilities

### python-multipart
- **Project:** https://github.com/andrew-d/python-multipart
- **Copyright:** 2012-2024 Andrew Dunham
- **License:** Apache 2.0
- **Usage:** Multipart form parsing

---

## Compliance Notes

### What We Must Do
1. ✅ Include this license file in source distributions
2. ✅ Include license notices in binary distributions (Android app "About" screen or docs)
3. ✅ Attribute copyright holders as listed above
4. ✅ Not claim endorsement by copyright holders

### What We May Do
- ✅ Use commercially
- ✅ Modify and create derivative works
- ✅ Distribute in source or binary form
- ✅ Sublicense (for MIT/Apache 2.0)
- ✅ Use without sharing our source code (no copyleft)

### What We Must NOT Do
- ❌ Remove copyright notices from dependencies
- ❌ Use trademarks without permission (e.g., "StarkWare", "Breez", "Google")
- ❌ Hold contributors liable for damages

---

## Full License Texts

The full text of each license is available at:
- **Apache 2.0:** https://www.apache.org/licenses/LICENSE-2.0
- **MIT:** https://opensource.org/licenses/MIT
- **BSD 3-Clause:** https://opensource.org/licenses/BSD-3-Clause
- **CC0:** https://creativecommons.org/publicdomain/zero/1.0/

---

*Last updated: 2026-02-19*
