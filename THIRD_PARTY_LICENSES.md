# Third-Party Licenses

SignedByMe uses the following open-source components:

---

## STWO (Circle STARK Prover)

**Project:** https://github.com/starkware-libs/stwo  
**Copyright:** 2024 StarkWare Industries Ltd.  
**License:** Apache License 2.0

Used for zero-knowledge proof generation and verification.

```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## secp256k1

**Project:** https://github.com/bitcoin-core/secp256k1  
**Copyright:** 2013-2024 Pieter Wuille, Andrew Poelstra, et al.  
**License:** MIT

Used for elliptic curve cryptography (DID signatures).

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## Breez SDK

**Project:** https://github.com/breez/breez-sdk  
**Copyright:** 2022-2024 Breez Technology Ltd.  
**License:** MIT

Used for Lightning Network wallet integration.

---

## Additional Rust Dependencies

The native Rust library (`btcdid_core`) uses various Rust crates, each with their own licenses. 
Run `cargo license` in `native/btcdid_core/` for a complete list.

Common licenses used by dependencies:
- MIT
- Apache 2.0
- BSD-3-Clause

---

## Android Dependencies

The Android app uses standard Android/Kotlin libraries under Apache 2.0 license.
See `app/build.gradle` for the complete dependency list.

---

## Python Dependencies

The API server uses various Python packages. See `requirements.txt` for the list.
Run `pip-licenses` for license details.
