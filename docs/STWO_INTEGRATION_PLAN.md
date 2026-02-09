# STWO Real Integration Plan

## Current State (Fake)
- `stwo_prover.rs` generates SHA256-based "proofs" that look like STWO but aren't cryptographic
- Verifier just checks hash consistency, trusts `valid` flag
- No real STARK math

## Target State (Real)
- Real Circle STARK proofs using StarkWare's STWO library
- Cryptographically sound: verifier derives validity, doesn't trust prover
- ≤5000 constraints per circuit (mobile-friendly)

---

## STWO Library Structure

```
stwo (StarkWare)
├── crates/stwo              # Core prover/verifier
├── crates/constraint-framework  # Define constraints via FrameworkEval trait
├── crates/air-utils         # AIR utilities
└── crates/examples          # Reference implementations
```

### Key Types
```rust
// Field element (Mersenne31)
use stwo::core::fields::m31::BaseField;

// Commitment channels
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;

// Prover/Verifier
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo::core::verifier::verify;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};

// Constraint framework
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval};
```

---

## Circuit Design for SignedByMe

### Identity Proof Circuit (~1500 constraints)

**Public Inputs:**
- `did_pubkey_x`, `did_pubkey_y` (secp256k1 point, 2 × 256 bits)
- `wallet_address_hash` (32 bytes)
- `binding_hash` (H_bind, 32 bytes)
- `timestamp` (u64)
- `expires_at` (u64)

**Private Inputs (Witness):**
- `did_private_key` (256 bits)
- `wallet_signature` (64 bytes)

**Constraints:**
1. **Pubkey derivation**: `G * did_private_key == (did_pubkey_x, did_pubkey_y)`
   - This is expensive in-circuit (~1000 constraints for EC scalar mul)
   - Alternative: Prove signature verification instead

2. **Binding hash check**: 
   ```
   computed_hash = SHA256(version || did_pubkey || wallet_address || timestamp)
   constraint: computed_hash == binding_hash
   ```
   - SHA256 in circuit: ~500 constraints per block

3. **Timestamp validity**: `timestamp <= expires_at`

### Simplified Circuit v1 (~500 constraints)

For mobile efficiency, start with hash-only proof:

**Public Inputs:**
- `binding_hash` (H_bind)
- `signature_r`, `signature_s` (from DID signing H_bind)
- `did_pubkey_x`, `did_pubkey_y`

**Constraints:**
1. Verify `(r, s)` is valid ECDSA signature of `binding_hash` under `did_pubkey`
2. This proves: "The holder of `did_pubkey` signed `binding_hash`"

Actually, ECDSA verification in-circuit is expensive. Let's be smarter:

### Pragmatic Circuit v1: Commitment Proof (~200 constraints)

**What we actually need to prove:**
"I know a preimage `P` such that `SHA256(P) = binding_hash`"

Where `P = (version || did_pubkey || wallet_address || timestamp || payment_hash)`

**Public Inputs:**
- `binding_hash` (the H_bind value)
- `did_pubkey` (claimed identity)
- `payment_hash` (from invoice)

**Private Inputs:**
- Full preimage components

**Constraints:**
- Recompute hash from inputs, check equals `binding_hash`

**Why this works:**
- Proof shows: "I know all the components that hash to H_bind"
- `binding_hash` includes `did_pubkey` and `payment_hash`
- Combined with a secp256k1 signature OUTSIDE the circuit, this binds identity to payment

---

## Implementation Steps

### Phase 1: Add STWO Dependency (Day 1)

```toml
# native/btcdid_core/Cargo.toml
[dependencies]
stwo = { git = "https://github.com/starkware-libs/stwo", branch = "dev", features = ["prover"] }
stwo-constraint-framework = { git = "https://github.com/starkware-libs/stwo", branch = "dev", features = ["prover"] }
```

### Phase 2: Implement Real Prover (Days 2-4)

```rust
// native/btcdid_core/src/stwo_real.rs

use stwo::core::fields::m31::BaseField;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo::prover::backend::CpuBackend;
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval};

/// Identity binding circuit evaluator
#[derive(Clone)]
pub struct IdentityBindingEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for IdentityBindingEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }
    
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Column layout:
        // [0-7]: binding_hash bytes (8 M31 elements, each holds 4 bytes)
        // [8-15]: did_pubkey bytes
        // [16-23]: payment_hash bytes
        // [24-31]: preimage_hash (computed)
        
        // Read trace columns
        let binding_hash = (0..8).map(|_| eval.next_trace_mask()).collect::<Vec<_>>();
        let did_pubkey = (0..8).map(|_| eval.next_trace_mask()).collect::<Vec<_>>();
        let payment_hash = (0..8).map(|_| eval.next_trace_mask()).collect::<Vec<_>>();
        let computed_hash = (0..8).map(|_| eval.next_trace_mask()).collect::<Vec<_>>();
        
        // Constraint: computed_hash == binding_hash
        for (c, b) in computed_hash.iter().zip(binding_hash.iter()) {
            eval.add_constraint(c.clone() - b.clone());
        }
        
        eval
    }
}

pub type IdentityBindingComponent = FrameworkComponent<IdentityBindingEval>;
```

### Phase 3: Trace Generation (Days 3-4)

```rust
pub fn generate_identity_trace(
    binding_hash: &[u8; 32],
    did_pubkey: &[u8; 33],
    payment_hash: &[u8; 32],
    preimage: &[u8],
) -> ColumnVec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    // Convert bytes to M31 field elements
    // Generate trace with hash computation
    // Return column evaluations
}
```

### Phase 4: Full Prove/Verify (Days 4-5)

```rust
pub fn prove_identity_binding(
    binding_hash: &[u8; 32],
    did_pubkey: &[u8; 33], 
    payment_hash: &[u8; 32],
    preimage: &[u8],
) -> Result<StwoProof> {
    let config = PcsConfig::default();
    let twiddles = CpuBackend::precompute_twiddles(...);
    
    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme = CommitmentSchemeProver::<
        CpuBackend,
        Blake2sM31MerkleChannel,
    >::new(config, &twiddles);
    
    // Generate and commit trace
    let trace = generate_identity_trace(binding_hash, did_pubkey, payment_hash, preimage);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);
    
    // Create component
    let component = IdentityBindingComponent::new(
        &mut TraceLocationAllocator::default(),
        IdentityBindingEval { log_n_rows: 0 },
        SecureField::zero(),
    );
    
    // Generate proof
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        prover_channel,
        commitment_scheme,
    )?;
    
    // Serialize to our StwoProof format
    Ok(serialize_proof(proof, binding_hash, did_pubkey, payment_hash))
}

pub fn verify_identity_binding(proof: &StwoProof) -> Result<bool> {
    let config = PcsConfig::default();
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    
    // Reconstruct component
    let component = IdentityBindingComponent::new(...);
    
    // Verify
    verify(&[&component], verifier_channel, commitment_scheme, deserialize_proof(proof)?)
        .map(|_| true)
        .map_err(|e| anyhow!("Verification failed: {}", e))
}
```

### Phase 5: JNI Bridge Update (Day 5)

Update `lib.rs` to expose new functions:
```rust
#[no_mangle]
pub extern "C" fn Java_com_signedby_me_NativeBridge_generateRealStwoProof(
    env: JNIEnv,
    _class: JClass,
    binding_hash: jbyteArray,
    did_pubkey: jbyteArray,
    payment_hash: jbyteArray,
    preimage: jbyteArray,
) -> jstring {
    // Call prove_identity_binding, return JSON
}

#[no_mangle]
pub extern "C" fn Java_com_signedby_me_NativeBridge_verifyRealStwoProof(
    env: JNIEnv,
    _class: JClass,
    proof_json: JString,
) -> jboolean {
    // Call verify_identity_binding
}
```

### Phase 6: Cross-Compile for Android (Days 5-6)

```bash
# Add STWO to cross-compile
cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target x86_64-linux-android --release
```

Potential issues:
- SIMD operations may not work on all Android targets
- May need to use `CpuBackend` instead of `SimdBackend` for compatibility
- Memory usage needs testing

### Phase 7: API Verifier (Day 6)

Update Python API to call Rust verifier via PyO3 or subprocess:

```python
# app/lib/stwo_verify.py
import subprocess
import json

def verify_stwo_proof(proof_json: str) -> bool:
    """Verify STWO proof using Rust verifier binary"""
    result = subprocess.run(
        ["./stwo_verifier", "--verify"],
        input=proof_json,
        capture_output=True,
        text=True
    )
    return result.returncode == 0
```

Or embed via PyO3:
```rust
// Build as Python extension
#[pyfunction]
fn verify_proof(proof_json: &str) -> PyResult<bool> {
    let proof: StwoProof = serde_json::from_str(proof_json)?;
    Ok(verify_identity_binding(&proof)?)
}
```

---

## Timeline

| Day | Task |
|-----|------|
| 1 | Add STWO dependency, test compilation |
| 2 | Implement IdentityBindingEval constraint |
| 3 | Implement trace generation |
| 4 | Implement prove/verify functions |
| 5 | JNI bridge, Android cross-compile |
| 6 | API verifier integration |
| 7 | Testing + optimization |

**Total: ~7 working days**

---

## Risk Mitigation

1. **STWO doesn't compile for Android NDK**
   - Fallback: Use `no_std` mode, CpuBackend only
   - Fallback: Compute-heavy proofs on server, light verification on mobile

2. **Proof generation too slow on mobile**
   - Use smallest viable circuit
   - Move proof generation to background thread
   - Cache proofs (identity proof generated once, reused for multiple logins)

3. **Memory usage too high**
   - Use streaming/incremental trace generation
   - Reduce log_n_rows (smaller domains)

4. **STWO API changes (it's "work in progress")**
   - Pin to specific commit
   - Wrap STWO types in our own abstractions

---

## Success Criteria

- [ ] `prove_identity_binding()` generates real STARK proof
- [ ] `verify_identity_binding()` returns true only for valid proofs
- [ ] Fake proof (random bytes) is rejected
- [ ] Tampered proof (modified public input) is rejected
- [ ] Proof generation < 10 seconds on Pixel 8 Pro
- [ ] Proof verification < 500ms on API server
- [ ] Proof size < 50KB
