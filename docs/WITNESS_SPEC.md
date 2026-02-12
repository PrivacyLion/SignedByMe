# Merkle Witness Spec (SignedByMe)

**Version:** 1  
**Status:** FROZEN — do not change without mobile + verifier coordination

## Scope

This spec defines the Merkle witness format consumed by:
- SignedByMe mobile prover (`proveMembership` JNI)
- Enterprise `sbm-tree` CLI (outputs per-user witnesses)
- Server-side membership verifier (`membership_verifier` binary)

**Parameters:**
- `hash_alg` = `"poseidon"`
- `depth` = 20 (fixed, enforced server-side)
- Roots scoped by `(client_id, purpose_id)`

---

## Terminology

| Term | Definition |
|------|------------|
| **Leaf commitment** | `Poseidon(domain_sep \|\| leaf_secret)` |
| **Merkle root** | Poseidon Merkle tree root over commitments padded to depth 20 |
| **Witness** | siblings + path direction bits for one leaf |
| **domain_sep** | `H("SBM", client_id, purpose_id)` using canonical encoding |

---

## Fixed Invariants

1. `depth` is always **20**
2. `hash_alg` is always **poseidon**
3. Root is **immutable** once published (rotation = publish new `root_id`)
4. Witnesses must match verifier semantics exactly

---

## Witness JSON Schema (v1)

```json
{
  "version": 1,
  "client_id": "acme_corp",
  "root_id": "acme-issuer_batch-2026-02-12",
  "purpose_id": 2,
  "hash_alg": "poseidon",
  "depth": 20,
  "not_before": 1770843306,
  "expires_at": 1802379306,
  "siblings": [
    "0x1234...64hex...",
    "0x5678...64hex...",
    ...
  ],
  "path_bits": [1, 0, 1, 0, ...]
}
```

**Note:** `leaf_index` is intentionally omitted from witnesses (privacy concern — 
could enable correlation). Enterprise tracks index→commitment mapping separately.

---

## Field Requirements

| Field | Type | Requirement |
|-------|------|-------------|
| `version` | int | Must be `1` |
| `client_id` | string | Enterprise identifier |
| `root_id` | string | Unique root identifier |
| `purpose_id` | int | 0=none, 1=allowlist, 2=issuer_batch, 3=revocation |
| `hash_alg` | string | Must be `"poseidon"` |
| `depth` | int | Must be `20` |
| `not_before` | int | Unix timestamp (seconds) |
| `expires_at` | int | Unix timestamp (seconds) |
| `siblings` | array | Exactly 20 elements |
| `path_bits` | array | Exactly 20 elements (0 or 1) |

**siblings encoding:**
- Each `siblings[i]` is a 32-byte field element
- Encoded as `0x` + 64 lowercase hex chars
- `siblings[0]` = leaf level (sibling of the leaf hash)
- `siblings[19]` = top level (sibling just below root)
- Order: **leaf → root**

---

## Ordering Conventions (CRITICAL)

### A) Sibling Order

```
siblings[0]   = sibling at leaf level
siblings[1]   = sibling one level up
...
siblings[19]  = sibling at top level (below root)
```

Order is **leaf → root**.

### B) Path Bit Meaning (matches btcdid_core verifier)

`path_bits[i]` indicates whether the **sibling** is on the right:

| `path_bits[i]` | Meaning | Hash computation |
|----------------|---------|------------------|
| `1` | sibling is RIGHT, current is LEFT | `parent = Poseidon(current, siblings[i])` |
| `0` | sibling is LEFT, current is RIGHT | `parent = Poseidon(siblings[i], current)` |

**⚠️ Note:** This is "is sibling right?" semantics, not "is current right?" semantics.

### C) Verification Algorithm

```
curr = leaf_commitment

for i in 0..20:
    if path_bits[i] == 1:
        curr = Poseidon(curr, siblings[i])      // sibling on right
    else:
        curr = Poseidon(siblings[i], curr)      // sibling on left

assert curr == published_root
```

---

## Deterministic Padding

When building a tree with fewer than 2^20 leaves:

1. Pad with `FieldElement::ZERO` (0x0000...0000, 32 zero bytes)
2. Padding goes at the END of the leaf array
3. Tree is always full depth 20

**Critical:** CLI, verifier, and mobile must all use the same padding value.

---

## Storage Rules

### Mobile Storage

Witness must be stored and retrieved by:
- Key: `(client_id, root_id)`
- Or: `(client_id, purpose_id, root_id)` for multi-purpose support

**Do not** assume one witness applies to all roots — roots rotate.

### Root Selection at Login

The login QR/deep link provides:
- `client_id` (always)
- `required_root_id` (when membership required)
- `purpose_id` (derived from root)

Mobile uses `required_root_id` to select the exact witness.

If `required_root_id` is missing but membership is optional, mobile may:
1. Call `GET /v1/roots/current?client_id=...`
2. Find active root matching desired purpose
3. Use witness for that root

---

## Implementation Notes

1. `leaf_index` is intentionally omitted from witnesses (privacy) — use `mapping.json` for enterprise correlation
2. If path_bits packing is added later, add `path_bits_encoding` field and bump version
3. This spec matches `btcdid_core/src/membership/merkle.rs` — do not change one without the other

---

## Test Vector

### Minimal Tree (2 leaves, padded to depth 20)

To generate a canonical test vector, run:

```bash
cd native/btcdid_core
cargo test test_witness_spec_vector -- --nocapture
```

**Test Setup:**
```
leaf_0 = FieldElement::from_u64(1)  // 0x0000...0001
leaf_1 = FieldElement::from_u64(2)  // 0x0000...0002
padding = FieldElement::ZERO        // 0x0000...0000

Tree has 2 real leaves + padding to 2^20 leaves
```

**Verification Algorithm (pseudocode):**
```python
def verify_witness(leaf, siblings, path_bits, expected_root):
    curr = leaf
    for i in range(20):
        if path_bits[i] == 1:  # sibling is RIGHT
            curr = poseidon(curr, siblings[i])
        else:                   # sibling is LEFT
            curr = poseidon(siblings[i], curr)
    return curr == expected_root
```

**Self-Test Script:**

Create `scripts/verify_witness.py`:
```python
#!/usr/bin/env python3
"""Verify a witness against a root using the spec's algorithm."""
import json
import sys

def verify(witness_path, leaf_commitment_hex):
    with open(witness_path) as f:
        w = json.load(f)
    
    # Your Poseidon implementation here
    # curr = leaf_commitment
    # for i in range(20):
    #     if w["path_bits"][i] == 1:
    #         curr = poseidon(curr, w["siblings"][i])
    #     else:
    #         curr = poseidon(w["siblings"][i], curr)
    # return curr == expected_root
    pass

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: verify_witness.py <witness.json> <leaf_commitment_hex>")
        sys.exit(1)
    verify(sys.argv[1], sys.argv[2])
```

### Interop Test

Before mobile release, run this end-to-end check:

1. **CLI:** Generate tree with 3 test commitments → `root.json` + `witnesses/`
2. **Server:** Publish root via `POST /v1/roots`
3. **Rust:** Load witness, call `verify_merkle_path()` → must return true
4. **Mobile (emulator):** Load same witness, call JNI `verifyMembership()` → must return true

All four must agree on the same root.
