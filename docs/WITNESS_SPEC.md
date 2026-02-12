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
  "leaf_index": 42,
  "siblings": [
    "0x1234...64hex...",
    "0x5678...64hex...",
    ...
  ],
  "path_bits": [1, 0, 1, 0, ...]
}
```

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
| `leaf_index` | int | 0-based index of leaf in tree (for debugging) |
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

1. `leaf_index` is included for debugging/audit but not cryptographically verified
2. If path_bits packing is added later, add `path_bits_encoding` field and bump version
3. This spec matches `btcdid_core/src/membership/merkle.rs` — do not change one without the other

---

## Test Vector

**TODO:** Add a concrete test vector with:
- `leaf_secret`
- `leaf_commitment`
- Small tree (e.g., 4 leaves, padded to 2^20)
- Full witness JSON
- Expected root

This allows CLI/mobile/verifier to independently verify correctness.
