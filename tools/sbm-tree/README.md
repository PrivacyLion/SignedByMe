# sbm-tree

Enterprise Merkle tree builder for SignedByMe.

Builds a Poseidon Merkle tree from leaf commitments and outputs:
- `root.json` — Publishable to `/v1/roots` API
- `witnesses/*.json` — One per member, distribute to users
- `mapping.json` — Maps commitments to witness files (enterprise reference only)

## Implementations

| Version | Use Case | Performance |
|---------|----------|-------------|
| **Rust** (`native/btcdid_core/src/bin/sbm_tree.rs`) | Production | ~5 sec for depth=20 |
| **Python** (`tools/sbm-tree/sbm_tree.py`) | Demo/pilot only | Too slow for depth=20 |

⚠️ **For production cohorts (depth=20), use the Rust CLI.**

## Usage (Rust)

Build:
```bash
cd native/btcdid_core
cargo build --release --bin sbm_tree
```

Build a tree:
```bash
./target/release/sbm_tree build \
    --client-id acme_corp \
    --purpose issuer_batch \
    --commitments commitments.csv \
    --output ./output
```

Verify a witness:
```bash
./target/release/sbm_tree verify \
    --witness witnesses/witness_000000.json \
    --commitment 0x1234...
```

## Usage (Python — demo only)

```bash
python3 sbm_tree.py build \
    --client-id acme_corp \
    --purpose issuer_batch \
    --commitments commitments.csv \
    --output ./output \
    --depth 4  # Use small depth for testing
```

## Input Format

`commitments.csv` — one hex commitment per line (enterprise collects these from users):

```
# Comments start with #
0x0000000000000000000000000000000000000000000000000000000000000001
0x0000000000000000000000000000000000000000000000000000000000000002
0x0000000000000000000000000000000000000000000000000000000000000003
```

## Output

### root.json

```json
{
  "root_id": "acme_corp-issuer_batch-1770925719",
  "client_id": "acme_corp",
  "purpose": "issuer_batch",
  "purpose_id": 2,
  "root": "0x...",
  "hash_alg": "poseidon",
  "depth": 20,
  "not_before": 1770925719,
  "expires_at": 1802461719,
  "description": "issuer_batch tree with 3 members",
  "member_count": 3
}
```

### witnesses/witness_NNNNNN.json

```json
{
  "version": 1,
  "client_id": "acme_corp",
  "root_id": "acme_corp-issuer_batch-1770925719",
  "purpose_id": 2,
  "hash_alg": "poseidon",
  "depth": 20,
  "not_before": 1770925719,
  "expires_at": 1802461719,
  "siblings": ["0x...", "0x...", ...],
  "path_bits": [1, 0, 1, ...]
}
```

Note: `leaf_index` is intentionally omitted from witnesses (privacy). 
Use `mapping.json` for enterprise-side correlation.

### mapping.json

```json
[
  {"leaf_index": 0, "commitment": "0x...", "witness_file": "witness_000000.json"},
  {"leaf_index": 1, "commitment": "0x...", "witness_file": "witness_000001.json"}
]
```

## Workflow

1. **Enterprise collects commitments** — Users generate `leaf_commitment = Poseidon(domain_sep || leaf_secret)` during enrollment and submit to enterprise
2. **Enterprise ingests commitments** — Compile into `commitments.csv`
3. **Build tree** — Run `sbm_tree build` to generate root + witnesses
4. **Publish root** — POST `root.json` to `/v1/roots` API
5. **Distribute witnesses** — Enterprise gives each user their witness file (out-of-band)
6. **User proves membership** — Mobile app uses witness + `leaf_secret` to generate membership proof at login

## Spec Compliance

See `docs/WITNESS_SPEC.md` for:
- Path bit semantics (`1 = sibling RIGHT`)
- Sibling ordering (`leaf → root`)
- Padding rules (`FieldElement::ZERO`)
