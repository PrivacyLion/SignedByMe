# sbm-tree

Enterprise Merkle tree builder for SignedByMe.

Builds a Poseidon Merkle tree from leaf commitments and outputs:
- `root.json` — Publishable to `/v1/roots` API
- `witnesses/*.json` — One per member, distribute to users

## Usage

### Build a tree

```bash
python3 sbm_tree.py build \
    --client-id acme_corp \
    --purpose allowlist \
    --commitments commitments.csv \
    --output ./output
```

### Verify a witness

```bash
python3 sbm_tree.py verify \
    --witness witnesses/witness_000000.json \
    --commitment 0x1234... \
    --root 0x5678...
```

## Input Format

`commitments.csv` — one hex commitment per line:

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
  "root_id": "acme_corp-allowlist-1770925719",
  "client_id": "acme_corp",
  "purpose": "allowlist",
  "purpose_id": 1,
  "root": "0x...",
  "hash_alg": "poseidon",
  "depth": 20,
  "not_before": 1770925719,
  "expires_at": 1802461719,
  "description": "allowlist tree with 3 members",
  "member_count": 3
}
```

### witnesses/witness_NNNNNN.json

```json
{
  "version": 1,
  "client_id": "acme_corp",
  "root_id": "acme_corp-allowlist-1770925719",
  "purpose_id": 1,
  "hash_alg": "poseidon",
  "depth": 20,
  "not_before": 1770925719,
  "expires_at": 1802461719,
  "leaf_index": 0,
  "siblings": ["0x...", "0x...", ...],
  "path_bits": [1, 0, 1, ...]
}
```

## Testing

Use `--depth` for faster testing (production requires depth=20):

```bash
python3 sbm_tree.py build \
    --client-id test \
    --purpose allowlist \
    --commitments test_commitments.csv \
    --output ./test_output \
    --depth 4
```

⚠️ Roots with depth ≠ 20 will be **rejected** by the API.

## Workflow

1. **Collect commitments** — User generates `leaf_commitment = Poseidon(domain_sep || leaf_secret)` during enrollment
2. **Build tree** — Run `sbm_tree.py build` with all commitments
3. **Publish root** — POST `root.json` to `/v1/roots`
4. **Distribute witnesses** — Give each user their `witness_NNNNNN.json`
5. **User proves** — Mobile app uses witness + `leaf_secret` to generate membership proof

## Spec Compliance

See `docs/WITNESS_SPEC.md` for:
- Path bit semantics (`1 = sibling RIGHT`)
- Sibling ordering (`leaf → root`)
- Padding rules (`FieldElement::ZERO`)
