#!/usr/bin/env python3
"""
sbm-tree: Enterprise Merkle tree builder for SignedByMe

Builds a Merkle tree from leaf commitments using SHA-256.
Outputs root.json (for API publish) and witnesses/*.json (per-user).

IMPORTANT: This tool uses SHA-256 with "merkle:" domain separator,
matching the Rust implementation in merkle_hash.rs and the Python
API in membership.py.

Usage:
    python sbm_tree.py build --client-id acme_corp --purpose allowlist \
        --commitments commitments.csv --output ./output

Commitments CSV format (one hex commitment per line, no header):
    0x1234...
    0x5678...
"""

import argparse
import json
import os
import sys
import hashlib
from pathlib import Path
from typing import List, Tuple
from dataclasses import dataclass
import time

# Constants matching WITNESS_SPEC.md
TREE_DEPTH = 20
HASH_ALG = "sha256-merkle"  # Changed from "poseidon"
WITNESS_VERSION = 1

# Domain separators matching Rust merkle_hash.rs
MERKLE_DOMAIN = b"merkle:"
LEAF_DOMAIN = b"leaf:"


def merkle_hash_pair(left: bytes, right: bytes) -> bytes:
    """
    Hash two children to create a parent node.
    
    Uses: SHA256("merkle:" || left || right)
    
    This matches the Rust implementation in merkle_hash.rs:
    ```rust
    pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(MERKLE_DOMAIN);  // b"merkle:"
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
    ```
    """
    return hashlib.sha256(MERKLE_DOMAIN + left + right).digest()


def hash_leaf(value: bytes) -> bytes:
    """
    Hash a leaf value.
    
    Uses: SHA256("leaf:" || value)
    """
    return hashlib.sha256(LEAF_DOMAIN + value).digest()


@dataclass
class PathSibling:
    """A sibling in the Merkle path"""
    hash: bytes  # 32 bytes
    is_right: bool  # True if sibling is on the right


@dataclass  
class MerklePath:
    """Merkle path from leaf to root"""
    siblings: List[PathSibling]
    
    def compute_root(self, leaf: bytes) -> bytes:
        """Compute root from leaf using this path"""
        current = leaf
        for sibling in self.siblings:
            if sibling.is_right:
                # sibling on right: H(current, sibling)
                current = merkle_hash_pair(current, sibling.hash)
            else:
                # sibling on left: H(sibling, current)
                current = merkle_hash_pair(sibling.hash, current)
        return current


class MerkleTree:
    """SHA-256 Merkle tree with zero padding"""
    
    def __init__(self, leaves: List[bytes], depth: int = TREE_DEPTH):
        if not leaves:
            raise ValueError("Cannot build empty tree")
        
        self.depth = depth
        
        # Pad to 2^depth leaves
        target_size = 2 ** depth
        self.original_count = len(leaves)
        
        if len(leaves) > target_size:
            raise ValueError(f"Too many leaves: {len(leaves)} > {target_size}")
        
        # Zero padding (32 zero bytes)
        zero_leaf = bytes(32)
        padded = leaves + [zero_leaf] * (target_size - len(leaves))
        
        # Build layers bottom-up
        self.layers = [padded]
        
        while len(self.layers[-1]) > 1:
            prev = self.layers[-1]
            next_layer = []
            for i in range(0, len(prev), 2):
                h = merkle_hash_pair(prev[i], prev[i + 1])
                next_layer.append(h)
            self.layers.append(next_layer)
        
        self.root = self.layers[-1][0]
    
    def get_path(self, leaf_index: int) -> MerklePath:
        """Get Merkle path for a leaf (0-indexed)"""
        if leaf_index < 0 or leaf_index >= self.original_count:
            raise ValueError(f"Invalid leaf index: {leaf_index}")
        
        siblings = []
        idx = leaf_index
        
        for layer in self.layers[:-1]:  # All layers except root
            # Sibling index
            if idx % 2 == 0:
                sibling_idx = idx + 1
                is_right = True  # sibling is on the right
            else:
                sibling_idx = idx - 1
                is_right = False  # sibling is on the left
            
            siblings.append(PathSibling(
                hash=layer[sibling_idx],
                is_right=is_right
            ))
            
            idx //= 2
        
        return MerklePath(siblings)


def parse_hex_commitment(hex_str: str) -> bytes:
    """Parse a hex commitment string to bytes"""
    hex_str = hex_str.strip()
    if hex_str.startswith('0x') or hex_str.startswith('0X'):
        hex_str = hex_str[2:]
    # Pad to 64 hex chars (32 bytes)
    hex_str = hex_str.zfill(64)
    return bytes.fromhex(hex_str)


def load_commitments(filepath: str) -> List[bytes]:
    """Load hex commitments from CSV (one per line)"""
    commitments = []
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                commitment = parse_hex_commitment(line)
                if len(commitment) != 32:
                    print(f"Warning: Line {line_num} commitment is not 32 bytes", file=sys.stderr)
                    continue
                commitments.append(commitment)
            except Exception as e:
                print(f"Warning: Invalid commitment on line {line_num}: {e}", file=sys.stderr)
    return commitments


def build_tree(args):
    """Build Merkle tree and output root + witnesses"""
    depth = args.depth
    
    if depth != TREE_DEPTH:
        print(f"WARNING: Using depth={depth} (production requires depth={TREE_DEPTH})", file=sys.stderr)
        print(f"         Roots with depth!={TREE_DEPTH} will be REJECTED by the API", file=sys.stderr)
    
    # Load commitments
    print(f"Loading commitments from {args.commitments}...")
    commitments = load_commitments(args.commitments)
    
    if not commitments:
        print("Error: No valid commitments found", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loaded {len(commitments)} commitments")
    
    # Build tree
    print(f"Building depth-{depth} Merkle tree (SHA-256 with 'merkle:' domain)...")
    tree = MerkleTree(commitments, depth=depth)
    print(f"Root: 0x{tree.root.hex()}")
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    witnesses_dir = output_dir / "witnesses"
    witnesses_dir.mkdir(exist_ok=True)
    
    # Generate root.json
    now = int(time.time())
    root_id = f"{args.client_id}-{args.purpose}-{now}"
    
    purpose_map = {
        "none": 0,
        "allowlist": 1,
        "issuer_batch": 2,
        "revocation": 3
    }
    purpose_id = purpose_map.get(args.purpose, 0)
    
    root_json = {
        "root_id": root_id,
        "client_id": args.client_id,
        "purpose": args.purpose,
        "purpose_id": purpose_id,
        "root": "0x" + tree.root.hex(),
        "hash_alg": HASH_ALG,
        "depth": depth,
        "not_before": now,
        "expires_at": now + (365 * 86400),  # 1 year
        "description": f"{args.purpose} tree with {len(commitments)} members",
        "member_count": len(commitments)
    }
    
    root_path = output_dir / "root.json"
    with open(root_path, 'w') as f:
        json.dump(root_json, f, indent=2)
    print(f"Wrote {root_path}")
    
    # Generate witnesses
    print(f"Generating {len(commitments)} witnesses...")
    for i, commitment in enumerate(commitments):
        path = tree.get_path(i)
        
        # Verify path is correct
        computed_root = path.compute_root(commitment)
        if computed_root != tree.root:
            print(f"ERROR: Path verification failed for leaf {i}!", file=sys.stderr)
            sys.exit(1)
        
        witness = {
            "version": WITNESS_VERSION,
            "client_id": args.client_id,
            "root_id": root_id,
            "purpose_id": purpose_id,
            "hash_alg": HASH_ALG,
            "depth": depth,
            "not_before": root_json["not_before"],
            "expires_at": root_json["expires_at"],
            # Note: leaf_index intentionally omitted (privacy)
            "siblings": ["0x" + s.hash.hex() for s in path.siblings],
            "path_bits": [1 if s.is_right else 0 for s in path.siblings]
        }
        
        witness_path = witnesses_dir / f"witness_{i:06d}.json"
        with open(witness_path, 'w') as f:
            json.dump(witness, f, indent=2)
    
    print(f"Wrote {len(commitments)} witnesses to {witnesses_dir}/")
    
    # Summary
    print("\n=== Summary ===")
    print(f"Root ID: {root_id}")
    print(f"Root: 0x{tree.root.hex()}")
    print(f"Hash Algorithm: {HASH_ALG}")
    print(f"Members: {len(commitments)}")
    print(f"Depth: {depth}")
    print(f"\nTo publish root:")
    print(f"  curl -X POST https://api.signedby.me/v1/roots \\")
    print(f"    -H 'X-API-Key: YOUR_API_KEY' \\")
    print(f"    -H 'Content-Type: application/json' \\")
    print(f"    -d @{root_path}")


def verify_witness(args):
    """Verify a witness against a root"""
    with open(args.witness, 'r') as f:
        witness = json.load(f)
    
    commitment = parse_hex_commitment(args.commitment)
    
    # Reconstruct path
    siblings = []
    for i, (sib_hex, is_right) in enumerate(zip(witness["siblings"], witness["path_bits"])):
        sib_bytes = parse_hex_commitment(sib_hex)
        siblings.append(PathSibling(
            hash=sib_bytes,
            is_right=(is_right == 1)
        ))
    path = MerklePath(siblings)
    
    # Compute root
    computed_root = path.compute_root(commitment)
    
    print(f"Commitment: {args.commitment}")
    print(f"Hash Algorithm: {witness.get('hash_alg', 'sha256-merkle')}")
    print(f"Computed root: 0x{computed_root.hex()}")
    
    if args.root:
        expected = parse_hex_commitment(args.root)
        if computed_root == expected:
            print("✓ Verification PASSED")
        else:
            print(f"✗ Verification FAILED")
            print(f"  Expected: {args.root}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="sbm-tree: Enterprise Merkle tree builder for SignedByMe"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Build command
    build_parser = subparsers.add_parser("build", help="Build Merkle tree from commitments")
    build_parser.add_argument("--client-id", required=True, help="Enterprise client ID")
    build_parser.add_argument("--purpose", required=True, 
                             choices=["none", "allowlist", "issuer_batch", "revocation"],
                             help="Tree purpose")
    build_parser.add_argument("--commitments", required=True, help="Path to commitments CSV")
    build_parser.add_argument("--output", required=True, help="Output directory")
    build_parser.add_argument("--depth", type=int, default=TREE_DEPTH,
                             help=f"Tree depth (default: {TREE_DEPTH}, use smaller for testing)")
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a witness")
    verify_parser.add_argument("--witness", required=True, help="Path to witness JSON")
    verify_parser.add_argument("--commitment", required=True, help="Leaf commitment (hex)")
    verify_parser.add_argument("--root", help="Expected root (hex, optional)")
    
    args = parser.parse_args()
    
    if args.command == "build":
        build_tree(args)
    elif args.command == "verify":
        verify_witness(args)


if __name__ == "__main__":
    main()
