#!/usr/bin/env python3
"""
sbm-tree: Enterprise Merkle tree builder for SignedByMe

Builds a depth-20 Poseidon Merkle tree from leaf commitments.
Outputs root.json (for API publish) and witnesses/*.json (per-user).

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
from pathlib import Path
from typing import List, Tuple
from dataclasses import dataclass
import time

# Constants matching WITNESS_SPEC.md
TREE_DEPTH = 20
HASH_ALG = "poseidon"
WITNESS_VERSION = 1

# Field element size
FIELD_SIZE = 32  # bytes


@dataclass
class FieldElement:
    """256-bit field element (simplified, matching Rust btcdid_core)"""
    limbs: Tuple[int, int, int, int]  # 4 x 64-bit limbs, little-endian
    
    @classmethod
    def zero(cls) -> 'FieldElement':
        return cls((0, 0, 0, 0))
    
    @classmethod
    def from_u64(cls, val: int) -> 'FieldElement':
        return cls((val & 0xFFFFFFFFFFFFFFFF, 0, 0, 0))
    
    @classmethod
    def from_bytes_be(cls, data: bytes) -> 'FieldElement':
        """Parse from big-endian bytes"""
        # Pad to 32 bytes
        if len(data) < 32:
            data = b'\x00' * (32 - len(data)) + data
        data = data[:32]
        
        # Convert to 4 u64 limbs (little-endian limb order)
        limbs = []
        for i in range(4):
            start = 32 - (i + 1) * 8
            chunk = data[start:start + 8]
            limbs.append(int.from_bytes(chunk, 'big'))
        return cls(tuple(limbs))
    
    @classmethod
    def from_hex(cls, hex_str: str) -> 'FieldElement':
        """Parse from hex string (with or without 0x prefix)"""
        if hex_str.startswith('0x') or hex_str.startswith('0X'):
            hex_str = hex_str[2:]
        # Pad to 64 hex chars
        hex_str = hex_str.zfill(64)
        return cls.from_bytes_be(bytes.fromhex(hex_str))
    
    def to_bytes_be(self) -> bytes:
        """Convert to big-endian bytes"""
        result = b''
        for i in range(3, -1, -1):
            result += self.limbs[i].to_bytes(8, 'big')
        return result
    
    def to_hex(self) -> str:
        """Convert to hex string with 0x prefix"""
        return '0x' + self.to_bytes_be().hex()
    
    def add(self, other: 'FieldElement') -> 'FieldElement':
        """Add two field elements (wrapping)"""
        result = []
        carry = 0
        for i in range(4):
            s = self.limbs[i] + other.limbs[i] + carry
            result.append(s & 0xFFFFFFFFFFFFFFFF)
            carry = s >> 64
        return FieldElement(tuple(result))
    
    def mul(self, other: 'FieldElement') -> 'FieldElement':
        """Multiply (simplified - low bits only, matching Rust)"""
        low = (self.limbs[0] * other.limbs[0]) & 0xFFFFFFFFFFFFFFFF
        return FieldElement((low, 0, 0, 0))
    
    def pow5(self) -> 'FieldElement':
        """x^5 (S-box)"""
        x2 = self.mul(self)
        x4 = x2.mul(x2)
        return x4.mul(self)
    
    def __eq__(self, other) -> bool:
        return self.limbs == other.limbs
    
    def __hash__(self) -> int:
        return hash(self.limbs)


class PoseidonHasher:
    """Poseidon hasher matching Rust btcdid_core implementation"""
    
    def __init__(self):
        self.state = [FieldElement.zero(), FieldElement.zero(), FieldElement.zero()]
        self.pos = 0
    
    def update(self, input_fe: FieldElement):
        self.state[self.pos] = self.state[self.pos].add(input_fe)
        self.pos += 1
        
        if self.pos == 2:
            self._permute()
            self.pos = 0
    
    def finalize(self) -> FieldElement:
        if self.pos > 0:
            self._permute()
        return self.state[0]
    
    def _permute(self):
        # Full rounds (first 4)
        for r in range(4):
            self._add_round_constant(r)
            self._sbox_full()
            self._mds_mix()
        
        # Partial rounds (57)
        for r in range(4, 61):
            self._add_round_constant(r)
            self._sbox_partial()
            self._mds_mix()
        
        # Full rounds (last 4)
        for r in range(61, 65):
            self._add_round_constant(r)
            self._sbox_full()
            self._mds_mix()
    
    def _add_round_constant(self, round_num: int):
        for i in range(3):
            c = FieldElement.from_u64(round_num * 3 + i)
            self.state[i] = self.state[i].add(c)
    
    def _sbox_full(self):
        for i in range(3):
            self.state[i] = self.state[i].pow5()
    
    def _sbox_partial(self):
        self.state[2] = self.state[2].pow5()
    
    def _mds_mix(self):
        old = self.state[:]
        three = FieldElement.from_u64(3)
        self.state[0] = old[0].mul(three).add(old[1]).add(old[2])
        self.state[1] = old[0].add(old[1].mul(three)).add(old[2])
        self.state[2] = old[0].add(old[1]).add(old[2].mul(three))


def poseidon_hash_pair(left: FieldElement, right: FieldElement) -> FieldElement:
    """Hash two field elements (for Merkle tree)"""
    hasher = PoseidonHasher()
    hasher.update(left)
    hasher.update(right)
    return hasher.finalize()


@dataclass
class PathSibling:
    """A sibling in the Merkle path"""
    hash: FieldElement
    is_right: bool  # True if sibling is on the right


@dataclass  
class MerklePath:
    """Merkle path from leaf to root"""
    siblings: List[PathSibling]
    
    def compute_root(self, leaf: FieldElement) -> FieldElement:
        """Compute root from leaf using this path"""
        current = leaf
        for sibling in self.siblings:
            if sibling.is_right:
                # sibling on right: H(current, sibling)
                current = poseidon_hash_pair(current, sibling.hash)
            else:
                # sibling on left: H(sibling, current)
                current = poseidon_hash_pair(sibling.hash, current)
        return current


class MerkleTree:
    """Poseidon Merkle tree with zero padding"""
    
    def __init__(self, leaves: List[FieldElement], depth: int = TREE_DEPTH):
        if not leaves:
            raise ValueError("Cannot build empty tree")
        
        self.depth = depth
        
        # Pad to 2^depth leaves
        target_size = 2 ** depth
        self.original_count = len(leaves)
        
        if len(leaves) > target_size:
            raise ValueError(f"Too many leaves: {len(leaves)} > {target_size}")
        
        padded = leaves + [FieldElement.zero()] * (target_size - len(leaves))
        
        # Build layers bottom-up
        self.layers = [padded]
        
        while len(self.layers[-1]) > 1:
            prev = self.layers[-1]
            next_layer = []
            for i in range(0, len(prev), 2):
                h = poseidon_hash_pair(prev[i], prev[i + 1])
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


def load_commitments(filepath: str) -> List[FieldElement]:
    """Load hex commitments from CSV (one per line)"""
    commitments = []
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                fe = FieldElement.from_hex(line)
                commitments.append(fe)
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
    print(f"Building depth-{depth} Merkle tree (padding with zeros)...")
    tree = MerkleTree(commitments, depth=depth)
    print(f"Root: {tree.root.to_hex()}")
    
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
        "root": tree.root.to_hex(),
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
            "siblings": [s.hash.to_hex() for s in path.siblings],
            "path_bits": [1 if s.is_right else 0 for s in path.siblings]
        }
        
        witness_path = witnesses_dir / f"witness_{i:06d}.json"
        with open(witness_path, 'w') as f:
            json.dump(witness, f, indent=2)
    
    print(f"Wrote {len(commitments)} witnesses to {witnesses_dir}/")
    
    # Summary
    print("\n=== Summary ===")
    print(f"Root ID: {root_id}")
    print(f"Root: {tree.root.to_hex()}")
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
    
    commitment = FieldElement.from_hex(args.commitment)
    
    # Reconstruct path
    siblings = []
    for i, (sib_hex, is_right) in enumerate(zip(witness["siblings"], witness["path_bits"])):
        siblings.append(PathSibling(
            hash=FieldElement.from_hex(sib_hex),
            is_right=(is_right == 1)
        ))
    path = MerklePath(siblings)
    
    # Compute root
    computed_root = path.compute_root(commitment)
    
    print(f"Commitment: {args.commitment}")
    print(f"Computed root: {computed_root.to_hex()}")
    
    if args.root:
        expected = FieldElement.from_hex(args.root)
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
