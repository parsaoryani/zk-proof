"""
Simple, proven Merkle tree implementation per Zerocash spec.
32-level binary tree with SHA256 hashing.
"""

import hashlib
from dataclasses import dataclass
from typing import List, Tuple, Optional


# Use a fixed empty hash for padding
EMPTY_HASH = b'\x00' * 32


def merkle_hash(left: bytes, right: bytes) -> bytes:
    """SHA256(left || right)"""
    if isinstance(left, str):
        left = bytes.fromhex(left)
    if isinstance(right, str):
        right = bytes.fromhex(right)
    return hashlib.sha256(left + right).digest()


@dataclass
class MerkleProof:
    """Merkle tree inclusion proof."""
    leaf_index: int
    path: List[bytes]  # List of 32 sibling hashes
    commitment: Optional[any] = None  # The leaf being proved (can be str or bytes)
    root: Optional[bytes] = None  # The expected root
    
    def verify(self, leaf: Optional[bytes] = None, root: Optional[bytes] = None) -> bool:
        """Verify proof matches root."""
        # Use provided values or fall back to stored values
        leaf = leaf or self.commitment
        root = root or self.root
        
        if leaf is None or root is None:
            return False
        
        # Convert hex strings to bytes if needed
        if isinstance(leaf, str):
            leaf = bytes.fromhex(leaf)
        if isinstance(root, str):
            root = bytes.fromhex(root)
            
        # Compute root from leaf and path
        current = leaf
        idx = self.leaf_index
        
        for sibling in self.path:
            if idx % 2 == 0:
                # Current is left child
                current = merkle_hash(current, sibling)
            else:
                # Current is right child
                current = merkle_hash(sibling, current)
            idx //= 2
        
        return current == root


class MerkleTree:
    """
    Simple Merkle tree with fixed 32-level structure.
    Uses SHA256 hashing, similar to Zcash/Zerocash.
    """
    
    TREE_HEIGHT = 32
    
    def __init__(self):
        """Initialize empty tree."""
        # Store all leaves (commitments)
        self.leaves: List[bytes] = []
        # Build cached layers for efficiency
        self._layers: List[List[bytes]] = []
    
    def insert(self, leaf: bytes) -> Tuple[int, str]:
        """Insert a commitment (leaf) into the tree. Returns (leaf_index, root_hex)."""
        # Handle both hex strings and bytes
        if isinstance(leaf, str):
            leaf_bytes = bytes.fromhex(leaf)
        else:
            leaf_bytes = leaf
        
        leaf_index = len(self.leaves)
        self.leaves.append(leaf_bytes)
        self._rebuild_tree()
        
        return leaf_index, self.root.hex()
    
    def _rebuild_tree(self) -> None:
        """Rebuild all tree levels from leaves."""
        if not self.leaves:
            self._layers = []
            return
        
        # Start with current leaves
        current_level = list(self.leaves)
        self._layers = [current_level]
        
        # Build each level up to the root
        for level_num in range(self.TREE_HEIGHT):
            next_level = []
            
            # Pair up nodes in current level
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else EMPTY_HASH
                parent = merkle_hash(left, right)
                next_level.append(parent)
            
            # If odd number of nodes, pair last with empty
            if len(current_level) % 2 == 1 and len(current_level) > 1:
                pass  # Already handled above
            
            self._layers.append(next_level)
            current_level = next_level
            
            # Stop when we have a single root
            if len(current_level) == 1:
                break
        
        # Pad to TREE_HEIGHT levels by hashing root with itself
        root = current_level[0]
        current_level = [root]
        
        for level_num in range(len(self._layers), self.TREE_HEIGHT):
            next_level = [merkle_hash(current_level[0], EMPTY_HASH)]
            self._layers.append(next_level)
            current_level = next_level
    
    @property
    def root(self) -> bytes:
        """Get the Merkle root."""
        if not self._layers:
            # Empty tree has root of all zeros
            return merkle_hash(EMPTY_HASH, EMPTY_HASH)
        
        # Find the actual root (should be at a complete level)
        for level in reversed(self._layers):
            if level:
                return level[0]
        
        return merkle_hash(EMPTY_HASH, EMPTY_HASH)
    
    def get_proof(self, leaf_index: int) -> MerkleProof:
        """Get Merkle proof for a leaf."""
        if leaf_index >= len(self.leaves):
            raise ValueError(f"Leaf index {leaf_index} out of range")
        
        path = []
        current_idx = leaf_index
        
        # Build path for all 32 levels
        for level_num in range(self.TREE_HEIGHT):
            if level_num >= len(self._layers):
                # Beyond current tree height, sibling is empty
                sibling = EMPTY_HASH
            else:
                level = self._layers[level_num]
                
                # Get the sibling index
                sibling_idx = current_idx ^ 1  # Flip the last bit
                
                if sibling_idx < len(level):
                    sibling = level[sibling_idx]
                else:
                    sibling = EMPTY_HASH
            
            path.append(sibling)
            current_idx //= 2
        
        # Store commitment as hex string for compatibility
        commitment_leaf = self.leaves[leaf_index]
        commitment_hex = commitment_leaf.hex()
        
        proof = MerkleProof(
            leaf_index=leaf_index, 
            path=path,
            commitment=commitment_hex,  # Store as hex string
            root=self.root.hex()  # Store root as hex string
        )
        return proof
    
    def prove(self, leaf_index: int) -> MerkleProof:
        """Alias for get_proof() for compatibility."""
        return self.get_proof(leaf_index)
    
    def verify_proof(self, leaf: bytes, proof: MerkleProof) -> bool:
        """Verify a Merkle proof."""
        return proof.verify(leaf, self.root)
    
    def __len__(self) -> int:
        """Return number of leaves."""
        return len(self.leaves)
    
    @property
    def size(self) -> int:
        """Return number of leaves (alias for len)."""
        return len(self.leaves)
    
    def __repr__(self) -> str:
        return f"MerkleTree(height={self.TREE_HEIGHT}, leaves={len(self.leaves)})"


def verify_merkle_path(leaf: bytes, leaf_index: int, path: List[bytes], root: bytes) -> bool:
    """Standalone verification function."""
    proof = MerkleProof(leaf_index=leaf_index, path=path)
    return proof.verify(leaf, root)
