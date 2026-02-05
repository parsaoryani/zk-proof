"""Merkle Tree implementation for storing coin commitments (Zerocash Foundation)."""

from typing import List, Dict, Tuple, Optional
import math

from zkm.utils.hash import merkle_hash, sha256
from zkm.exceptions import (
    TreeHeightExceededError,
    InvalidLeafIndexError,
    InvalidMerkleRootError,
    MerkleTreeError,
)


class MerkleTree:
    """
    Merkle Tree for storing and verifying coin commitments.

    Paper Reference: Zerocash - Section 3.2

    This implementation uses a binary tree structure where:
    - Leaves are coin commitments
    - Internal nodes are hash values
    - Root hash verifies tree integrity
    """

    # Constants
    DEFAULT_HEIGHT = 32
    NULL_LEAF = b"\x00" * 32  # Placeholder for empty leaves

    def __init__(self, tree_height: int = DEFAULT_HEIGHT):
        """
        Initialize empty Merkle tree.

        Args:
            tree_height: Height of the tree (default 32)

        Raises:
            ValueError: If height is invalid
        """
        if tree_height < 1 or tree_height > 64:
            raise ValueError("Tree height must be between 1 and 64")

        self.height = tree_height
        self.max_leaves = 2**tree_height

        # Store leaves in a list
        self.leaves: List[bytes] = []

        # Store tree nodes as a dictionary: (level, position) -> hash
        self.nodes: Dict[Tuple[int, int], bytes] = {}

        # Root is initially NULL
        self._root = self._compute_null_root()

    def _compute_null_root(self) -> bytes:
        """
        Compute root hash when tree is empty.

        Uses the NULL_LEAF pattern hashed up the tree.
        """
        current = self.NULL_LEAF
        for _ in range(self.height):
            current = merkle_hash(current, current)
        return current

    def insert(self, commitment: bytes) -> int:
        """
        Insert commitment leaf and return leaf index.

        Args:
            commitment: H(secret || randomness) - 32 bytes

        Returns:
            int: Leaf index in tree

        Raises:
            InvalidLeafIndexError: If tree is full
            ValueError: If commitment format is invalid
        """
        if not isinstance(commitment, bytes) or len(commitment) != 32:
            raise ValueError("Commitment must be 32 bytes")

        if len(self.leaves) >= self.max_leaves:
            raise TreeHeightExceededError(f"Tree is full (max {self.max_leaves} commitments)")

        leaf_index = len(self.leaves)
        self.leaves.append(commitment)

        # Store leaf at level 0
        self.nodes[(0, leaf_index)] = commitment

        # Compute parent hashes up the tree
        self._compute_parent_hashes(leaf_index)

        return leaf_index

    def _compute_parent_hashes(self, leaf_index: int) -> None:
        """
        Update parent hashes up the tree from a leaf.

        This is called whenever a leaf is inserted or modified.

        Args:
            leaf_index: Index of the leaf that changed
        """
        position = leaf_index

        for level in range(self.height):
            # Get position at this level
            sibling_position = position ^ 1  # XOR with 1 to get sibling
            is_left = position % 2 == 0

            # Get child hashes
            left_key = (level, position if is_left else sibling_position)
            right_key = (level, sibling_position if is_left else position)

            left_hash = self.nodes.get(left_key, self.NULL_LEAF)
            right_hash = self.nodes.get(right_key, self.NULL_LEAF)

            # Compute parent
            parent = merkle_hash(left_hash, right_hash)
            parent_position = position >> 1  # Integer division by 2

            # Store parent
            parent_key = (level + 1, parent_position)
            self.nodes[parent_key] = parent

            # Update root after each level
            if level == self.height - 1:
                self._root = parent

            # Move up to parent for next iteration
            position = parent_position

    def get_path(self, leaf_index: int) -> List[bytes]:
        """
        Return Merkle path (sibling hashes) for leaf verification.

        The path includes all sibling hashes needed to reconstruct the root
        from the leaf hash.

        Args:
            leaf_index: Index of the leaf

        Returns:
            List[bytes]: Path of sibling hashes from leaf to root

        Raises:
            InvalidLeafIndexError: If leaf index is invalid
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise InvalidLeafIndexError(f"Invalid leaf index: {leaf_index}")

        path = []
        position = leaf_index

        for level in range(self.height):
            # Get sibling position
            sibling_position = position ^ 1

            # Get sibling hash
            sibling_key = (level, sibling_position)
            sibling_hash = self.nodes.get(sibling_key, self.NULL_LEAF)

            path.append(sibling_hash)

            # Move up to parent
            position >>= 1

        return path

    def verify_path(self, commitment: bytes, path: List[bytes], leaf_index: int) -> bool:
        """
        Verify that commitment exists in tree via Merkle path.

        Reconstructs the root hash using the commitment and path,
        then compares with the current root.

        Args:
            commitment: Original leaf value (32 bytes)
            path: Merkle path (list of hashes)
            leaf_index: Position of leaf

        Returns:
            bool: True if path is valid and leads to current root

        Raises:
            ValueError: If inputs are invalid format
        """
        try:
            if not isinstance(commitment, bytes) or len(commitment) != 32:
                raise ValueError("Commitment must be 32 bytes")

            if not isinstance(path, list) or len(path) != self.height:
                raise ValueError(f"Path must have exactly {self.height} hashes")

            if leaf_index < 0 or leaf_index >= self.max_leaves:
                raise ValueError(f"Invalid leaf index: {leaf_index}")

            # Reconstruct root from commitment using path
            current = commitment
            position = leaf_index

            for level, sibling_hash in enumerate(path):
                is_left = position % 2 == 0

                if is_left:
                    current = merkle_hash(current, sibling_hash)
                else:
                    current = merkle_hash(sibling_hash, current)

                position >>= 1

            # Check if reconstructed root matches current root
            return current == self.root

        except (ValueError, TypeError):
            return False

    @property
    def root(self) -> bytes:
        """Get the current Merkle root hash."""
        return self._root

    @root.setter
    def root(self, value: bytes) -> None:
        """Set the root hash."""
        self._root = value

    def get_state(self) -> dict:
        """
        Get the current state of the tree for serialization.

        Returns:
            dict: Tree state including leaves, height, and root
        """
        return {
            "height": self.height,
            "max_leaves": self.max_leaves,
            "num_leaves": len(self.leaves),
            "leaves": [leaf.hex() for leaf in self.leaves],
            "root": self.root.hex(),
        }

    def __len__(self) -> int:
        """Return the number of leaves in the tree."""
        return len(self.leaves)

    def __repr__(self) -> str:
        """String representation of the tree."""
        return (
            f"MerkleTree(height={self.height}, "
            f"leaves={len(self.leaves)}/{self.max_leaves}, "
            f"root={self.root.hex()[:16]}...)"
        )
