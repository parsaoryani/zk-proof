"""Tests for Merkle Tree implementation."""

import pytest
from zkm.core.merkle_tree import MerkleTree
from zkm.exceptions import (
    TreeHeightExceededError,
    InvalidLeafIndexError,
    InvalidMerkleRootError,
)
import os


@pytest.fixture
def merkle_tree():
    """Create a test Merkle tree."""
    return MerkleTree(tree_height=8)


@pytest.fixture
def sample_commitment():
    """Create a sample commitment."""
    return os.urandom(32)


class TestMerkleTreeInitialization:
    """Tests for tree initialization."""
    
    def test_tree_creation_default(self):
        """Test creating tree with default height."""
        tree = MerkleTree()
        assert tree.height == 32
        assert len(tree) == 0
    
    def test_tree_creation_custom_height(self):
        """Test creating tree with custom height."""
        for height in [4, 8, 16, 32]:
            tree = MerkleTree(tree_height=height)
            assert tree.height == height
            assert tree.max_leaves == 2 ** height
    
    def test_tree_invalid_height(self):
        """Test that invalid heights raise errors."""
        with pytest.raises(ValueError):
            MerkleTree(tree_height=0)
        with pytest.raises(ValueError):
            MerkleTree(tree_height=-1)
        with pytest.raises(ValueError):
            MerkleTree(tree_height=100)
    
    def test_tree_null_root(self):
        """Test that empty tree has NULL root."""
        tree = MerkleTree(tree_height=4)
        assert tree.root is not None
        assert len(tree.root) == 32


class TestMerkleTreeInsertion:
    """Tests for leaf insertion."""
    
    def test_insert_single_commitment(self, merkle_tree, sample_commitment):
        """Test inserting a single commitment."""
        index = merkle_tree.insert(sample_commitment)
        assert index == 0
        assert len(merkle_tree) == 1
        assert merkle_tree.leaves[0] == sample_commitment
    
    def test_insert_multiple_commitments(self, merkle_tree):
        """Test inserting multiple commitments."""
        commitments = [os.urandom(32) for _ in range(10)]
        indices = []
        
        for i, commitment in enumerate(commitments):
            index = merkle_tree.insert(commitment)
            assert index == i
            indices.append(index)
        
        assert len(merkle_tree) == 10
        assert merkle_tree.leaves == commitments
    
    def test_insert_invalid_commitment_format(self, merkle_tree):
        """Test that invalid commitments are rejected."""
        with pytest.raises(ValueError):
            merkle_tree.insert(b"short")  # Too short
        
        with pytest.raises(ValueError):
            merkle_tree.insert(b"x" * 64)  # Too long
        
        with pytest.raises(ValueError):
            merkle_tree.insert("not bytes")  # Wrong type
    
    def test_tree_capacity_exceeded(self):
        """Test that tree capacity is enforced."""
        small_tree = MerkleTree(tree_height=2)  # Max 4 leaves
        
        for i in range(4):
            small_tree.insert(os.urandom(32))
        
        with pytest.raises(TreeHeightExceededError):
            small_tree.insert(os.urandom(32))
    
    def test_root_changes_on_insert(self, merkle_tree, sample_commitment):
        """Test that root changes after insertion."""
        root_before = merkle_tree.root
        merkle_tree.insert(sample_commitment)
        root_after = merkle_tree.root
        
        assert root_before != root_after


class TestMerklePathGeneration:
    """Tests for getting Merkle paths."""
    
    def test_get_path_single_leaf(self, merkle_tree, sample_commitment):
        """Test getting path for single leaf."""
        index = merkle_tree.insert(sample_commitment)
        path = merkle_tree.get_path(index)
        
        assert isinstance(path, list)
        assert len(path) == merkle_tree.height
        assert all(isinstance(h, bytes) and len(h) == 32 for h in path)
    
    def test_get_path_multiple_leaves(self, merkle_tree):
        """Test getting paths for multiple leaves."""
        commitments = [os.urandom(32) for _ in range(5)]
        indices = []
        
        for commitment in commitments:
            index = merkle_tree.insert(commitment)
            indices.append(index)
        
        for i, index in enumerate(indices):
            path = merkle_tree.get_path(index)
            assert len(path) == merkle_tree.height
    
    def test_get_path_invalid_index(self, merkle_tree, sample_commitment):
        """Test that invalid indices raise errors."""
        merkle_tree.insert(sample_commitment)
        
        with pytest.raises(InvalidLeafIndexError):
            merkle_tree.get_path(-1)
        
        with pytest.raises(InvalidLeafIndexError):
            merkle_tree.get_path(100)
    
    def test_get_path_empty_tree(self, merkle_tree):
        """Test getting path from empty tree."""
        with pytest.raises(InvalidLeafIndexError):
            merkle_tree.get_path(0)


class TestMerklePathVerification:
    """Tests for verifying Merkle paths."""
    
    def test_verify_path_valid(self, merkle_tree, sample_commitment):
        """Test verifying a valid path."""
        index = merkle_tree.insert(sample_commitment)
        path = merkle_tree.get_path(index)
        
        is_valid = merkle_tree.verify_path(sample_commitment, path, index)
        assert is_valid is True
    
    def test_verify_path_multiple_leaves(self, merkle_tree):
        """Test verifying paths with multiple leaves."""
        commitments = [os.urandom(32) for _ in range(8)]
        
        for commitment in commitments:
            merkle_tree.insert(commitment)
        
        for i, commitment in enumerate(commitments):
            path = merkle_tree.get_path(i)
            assert merkle_tree.verify_path(commitment, path, i) is True
    
    def test_verify_path_wrong_commitment(self, merkle_tree, sample_commitment):
        """Test that wrong commitment fails verification."""
        index = merkle_tree.insert(sample_commitment)
        path = merkle_tree.get_path(index)
        
        wrong_commitment = os.urandom(32)
        is_valid = merkle_tree.verify_path(wrong_commitment, path, index)
        assert is_valid is False
    
    def test_verify_path_modified_path(self, merkle_tree, sample_commitment):
        """Test that modified path fails verification."""
        index = merkle_tree.insert(sample_commitment)
        path = merkle_tree.get_path(index)
        
        # Modify path
        modified_path = path.copy()
        modified_path[0] = os.urandom(32)
        
        is_valid = merkle_tree.verify_path(sample_commitment, modified_path, index)
        assert is_valid is False
    
    def test_verify_path_wrong_index(self, merkle_tree, sample_commitment):
        """Test that wrong index fails verification."""
        index = merkle_tree.insert(sample_commitment)
        path = merkle_tree.get_path(index)
        
        wrong_index = (index + 1) % merkle_tree.max_leaves
        is_valid = merkle_tree.verify_path(sample_commitment, path, wrong_index)
        assert is_valid is False
    
    def test_verify_path_invalid_format(self, merkle_tree, sample_commitment):
        """Test that invalid path format fails gracefully."""
        index = merkle_tree.insert(sample_commitment)
        
        # Wrong path length
        short_path = [os.urandom(32)] * 4
        is_valid = merkle_tree.verify_path(sample_commitment, short_path, index)
        assert is_valid is False
        
        # Wrong hash size
        bad_path = [os.urandom(16)] * merkle_tree.height
        is_valid = merkle_tree.verify_path(sample_commitment, bad_path, index)
        assert is_valid is False


class TestMerkleTreeState:
    """Tests for tree state operations."""
    
    def test_get_state(self, merkle_tree):
        """Test getting tree state."""
        commitments = [os.urandom(32) for _ in range(3)]
        for commitment in commitments:
            merkle_tree.insert(commitment)
        
        state = merkle_tree.get_state()
        
        assert state["height"] == merkle_tree.height
        assert state["num_leaves"] == 3
        assert state["max_leaves"] == merkle_tree.max_leaves
        assert len(state["leaves"]) == 3
        assert state["root"] == merkle_tree.root.hex()
    
    def test_tree_length(self, merkle_tree):
        """Test __len__ method."""
        assert len(merkle_tree) == 0
        
        merkle_tree.insert(os.urandom(32))
        assert len(merkle_tree) == 1
        
        merkle_tree.insert(os.urandom(32))
        assert len(merkle_tree) == 2
    
    def test_tree_repr(self, merkle_tree):
        """Test __repr__ method."""
        repr_str = repr(merkle_tree)
        assert "MerkleTree" in repr_str
        assert "height" in repr_str
        assert "leaves" in repr_str


class TestMerkleTreeComplexScenarios:
    """Tests for complex scenarios."""
    
    def test_large_tree_many_leaves(self):
        """Test inserting many leaves into tree."""
        tree = MerkleTree(tree_height=10)  # 1024 max leaves
        
        commitments = [os.urandom(32) for _ in range(100)]
        
        for commitment in commitments:
            tree.insert(commitment)
        
        assert len(tree) == 100
        
        # Verify all paths
        for i, commitment in enumerate(commitments):
            path = tree.get_path(i)
            assert tree.verify_path(commitment, path, i) is True
    
    def test_tree_consistency_after_operations(self, merkle_tree):
        """Test that tree remains consistent after operations."""
        commitments = [os.urandom(32) for _ in range(10)]
        
        # Insert all
        for commitment in commitments:
            merkle_tree.insert(commitment)
        
        # Verify before operations
        root_before = merkle_tree.root
        
        # Get all paths
        paths = [merkle_tree.get_path(i) for i in range(len(commitments))]
        
        # Verify all still valid
        for i, commitment in enumerate(commitments):
            assert merkle_tree.verify_path(commitment, paths[i], i) is True
        
        # Root should not change
        assert merkle_tree.root == root_before
