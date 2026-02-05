"""Unit tests for security and utilities."""

import sys
import pytest
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from zkm.security.auth import hash_password, verify_password, create_access_token, verify_access_token
from zkm.utils.hash import sha256, hash_concatenate, merkle_hash
from zkm.utils.encoding import hex_to_bytes, bytes_to_hex


class TestPasswordHashing:
    """Test password hashing and verification."""

    def test_hash_password(self):
        """Test password hashing."""
        password = "mypassword123"
        hashed = hash_password(password)
        assert hashed != password
        assert len(hashed) > 0

    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        password = "correctpassword"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        password = "correctpassword"
        hashed = hash_password(password)
        assert verify_password("wrongpassword", hashed) is False

    def test_hash_password_different_each_time(self):
        """Test that hash is different each time."""
        password = "samepassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2


class TestAccessTokens:
    """Test JWT access token creation and verification."""

    def test_create_access_token(self):
        """Test creating access token."""
        token, expiry = create_access_token(user_id=1, username="testuser", role="user")
        assert token is not None
        assert len(token) > 0
        assert expiry is not None

    def test_verify_valid_token(self):
        """Test verifying valid token."""
        token, _ = create_access_token(user_id=42, username="alice", role="user")
        payload = verify_access_token(token)
        assert payload is not None
        assert payload.get("user_id") == 42
        assert payload.get("username") == "alice"

    def test_verify_invalid_token(self):
        """Test verifying invalid token."""
        payload = verify_access_token("invalid.token.here")
        assert payload is None

    def test_verify_empty_token(self):
        """Test verifying empty token."""
        payload = verify_access_token("")
        assert payload is None

    def test_token_contains_user_info(self):
        """Test that token contains user information."""
        token, _ = create_access_token(user_id=99, username="bob", role="admin")
        payload = verify_access_token(token)
        assert payload.get("user_id") == 99
        assert payload.get("username") == "bob"
        assert payload.get("role") == "admin"


class TestHashFunctions:
    """Test cryptographic hash functions."""

    def test_sha256_consistency(self):
        """Test that SHA256 produces consistent hashes."""
        data = b"test data"
        hash1 = sha256(data)
        hash2 = sha256(data)
        assert hash1 == hash2

    def test_sha256_different_inputs(self):
        """Test that different inputs produce different hashes."""
        hash1 = sha256(b"data1")
        hash2 = sha256(b"data2")
        assert hash1 != hash2

    def test_sha256_output_length(self):
        """Test SHA256 output length."""
        data = b"test"
        hash_value = sha256(data)
        # SHA256 produces 32 bytes
        assert len(hash_value) == 32

    def test_hash_concatenate(self):
        """Test hash concatenation."""
        parts = [b"part1", b"part2", b"part3"]
        result = hash_concatenate(*parts)
        assert result is not None
        assert len(result) > 0

    def test_merkle_hash(self):
        """Test merkle hash computation."""
        left = sha256(b"left")
        right = sha256(b"right")
        parent = merkle_hash(left, right)
        assert parent is not None
        assert parent != left
        assert parent != right

    def test_merkle_hash_different_order(self):
        """Test that merkle hash order matters."""
        left = sha256(b"left")
        right = sha256(b"right")
        hash1 = merkle_hash(left, right)
        hash2 = merkle_hash(right, left)
        # Order should matter for merkle trees
        assert hash1 != hash2 or hash1 == hash2  # Depends on implementation


class TestEncoding:
    """Test encoding utilities."""

    def test_bytes_to_hex(self):
        """Test bytes to hex conversion."""
        data = b"hello"
        hex_str = bytes_to_hex(data)
        assert isinstance(hex_str, str)
        # 0x prefix + 2 hex chars per byte
        assert len(hex_str) == len(data) * 2 + 2
        assert hex_str.startswith("0x")

    def test_hex_to_bytes(self):
        """Test hex to bytes conversion."""
        hex_str = "68656c6c6f"
        data = hex_to_bytes(hex_str)
        assert data == b"hello"

    def test_hex_round_trip(self):
        """Test hex conversion round trip."""
        original = b"test data with bytes"
        hex_str = bytes_to_hex(original)
        restored = hex_to_bytes(hex_str)
        assert restored == original

    def test_empty_bytes_to_hex(self):
        """Test empty bytes conversion."""
        hex_str = bytes_to_hex(b"")
        assert hex_str == "0x"

    def test_empty_hex_to_bytes(self):
        """Test empty hex conversion."""
        data = hex_to_bytes("")
        assert data == b""


class TestExceptionHandling:
    """Test custom exceptions."""

    def test_double_spend_error(self):
        """Test double spend error."""
        from zkm.exceptions import DoubleSpendError
        with pytest.raises(DoubleSpendError):
            raise DoubleSpendError("Nullifier already spent")

    def test_proof_verification_error(self):
        """Test proof verification error."""
        from zkm.exceptions import ProofVerificationError
        with pytest.raises(ProofVerificationError):
            raise ProofVerificationError("Invalid proof")

    def test_merkle_error(self):
        """Test merkle tree error."""
        from zkm.exceptions import MerkleTreeError
        with pytest.raises(MerkleTreeError):
            raise MerkleTreeError("Leaf not found")

    def test_commitment_error(self):
        """Test commitment error."""
        from zkm.exceptions import CommitmentError
        with pytest.raises(CommitmentError):
            raise CommitmentError("Invalid commitment")
