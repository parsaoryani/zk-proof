"""Tests for Commitment and Nullifier generation."""

import pytest
import os
from datetime import datetime
from zkm.core.commitment import Commitment, CoinData
from zkm.exceptions import InvalidCommitmentError, InvalidNullifierError


class TestSecretAndRandomnessGeneration:
    """Tests for secret and randomness generation."""
    
    def test_generate_secret(self):
        """Test generating secrets."""
        secret1 = Commitment.generate_secret()
        secret2 = Commitment.generate_secret()
        
        assert isinstance(secret1, bytes)
        assert isinstance(secret2, bytes)
        assert len(secret1) == 32
        assert len(secret2) == 32
        assert secret1 != secret2  # Should be random
    
    def test_generate_randomness(self):
        """Test generating randomness."""
        rand1 = Commitment.generate_randomness()
        rand2 = Commitment.generate_randomness()
        
        assert isinstance(rand1, bytes)
        assert isinstance(rand2, bytes)
        assert len(rand1) == 32
        assert len(rand2) == 32
        assert rand1 != rand2  # Should be random
    
    def test_secret_entropy(self):
        """Test that secrets have sufficient entropy."""
        secrets = [Commitment.generate_secret() for _ in range(100)]
        unique = set(secrets)
        
        # Should have at least 99 unique secrets (extremely unlikely to collide)
        assert len(unique) >= 99


class TestCommitmentComputation:
    """Tests for commitment computation."""
    
    def test_compute_commitment_valid_input(self):
        """Test computing commitment with valid inputs."""
        secret = Commitment.generate_secret()
        randomness = Commitment.generate_randomness()
        
        commitment = Commitment.compute_commitment(secret, randomness)
        
        assert isinstance(commitment, bytes)
        assert len(commitment) == 32  # SHA-256
    
    def test_commitment_deterministic(self):
        """Test that commitment is deterministic."""
        secret = Commitment.generate_secret()
        randomness = Commitment.generate_randomness()
        
        commitment1 = Commitment.compute_commitment(secret, randomness)
        commitment2 = Commitment.compute_commitment(secret, randomness)
        
        assert commitment1 == commitment2
    
    def test_different_secrets_different_commitments(self):
        """Test that different secrets produce different commitments."""
        randomness = Commitment.generate_randomness()
        secret1 = Commitment.generate_secret()
        secret2 = Commitment.generate_secret()
        
        commitment1 = Commitment.compute_commitment(secret1, randomness)
        commitment2 = Commitment.compute_commitment(secret2, randomness)
        
        assert commitment1 != commitment2
    
    def test_different_randomness_different_commitments(self):
        """Test that different randomness produces different commitments."""
        secret = Commitment.generate_secret()
        rand1 = Commitment.generate_randomness()
        rand2 = Commitment.generate_randomness()
        
        commitment1 = Commitment.compute_commitment(secret, rand1)
        commitment2 = Commitment.compute_commitment(secret, rand2)
        
        assert commitment1 != commitment2
    
    def test_commitment_invalid_secret_length(self):
        """Test that invalid secret length raises error."""
        randomness = Commitment.generate_randomness()
        
        with pytest.raises(InvalidCommitmentError):
            Commitment.compute_commitment(b"short", randomness)
        
        with pytest.raises(InvalidCommitmentError):
            Commitment.compute_commitment(b"x" * 64, randomness)
    
    def test_commitment_invalid_randomness_length(self):
        """Test that invalid randomness length raises error."""
        secret = Commitment.generate_secret()
        
        with pytest.raises(InvalidCommitmentError):
            Commitment.compute_commitment(secret, b"short")
        
        with pytest.raises(InvalidCommitmentError):
            Commitment.compute_commitment(secret, b"x" * 64)
    
    def test_commitment_invalid_type(self):
        """Test that invalid types raise error."""
        randomness = Commitment.generate_randomness()
        
        with pytest.raises(InvalidCommitmentError):
            Commitment.compute_commitment("not bytes", randomness)
        
        with pytest.raises(InvalidCommitmentError):
            Commitment.compute_commitment(123, randomness)


class TestNullifierComputation:
    """Tests for nullifier computation."""
    
    def test_compute_nullifier_valid_input(self):
        """Test computing nullifier with valid input."""
        secret = Commitment.generate_secret()
        nullifier = Commitment.compute_nullifier(secret)
        
        assert isinstance(nullifier, bytes)
        assert len(nullifier) == 32
    
    def test_nullifier_deterministic(self):
        """Test that nullifier is deterministic."""
        secret = Commitment.generate_secret()
        
        nullifier1 = Commitment.compute_nullifier(secret)
        nullifier2 = Commitment.compute_nullifier(secret)
        
        assert nullifier1 == nullifier2
    
    def test_different_secrets_different_nullifiers(self):
        """Test that different secrets produce different nullifiers."""
        secret1 = Commitment.generate_secret()
        secret2 = Commitment.generate_secret()
        
        nullifier1 = Commitment.compute_nullifier(secret1)
        nullifier2 = Commitment.compute_nullifier(secret2)
        
        assert nullifier1 != nullifier2
    
    def test_nullifier_one_way(self):
        """Test that nullifier is one-way (can't recover secret)."""
        secret = Commitment.generate_secret()
        nullifier = Commitment.compute_nullifier(secret)
        
        # Nullifier should not equal secret
        assert nullifier != secret
        
        # Can't reverse it (no inverse function)
        assert secret not in [nullifier, nullifier.hex()]
    
    def test_nullifier_invalid_secret_length(self):
        """Test that invalid secret length raises error."""
        with pytest.raises(InvalidNullifierError):
            Commitment.compute_nullifier(b"short")
        
        with pytest.raises(InvalidNullifierError):
            Commitment.compute_nullifier(b"x" * 64)
    
    def test_nullifier_invalid_type(self):
        """Test that invalid types raise error."""
        with pytest.raises(InvalidNullifierError):
            Commitment.compute_nullifier("not bytes")
        
        with pytest.raises(InvalidNullifierError):
            Commitment.compute_nullifier(123)


class TestCoinDataCreation:
    """Tests for CoinData creation."""
    
    def test_create_coin(self):
        """Test creating a coin."""
        coin = Commitment.create_coin(amount=1000)
        
        assert isinstance(coin, CoinData)
        assert len(coin.secret) == 32
        assert len(coin.randomness) == 32
        assert len(coin.commitment) == 32
        assert len(coin.nullifier) == 32
        assert coin.amount == 1000
        assert isinstance(coin.timestamp, datetime)
    
    def test_create_coin_different_amounts(self):
        """Test creating coins with different amounts."""
        coin1 = Commitment.create_coin(amount=100)
        coin2 = Commitment.create_coin(amount=200)
        
        assert coin1.amount == 100
        assert coin2.amount == 200
        assert coin1.secret != coin2.secret
        assert coin1.commitment != coin2.commitment
    
    def test_create_coin_commitment_matches(self):
        """Test that created coin's commitment is correct."""
        coin = Commitment.create_coin(amount=1000)
        
        # Verify commitment matches secret and randomness
        expected = Commitment.compute_commitment(coin.secret, coin.randomness)
        assert coin.commitment == expected
    
    def test_create_coin_nullifier_matches(self):
        """Test that created coin's nullifier is correct."""
        coin = Commitment.create_coin(amount=1000)
        
        # Verify nullifier matches secret
        expected = Commitment.compute_nullifier(coin.secret)
        assert coin.nullifier == expected


class TestCommitmentVerification:
    """Tests for verification functions."""
    
    def test_verify_commitment_valid(self):
        """Test verifying a valid commitment."""
        secret = Commitment.generate_secret()
        randomness = Commitment.generate_randomness()
        commitment = Commitment.compute_commitment(secret, randomness)
        
        is_valid = Commitment.verify_commitment(secret, randomness, commitment)
        assert is_valid is True
    
    def test_verify_commitment_invalid(self):
        """Test that verification fails for invalid commitment."""
        secret = Commitment.generate_secret()
        randomness = Commitment.generate_randomness()
        wrong_commitment = os.urandom(32)
        
        is_valid = Commitment.verify_commitment(secret, randomness, wrong_commitment)
        assert is_valid is False
    
    def test_verify_commitment_wrong_secret(self):
        """Test that verification fails with wrong secret."""
        secret = Commitment.generate_secret()
        wrong_secret = Commitment.generate_secret()
        randomness = Commitment.generate_randomness()
        commitment = Commitment.compute_commitment(secret, randomness)
        
        is_valid = Commitment.verify_commitment(wrong_secret, randomness, commitment)
        assert is_valid is False
    
    def test_verify_commitment_wrong_randomness(self):
        """Test that verification fails with wrong randomness."""
        secret = Commitment.generate_secret()
        randomness = Commitment.generate_randomness()
        wrong_randomness = Commitment.generate_randomness()
        commitment = Commitment.compute_commitment(secret, randomness)
        
        is_valid = Commitment.verify_commitment(secret, wrong_randomness, commitment)
        assert is_valid is False
    
    def test_verify_nullifier_valid(self):
        """Test verifying a valid nullifier."""
        secret = Commitment.generate_secret()
        nullifier = Commitment.compute_nullifier(secret)
        
        is_valid = Commitment.verify_nullifier(secret, nullifier)
        assert is_valid is True
    
    def test_verify_nullifier_invalid(self):
        """Test that verification fails for invalid nullifier."""
        secret = Commitment.generate_secret()
        wrong_nullifier = os.urandom(32)
        
        is_valid = Commitment.verify_nullifier(secret, wrong_nullifier)
        assert is_valid is False


class TestCommitmentSecurityProperties:
    """Tests for cryptographic security properties."""
    
    def test_commitment_preimage_resistance(self):
        """Test that commitments are preimage resistant."""
        # Can't easily find a preimage for a random commitment
        random_commitment = os.urandom(32)
        
        # Try random guesses (should fail)
        found_preimage = False
        for _ in range(1000):
            secret = Commitment.generate_secret()
            randomness = Commitment.generate_randomness()
            if Commitment.compute_commitment(secret, randomness) == random_commitment:
                found_preimage = True
                break
        
        assert not found_preimage
    
    def test_commitment_collision_resistance(self):
        """Test that commitments are collision resistant."""
        # Generate many commitments, shouldn't see collisions
        commitments = []
        
        for _ in range(100):
            secret = Commitment.generate_secret()
            randomness = Commitment.generate_randomness()
            commitment = Commitment.compute_commitment(secret, randomness)
            commitments.append(commitment)
        
        unique = set(commitments)
        assert len(unique) == 100  # All should be unique
