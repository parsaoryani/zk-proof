"""Commitment and Nullifier generation (Zerocash Core)."""

import os
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

from zkm.utils.hash import compute_commitment, compute_nullifier
from zkm.exceptions import InvalidCommitmentError, InvalidNullifierError


@dataclass
class CoinData:
    """Represents a coin in the mixer system."""
    
    secret: bytes
    randomness: bytes
    commitment: bytes
    nullifier: bytes
    amount: int
    timestamp: datetime


class Commitment:
    """
    Coin commitment and nullifier generation.
    
    Paper Reference: Zerocash - Section 3.1 & 3.3
    """
    
    # Constants
    SECRET_SIZE = 32  # bytes
    RANDOMNESS_SIZE = 32  # bytes
    HASH_SIZE = 32  # SHA-256 output size
    
    @staticmethod
    def generate_secret() -> bytes:
        """
        Generate random secret (s in Zerocash).
        
        Returns:
            bytes: 32-byte cryptographically secure random secret
            
        Implementation: os.urandom(32)
        Paper Reference: Zerocash Section 3.1
        """
        return os.urandom(Commitment.SECRET_SIZE)
    
    @staticmethod
    def generate_randomness() -> bytes:
        """
        Generate random value (r in Zerocash).
        
        Returns:
            bytes: 32-byte cryptographically secure random value
            
        Implementation: os.urandom(32)
        Paper Reference: Zerocash Section 3.1
        """
        return os.urandom(Commitment.RANDOMNESS_SIZE)
    
    @staticmethod
    def compute_commitment(secret: bytes, randomness: bytes) -> bytes:
        """
        Compute coin commitment C = H(s || r).
        
        Args:
            secret: User's secret (must be 32 bytes)
            randomness: Random value (must be 32 bytes)
            
        Returns:
            bytes: SHA-256 commitment (32 bytes)
            
        Raises:
            InvalidCommitmentError: If inputs are invalid
            
        Paper Reference: Zerocash Equation 1
        Implementation: hashlib.sha256(secret + randomness).digest()
        """
        if not isinstance(secret, bytes) or len(secret) != Commitment.SECRET_SIZE:
            raise InvalidCommitmentError("Secret must be 32 bytes")
        if not isinstance(randomness, bytes) or len(randomness) != Commitment.RANDOMNESS_SIZE:
            raise InvalidCommitmentError("Randomness must be 32 bytes")
        
        return compute_commitment(secret, randomness)
    
    @staticmethod
    def compute_nullifier(secret: bytes) -> bytes:
        """
        Compute nullifier nf = H("nf" || s).
        
        Purpose: Prevent double-spending without revealing the secret.
        The nullifier is derived deterministically from the secret,
        so the same coin always produces the same nullifier.
        
        Args:
            secret: User's secret (must be 32 bytes)
            
        Returns:
            bytes: SHA-256 nullifier (32 bytes)
            
        Raises:
            InvalidNullifierError: If input is invalid
            
        Paper Reference: Zerocash - Section 3.3
        Implementation: hashlib.sha256(b"nf" + secret).digest()
        """
        if not isinstance(secret, bytes) or len(secret) != Commitment.SECRET_SIZE:
            raise InvalidNullifierError("Secret must be 32 bytes")
        
        return compute_nullifier(secret)
    
    @staticmethod
    def create_coin(amount: int) -> CoinData:
        """
        Create a new coin with fresh secret and randomness.
        
        Args:
            amount: Coin value in currency units
            
        Returns:
            CoinData: Complete coin data with computed commitment and nullifier
        """
        secret = Commitment.generate_secret()
        randomness = Commitment.generate_randomness()
        commitment = Commitment.compute_commitment(secret, randomness)
        nullifier = Commitment.compute_nullifier(secret)
        
        return CoinData(
            secret=secret,
            randomness=randomness,
            commitment=commitment,
            nullifier=nullifier,
            amount=amount,
            timestamp=datetime.now()
        )
    
    @staticmethod
    def verify_commitment(
        secret: bytes,
        randomness: bytes,
        expected_commitment: bytes
    ) -> bool:
        """
        Verify that a commitment matches the given secret and randomness.
        
        Args:
            secret: User's secret
            randomness: Random value
            expected_commitment: Commitment to verify
            
        Returns:
            bool: True if commitment is valid, False otherwise
        """
        try:
            computed = Commitment.compute_commitment(secret, randomness)
            return computed == expected_commitment
        except (InvalidCommitmentError, ValueError):
            return False
    
    @staticmethod
    def verify_nullifier(secret: bytes, expected_nullifier: bytes) -> bool:
        """
        Verify that a nullifier matches the given secret.
        
        Args:
            secret: User's secret
            expected_nullifier: Nullifier to verify
            
        Returns:
            bool: True if nullifier is valid, False otherwise
        """
        try:
            computed = Commitment.compute_nullifier(secret)
            return computed == expected_nullifier
        except (InvalidNullifierError, ValueError):
            return False
