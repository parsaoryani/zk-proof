"""Cryptographic hash utilities."""

import hashlib
from typing import Union


def sha256(data: Union[bytes, str]) -> bytes:
    """
    Compute SHA-256 hash of data.
    
    Args:
        data: Bytes or string to hash
        
    Returns:
        bytes: 32-byte SHA-256 hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def hash_concatenate(*data: Union[bytes, str]) -> bytes:
    """
    Hash concatenated data.
    
    Args:
        *data: Multiple bytes or strings to concatenate and hash
        
    Returns:
        bytes: SHA-256 hash of concatenated data
    """
    concatenated = b""
    for item in data:
        if isinstance(item, str):
            concatenated += item.encode('utf-8')
        else:
            concatenated += item
    return sha256(concatenated)


def merkle_hash(left: bytes, right: bytes) -> bytes:
    """
    Compute Merkle tree hash of two siblings.
    
    Uses SHA-256(left || right) to prevent second preimage attacks.
    
    Args:
        left: Left child hash (32 bytes)
        right: Right child hash (32 bytes)
        
    Returns:
        bytes: Parent hash (32 bytes)
    """
    if not isinstance(left, bytes) or len(left) != 32:
        raise ValueError("Left hash must be 32 bytes")
    if not isinstance(right, bytes) or len(right) != 32:
        raise ValueError("Right hash must be 32 bytes")
    
    return sha256(left + right)


def compute_commitment(secret: bytes, randomness: bytes) -> bytes:
    """
    Compute coin commitment C = H(s || r).
    
    Paper Reference: Zerocash Equation 1
    
    Args:
        secret: User's secret (32 bytes)
        randomness: Random value (32 bytes)
        
    Returns:
        bytes: Commitment (32 bytes)
    """
    return hash_concatenate(secret, randomness)


def compute_nullifier(secret: bytes) -> bytes:
    """
    Compute nullifier nf = H("nf" || s).
    
    Paper Reference: Zerocash Section 3.3
    
    Args:
        secret: User's secret (32 bytes)
        
    Returns:
        bytes: Nullifier (32 bytes)
    """
    return hash_concatenate(b"nf", secret)
