"""Main package initialization."""

__version__ = "0.1.0"
__author__ = "ZK-Mixer Team"
__description__ = "Regulated ZK-Mixer: Combining Zerocash & Morales et al. Concepts"

from .core.merkle_tree import MerkleTree
from .core.commitment import Commitment, CoinData
from .core.auditor import Auditor, IdentityEncryptionProof
from .core.zkproof import ZKProofSystem, WithdrawalProof

__all__ = [
    "MerkleTree",
    "Commitment",
    "CoinData",
    "Auditor",
    "IdentityEncryptionProof",
    "ZKProofSystem",
    "WithdrawalProof",
]
