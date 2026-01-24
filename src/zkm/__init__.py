"""Main package initialization."""

__version__ = "0.1.0"
__author__ = "ZK-Mixer Team"
__description__ = "Regulated ZK-Mixer: Combining Zerocash & Morales et al. Concepts"

from zkm.core.merkle_tree import MerkleTree
from zkm.core.commitment import Commitment, CoinData
from zkm.core.auditor import Auditor, IdentityEncryptionProof
from zkm.core.zkproof import ZKProofSystem, WithdrawalProof

__all__ = [
    "MerkleTree",
    "Commitment",
    "CoinData",
    "Auditor",
    "IdentityEncryptionProof",
    "ZKProofSystem",
    "WithdrawalProof",
]
