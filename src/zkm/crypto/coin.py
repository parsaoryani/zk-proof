"""
Zerocash-compliant coin structure with proper serialization.

Per Ben-Sasson et al., 2014:
  A coin c = (k, r, v) where:
  - k = spend key (secret, unique per coin)
  - r = randomness (hides commitment structure)
  - v = value (amount in the coin)
"""

from dataclasses import dataclass, field
from typing import Optional
import json
import hashlib
from datetime import datetime
from enum import Enum
import secrets
from cryptography.hazmat.primitives import hashes


class CoinStatus(Enum):
    """Coin lifecycle status per Zerocash specification."""
    ACTIVE = "active"        # Coin exists in tree
    SPENT = "spent"          # Nullifier was submitted
    INVALID = "invalid"      # Failed verification
    PENDING = "pending"      # Awaiting tree inclusion


@dataclass
class Coin:
    """
    Zerocash coin c = (k, r, v).
    
    Per paper: "A coin is a tuple (k, r, v) where k is a spend key,
    r is randomness, and v is a value."
    """
    
    spend_key: str           # k: hex-encoded spend key (256-bit)
    randomness: str          # r: hex-encoded randomness (256-bit)
    value: int               # v: amount (satoshis, 64-bit)
    
    # Derived fields
    commitment: str = field(default="")        # Hash_cm(k, r, v)
    nullifier: Optional[str] = field(default=None)  # Hash_sn(k, rho)
    rho: str = field(default="")               # Serial number
    
    # Metadata
    coin_id: str = field(default="")
    status: CoinStatus = field(default=CoinStatus.ACTIVE)
    created_at: str = field(default="")
    spent_at: Optional[str] = field(default=None)
    
    # Tree position (after deposit)
    merkle_index: Optional[int] = field(default=None)
    merkle_root: Optional[str] = field(default=None)
    merkle_path: list = field(default_factory=list)
    
    def __post_init__(self):
        """Compute derived fields after initialization."""
        if not self.coin_id:
            self.coin_id = self._generate_coin_id()
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat() + "Z"
        if not self.rho:
            self.rho = secrets.token_hex(32)
        if not self.commitment:
            self.commitment = self._compute_commitment()
    
    @staticmethod
    def generate(value: int) -> "Coin":
        """
        Generate a new random coin per Zerocash.
        
        Generates random k, r and creates coin structure.
        """
        return Coin(
            spend_key=secrets.token_hex(32),
            randomness=secrets.token_hex(32),
            value=value,
            rho=secrets.token_hex(32)
        )
    
    def _generate_coin_id(self) -> str:
        """Generate unique coin ID from k and timestamp."""
        data = f"{self.spend_key}{self.created_at}".encode()
        return hashlib.sha256(data).hexdigest()[:16]
    
    def _compute_commitment(self) -> str:
        """
        Compute commitment: cm = Hash_cm(k, r, v).
        
        Per Zerocash: cm = PeddersenHash(k || r || v)
        Implementation: SHA-256(k || r || v_as_bytes)
        """
        # Encode value as 8-byte little-endian
        value_bytes = self.value.to_bytes(8, byteorder='little')
        
        # Concatenate: k || r || v
        k_bytes = bytes.fromhex(self.spend_key)
        r_bytes = bytes.fromhex(self.randomness)
        
        data = k_bytes + r_bytes + value_bytes
        
        # Hash to commitment
        commitment_hash = hashlib.sha256(data).digest()
        return commitment_hash.hex()
    
    def compute_nullifier(self) -> str:
        """
        Compute nullifier: sn = Hash_sn(k, rho).
        
        Per Zerocash: sn = Hash_sn(k, rho)
        Implementation: SHA-256(k || rho)
        
        Properties:
          - Cannot link to commitment
          - Prevents double-spending
          - Proves knowledge of k without revealing it
        """
        k_bytes = bytes.fromhex(self.spend_key)
        rho_bytes = bytes.fromhex(self.rho)
        
        data = k_bytes + rho_bytes
        nullifier_hash = hashlib.sha256(data).digest()
        
        self.nullifier = nullifier_hash.hex()
        return self.nullifier
    
    def serialize(self) -> str:
        """
        Serialize coin to JSON (for storage/transmission).
        
        Includes all necessary fields for proof generation.
        """
        return json.dumps({
            "coin_id": self.coin_id,
            "spend_key": self.spend_key,
            "randomness": self.randomness,
            "value": self.value,
            "rho": self.rho,
            "commitment": self.commitment,
            "nullifier": self.nullifier,
            "status": self.status.value,
            "merkle_index": self.merkle_index,
            "merkle_root": self.merkle_root,
            "merkle_path": self.merkle_path,
            "created_at": self.created_at,
            "spent_at": self.spent_at
        }, indent=2)
    
    @classmethod
    def deserialize(cls, json_str: str) -> "Coin":
        """Deserialize coin from JSON."""
        data = json.loads(json_str)
        
        coin = cls(
            spend_key=data["spend_key"],
            randomness=data["randomness"],
            value=data["value"],
            rho=data["rho"],
            coin_id=data["coin_id"],
            commitment=data["commitment"],
            nullifier=data["nullifier"],
            status=CoinStatus(data["status"]),
            merkle_index=data["merkle_index"],
            merkle_root=data["merkle_root"],
            merkle_path=data["merkle_path"],
            created_at=data["created_at"],
            spent_at=data["spent_at"]
        )
        return coin
    
    def is_spendable(self) -> bool:
        """Check if coin can be spent."""
        return (
            self.status == CoinStatus.ACTIVE and
            self.merkle_index is not None and
            self.nullifier is not None
        )
    
    def mark_spent(self):
        """Mark coin as spent after successful withdrawal."""
        self.status = CoinStatus.SPENT
        self.spent_at = datetime.utcnow().isoformat() + "Z"
    
    def __repr__(self) -> str:
        return (
            f"Coin(id={self.coin_id[:8]}, value={self.value}, "
            f"status={self.status.value}, merkle_index={self.merkle_index})"
        )


@dataclass
class CoinCommitment:
    """
    Commitment representation for Merkle tree.
    
    Per Zerocash: Each commitment is a node in the Merkle tree.
    """
    
    commitment_hash: str           # The cm value
    coin_id: str                   # Reference to coin
    timestamp: str                 # When committed
    merkle_leaf_index: int = -1   # Position in tree (-1 = not yet inserted)
    
    def serialize(self) -> str:
        """Serialize to JSON."""
        return json.dumps({
            "commitment_hash": self.commitment_hash,
            "coin_id": self.coin_id,
            "timestamp": self.timestamp,
            "merkle_leaf_index": self.merkle_leaf_index
        })
    
    @classmethod
    def deserialize(cls, json_str: str) -> "CoinCommitment":
        """Deserialize from JSON."""
        data = json.loads(json_str)
        return cls(
            commitment_hash=data["commitment_hash"],
            coin_id=data["coin_id"],
            timestamp=data["timestamp"],
            merkle_leaf_index=data["merkle_leaf_index"]
        )


@dataclass
class SpendingWitness:
    """
    Witness for spending a coin (withdrawal proof).
    
    Per Zerocash: The witness (a_sk, k, r, rho, v, path) needed to prove
    knowledge of a coin c = (k, r, v) in the current Merkle tree.
    """
    
    spend_key: str                 # k
    randomness: str                # r
    value: int                     # v
    rho: str                        # rho (serial number)
    
    merkle_path: list              # Path from leaf to root
    merkle_leaf_index: int         # Position in tree
    merkle_root: str               # Current tree root
    
    commitment: str                # Original cm
    nullifier: str                 # Derived sn
    
    def validate(self) -> bool:
        """
        Validate witness structure.
        
        Checks that all required fields are present and properly formatted.
        """
        checks = [
            len(self.spend_key) == 64,           # 256 bits hex
            len(self.randomness) == 64,          # 256 bits hex
            len(self.rho) == 64,                 # 256 bits hex
            isinstance(self.value, int),
            0 <= self.value < 2**64,             # Valid amount
            isinstance(self.merkle_path, list),
            len(self.merkle_path) > 0,
            isinstance(self.merkle_leaf_index, int),
            0 <= self.merkle_leaf_index < 2**32,
            len(self.merkle_root) == 64,         # 256 bits hex
            len(self.commitment) == 64,
            len(self.nullifier) == 64
        ]
        
        return all(checks)
    
    def serialize(self) -> str:
        """Serialize for transmission."""
        return json.dumps({
            "spend_key": self.spend_key,
            "randomness": self.randomness,
            "value": self.value,
            "rho": self.rho,
            "merkle_path": self.merkle_path,
            "merkle_leaf_index": self.merkle_leaf_index,
            "merkle_root": self.merkle_root,
            "commitment": self.commitment,
            "nullifier": self.nullifier
        })
    
    @classmethod
    def deserialize(cls, json_str: str) -> "SpendingWitness":
        """Deserialize from JSON."""
        data = json.loads(json_str)
        return cls(
            spend_key=data["spend_key"],
            randomness=data["randomness"],
            value=data["value"],
            rho=data["rho"],
            merkle_path=data["merkle_path"],
            merkle_leaf_index=data["merkle_leaf_index"],
            merkle_root=data["merkle_root"],
            commitment=data["commitment"],
            nullifier=data["nullifier"]
        )
