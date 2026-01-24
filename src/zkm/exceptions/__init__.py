"""Custom exceptions for the ZK-Mixer system."""


class ZKMixerException(Exception):
    """Base exception for all ZK-Mixer errors."""
    pass


# Cryptography Errors
class CryptoError(ZKMixerException):
    """Base exception for cryptographic errors."""
    pass


class InvalidCommitmentError(CryptoError):
    """Raised when a commitment is invalid."""
    pass


class InvalidNullifierError(CryptoError):
    """Raised when a nullifier is invalid."""
    pass


class EncryptionError(CryptoError):
    """Raised when encryption fails."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails."""
    pass


# Proof Errors
class ProofError(ZKMixerException):
    """Base exception for proof-related errors."""
    pass


class InvalidProofError(ProofError):
    """Raised when proof verification fails."""
    pass


class ProofTamperingError(ProofError):
    """Raised when proof has been tampered with."""
    pass


class DoubleSpendError(ProofError):
    """Raised when attempting to spend the same coin twice."""
    pass


class InvalidMerklePathError(ProofError):
    """Raised when Merkle path verification fails."""
    pass


class InvalidIdentityProofError(ProofError):
    """Raised when identity encryption proof is invalid."""
    pass


# Merkle Tree Errors
class MerkleTreeError(ZKMixerException):
    """Base exception for Merkle tree errors."""
    pass


class TreeHeightExceededError(MerkleTreeError):
    """Raised when tree height limit is exceeded."""
    pass


class InvalidLeafIndexError(MerkleTreeError):
    """Raised when leaf index is invalid."""
    pass


class InvalidMerkleRootError(MerkleTreeError):
    """Raised when Merkle root is invalid."""
    pass


# Mixer Errors
class MixerError(ZKMixerException):
    """Base exception for mixer operation errors."""
    pass


class DepositError(MixerError):
    """Raised when deposit operation fails."""
    pass


class WithdrawalError(MixerError):
    """Raised when withdrawal operation fails."""
    pass


class AuditError(MixerError):
    """Raised when audit operation fails."""
    pass


class InvalidMixerStateError(MixerError):
    """Raised when mixer state is inconsistent."""
    pass


# Database Errors
class DatabaseError(ZKMixerException):
    """Base exception for database errors."""
    pass


class TransactionNotFoundError(DatabaseError):
    """Raised when transaction is not found."""
    pass


# Storage Errors
class StorageError(ZKMixerException):
    """Base exception for storage errors."""
    pass


class SerializationError(StorageError):
    """Raised when serialization fails."""
    pass


class DeserializationError(StorageError):
    """Raised when deserialization fails."""
    pass
