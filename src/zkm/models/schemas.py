"""Pydantic data models for the ZK-Mixer system."""

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum


class TransactionStatus(str, Enum):
    """Transaction status enumeration."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    AUDITED = "audited"


class DepositRequest(BaseModel):
    """Request model for deposit operations."""
    identity: str = Field(..., description="User identity/address")
    amount: int = Field(..., gt=0, description="Amount to deposit")
    timestamp: Optional[datetime] = Field(default_factory=datetime.now)


class DepositResponse(BaseModel):
    """Response model for deposit operations."""
    commitment: str = Field(..., description="Commitment hash (hex)")
    commitment_index: int = Field(..., description="Index in Merkle tree")
    merkle_root: str = Field(..., description="Merkle root (hex)")
    encrypted_identity_proof: str = Field(..., description="Identity proof (hex)")
    deposit_hash: str = Field(..., description="Transaction hash")
    timestamp: datetime
    
    class Config:
        from_attributes = True


class WithdrawalRequest(BaseModel):
    """Request model for withdrawal operations."""
    nullifier: str = Field(..., description="Nullifier (hex)")
    merkle_path: List[str] = Field(..., description="Merkle path (hex list)")
    leaf_index: int = Field(..., description="Leaf index in tree")
    identity_encryption_proof: str = Field(..., description="Identity proof (hex)")
    encrypted_identity: str = Field(..., description="Encrypted identity (hex)")
    timestamp: datetime


class WithdrawalResponse(BaseModel):
    """Response model for withdrawal operations."""
    transaction_hash: str = Field(..., description="Transaction hash")
    status: TransactionStatus = Field(...)
    timestamp: datetime
    amount: int = Field(..., description="Withdrawal amount")
    
    class Config:
        from_attributes = True


class AuditRequest(BaseModel):
    """Request model for audit operations."""
    transaction_hash: str = Field(..., description="Transaction to audit")
    auditor_private_key: str = Field(..., description="Auditor private key (PEM)")


class AuditResponse(BaseModel):
    """Response model for audit operations."""
    transaction_hash: str
    decrypted_identity: str = Field(..., description="Decrypted user identity")
    audit_timestamp: datetime
    auditor_note: Optional[str] = None
    
    class Config:
        from_attributes = True


class MixerStateResponse(BaseModel):
    """Response model for mixer state."""
    merkle_root: str = Field(..., description="Current Merkle root (hex)")
    tree_height: int = Field(..., description="Merkle tree height")
    num_commitments: int = Field(..., description="Number of commitments")
    num_nullifiers: int = Field(..., description="Number of used nullifiers")
    total_volume: int = Field(default=0, description="Total transaction volume")
    last_update: datetime = Field(default_factory=datetime.now)


class TransactionRecord(BaseModel):
    """Record of a transaction."""
    transaction_hash: str
    transaction_type: str  # "deposit" or "withdrawal"
    amount: int
    status: TransactionStatus
    timestamp: datetime
    commitment: Optional[str] = None
    nullifier: Optional[str] = None
    encrypted_identity: Optional[str] = None
    audited: bool = False
    decrypted_identity: Optional[str] = None
    
    class Config:
        from_attributes = True


class MixerStatistics(BaseModel):
    """Statistics about the mixer."""
    total_deposits: int = 0
    total_withdrawals: int = 0
    total_volume: int = 0
    average_deposit: float = 0.0
    average_withdrawal: float = 0.0
    unique_users: int = 0
    audited_transactions: int = 0
    uptime_hours: float = 0.0
    last_update: datetime = Field(default_factory=datetime.now)
