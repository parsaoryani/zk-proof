"""Tests for database storage layer."""

import pytest
from datetime import datetime
import tempfile
import os

from zkm.storage.database import (
    DatabaseManager,
    Transaction,
    Commitment,
    Nullifier,
    AuditRecord,
    MerkleRoot,
    MixerStatistics,
    TransactionType,
    TransactionStatus,
    get_db_manager,
    reset_db_manager,
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db_url = f"sqlite:///{path}"
    manager = DatabaseManager(db_url)
    manager.create_tables()
    yield manager
    # Cleanup
    os.unlink(path)


class TestDatabaseManager:
    """Test database manager initialization."""
    
    def test_database_creation(self, temp_db):
        """Test database creation."""
        assert temp_db.engine is not None
        assert temp_db.SessionLocal is not None
    
    def test_get_session(self, temp_db):
        """Test session creation."""
        session = temp_db.get_session()
        assert session is not None
        session.close()


class TestTransactionOperations:
    """Test transaction table operations."""
    
    def test_add_transaction(self, temp_db):
        """Test adding a transaction."""
        session = temp_db.get_session()
        tx = temp_db.add_transaction(
            session,
            transaction_hash="tx_123",
            tx_type=TransactionType.DEPOSIT,
            amount=1000.0
        )
        assert tx.transaction_hash == "tx_123"
        assert tx.tx_type == TransactionType.DEPOSIT
        assert tx.amount == 1000.0
        assert tx.status == TransactionStatus.CONFIRMED
        session.close()
    
    def test_get_transaction(self, temp_db):
        """Test retrieving a transaction."""
        session = temp_db.get_session()
        temp_db.add_transaction(session, "tx_456", TransactionType.WITHDRAWAL, 500.0)
        
        tx = temp_db.get_transaction(session, "tx_456")
        assert tx is not None
        assert tx.amount == 500.0
        session.close()
    
    def test_get_nonexistent_transaction(self, temp_db):
        """Test retrieving nonexistent transaction."""
        session = temp_db.get_session()
        tx = temp_db.get_transaction(session, "nonexistent")
        assert tx is None
        session.close()
    
    def test_update_transaction_status(self, temp_db):
        """Test updating transaction status."""
        session = temp_db.get_session()
        temp_db.add_transaction(session, "tx_789", TransactionType.DEPOSIT, 1500.0)
        
        success = temp_db.update_transaction_status(
            session, "tx_789", TransactionStatus.AUDITED
        )
        assert success
        
        tx = temp_db.get_transaction(session, "tx_789")
        assert tx.status == TransactionStatus.AUDITED
        session.close()


class TestCommitmentOperations:
    """Test commitment table operations."""
    
    def test_add_commitment(self, temp_db):
        """Test adding a commitment."""
        session = temp_db.get_session()
        commitment_hash = b'\x00' * 32
        merkle_root = b'\x01' * 32
        
        commitment = temp_db.add_commitment(
            session,
            commitment_hash=commitment_hash,
            commitment_index=0,
            transaction_hash="tx_deposit_1",
            merkle_root=merkle_root,
            encrypted_secret=b'\x02' * 64,
            encrypted_randomness=b'\x03' * 64,
            amount=1000.0
        )
        
        assert commitment.commitment_index == 0
        assert commitment.amount == 1000.0
        session.close()
    
    def test_get_commitment_by_index(self, temp_db):
        """Test retrieving commitment by index."""
        session = temp_db.get_session()
        commitment_hash = b'\x04' * 32
        
        temp_db.add_commitment(
            session,
            commitment_hash=commitment_hash,
            commitment_index=5,
            transaction_hash="tx_deposit_2",
            merkle_root=b'\x05' * 32,
            encrypted_secret=b'\x06' * 64,
            encrypted_randomness=b'\x07' * 64,
            amount=2000.0
        )
        
        commitment = temp_db.get_commitment_by_index(session, 5)
        assert commitment is not None
        assert commitment.amount == 2000.0
        session.close()
    
    def test_get_commitment_by_hash(self, temp_db):
        """Test retrieving commitment by hash."""
        session = temp_db.get_session()
        commitment_hash = b'\x08' * 32
        
        temp_db.add_commitment(
            session,
            commitment_hash=commitment_hash,
            commitment_index=10,
            transaction_hash="tx_deposit_3",
            merkle_root=b'\x09' * 32,
            encrypted_secret=b'\x0a' * 64,
            encrypted_randomness=b'\x0b' * 64,
            amount=3000.0
        )
        
        commitment = temp_db.get_commitment_by_hash(session, commitment_hash)
        assert commitment is not None
        assert commitment.commitment_index == 10
        session.close()


class TestNullifierOperations:
    """Test nullifier table operations."""
    
    def test_add_nullifier(self, temp_db):
        """Test adding a nullifier."""
        session = temp_db.get_session()
        nullifier_hash = b'\x0c' * 32
        commitment_hash = b'\x0d' * 32
        
        nullifier = temp_db.add_nullifier(session, nullifier_hash, commitment_hash)
        assert nullifier.is_spent == 0
        assert nullifier.spent_timestamp is None
        session.close()
    
    def test_mark_nullifier_spent(self, temp_db):
        """Test marking nullifier as spent."""
        session = temp_db.get_session()
        nullifier_hash = b'\x0e' * 32
        commitment_hash = b'\x0f' * 32
        
        temp_db.add_nullifier(session, nullifier_hash, commitment_hash)
        
        success = temp_db.mark_nullifier_spent(session, nullifier_hash, "tx_withdrawal_1")
        assert success
        
        # Verify it's marked as spent
        assert temp_db.is_nullifier_spent(session, nullifier_hash)
        session.close()
    
    def test_is_nullifier_spent(self, temp_db):
        """Test checking if nullifier is spent."""
        session = temp_db.get_session()
        nullifier_hash = b'\x10' * 32
        
        # Before marking as spent
        assert not temp_db.is_nullifier_spent(session, nullifier_hash)
        
        # Add and mark as spent
        temp_db.add_nullifier(session, nullifier_hash, b'\x11' * 32)
        temp_db.mark_nullifier_spent(session, nullifier_hash, "tx_withdrawal_2")
        
        # After marking as spent
        assert temp_db.is_nullifier_spent(session, nullifier_hash)
        session.close()


class TestAuditOperations:
    """Test audit record operations."""
    
    def test_add_audit_record(self, temp_db):
        """Test adding audit record."""
        session = temp_db.get_session()
        
        audit = temp_db.add_audit_record(
            session,
            audit_hash="audit_123",
            transaction_hash="tx_deposit_4",
            decrypted_identity="alice@example.com",
            auditor_note="Flagged for review"
        )
        
        assert audit.decrypted_identity == "alice@example.com"
        assert audit.auditor_note == "Flagged for review"
        session.close()
    
    def test_get_audit_record(self, temp_db):
        """Test retrieving audit record."""
        session = temp_db.get_session()
        
        temp_db.add_audit_record(
            session,
            audit_hash="audit_456",
            transaction_hash="tx_deposit_5",
            decrypted_identity="bob@example.com"
        )
        
        audit = temp_db.get_audit_record(session, "audit_456")
        assert audit is not None
        assert audit.decrypted_identity == "bob@example.com"
        session.close()
    
    def test_get_audits_for_transaction(self, temp_db):
        """Test retrieving all audits for a transaction."""
        session = temp_db.get_session()
        
        temp_db.add_audit_record(session, "audit_a", "tx_deposit_6", "alice@example.com")
        temp_db.add_audit_record(session, "audit_b", "tx_deposit_6", "alice@example.com")
        
        audits = temp_db.get_audits_for_transaction(session, "tx_deposit_6")
        assert len(audits) == 2
        session.close()


class TestMerkleRootOperations:
    """Test Merkle root operations."""
    
    def test_add_merkle_root(self, temp_db):
        """Test adding Merkle root snapshot."""
        session = temp_db.get_session()
        root_hash = b'\x12' * 32
        
        root = temp_db.add_merkle_root(session, root_hash, tree_height=8, num_leaves=10)
        assert root.tree_height == 8
        assert root.num_leaves == 10
        session.close()
    
    def test_get_current_root(self, temp_db):
        """Test retrieving current Merkle root."""
        session = temp_db.get_session()
        
        temp_db.add_merkle_root(session, b'\x13' * 32, 8, 5)
        temp_db.add_merkle_root(session, b'\x14' * 32, 8, 10)
        
        current = temp_db.get_current_root(session)
        assert current is not None
        assert current.num_leaves == 10
        session.close()


class TestStatisticsOperations:
    """Test statistics operations."""
    
    def test_save_statistics(self, temp_db):
        """Test saving statistics."""
        session = temp_db.get_session()
        
        stats = temp_db.save_statistics(
            session,
            total_deposits=10,
            total_withdrawals=5,
            total_volume=5000.0,
            num_commitments=10,
            num_nullifiers=5,
            num_audited=2
        )
        
        assert stats.total_deposits == 10
        assert stats.total_volume == 5000.0
        session.close()
    
    def test_get_latest_statistics(self, temp_db):
        """Test retrieving latest statistics."""
        session = temp_db.get_session()
        
        temp_db.save_statistics(session, 5, 2, 2500.0, 5, 2, 1)
        temp_db.save_statistics(session, 10, 5, 5000.0, 10, 5, 2)
        
        latest = temp_db.get_latest_statistics(session)
        assert latest is not None
        assert latest.total_deposits == 10
        session.close()


class TestAggregateQueries:
    """Test aggregate query operations."""
    
    def test_get_total_volume(self, temp_db):
        """Test getting total volume."""
        session = temp_db.get_session()
        
        temp_db.add_transaction(session, "tx_1", TransactionType.DEPOSIT, 1000.0)
        temp_db.add_transaction(session, "tx_2", TransactionType.DEPOSIT, 2000.0)
        temp_db.add_transaction(session, "tx_3", TransactionType.WITHDRAWAL, 500.0)
        
        total = temp_db.get_total_volume(session)
        assert total == 3000.0
        session.close()
    
    def test_get_transaction_count(self, temp_db):
        """Test getting transaction count."""
        session = temp_db.get_session()
        
        temp_db.add_transaction(session, "tx_4", TransactionType.DEPOSIT, 1000.0)
        temp_db.add_transaction(session, "tx_5", TransactionType.DEPOSIT, 2000.0)
        temp_db.add_transaction(session, "tx_6", TransactionType.WITHDRAWAL, 500.0)
        
        total_count = temp_db.get_transaction_count(session)
        assert total_count == 3
        
        deposit_count = temp_db.get_transaction_count(session, TransactionType.DEPOSIT)
        assert deposit_count == 2
        
        session.close()
    
    def test_get_recent_transactions(self, temp_db):
        """Test getting recent transactions."""
        session = temp_db.get_session()
        
        for i in range(15):
            temp_db.add_transaction(session, f"tx_{i}", TransactionType.DEPOSIT, float(i * 100))
        
        recent = temp_db.get_recent_transactions(session, limit=10)
        assert len(recent) == 10
        session.close()


class TestDataIntegrity:
    """Test data integrity and relationships."""
    
    def test_commitment_and_nullifier_relationship(self, temp_db):
        """Test commitment and nullifier relationships."""
        session = temp_db.get_session()
        
        commitment_hash = b'\x15' * 32
        nullifier_hash = b'\x16' * 32
        
        # Add commitment
        temp_db.add_commitment(
            session,
            commitment_hash=commitment_hash,
            commitment_index=0,
            transaction_hash="tx_deposit_7",
            merkle_root=b'\x17' * 32,
            encrypted_secret=b'\x18' * 64,
            encrypted_randomness=b'\x19' * 64,
            amount=1000.0
        )
        
        # Add corresponding nullifier
        temp_db.add_nullifier(session, nullifier_hash, commitment_hash)
        
        # Verify both exist
        commitment = temp_db.get_commitment_by_hash(session, commitment_hash)
        assert commitment is not None
        
        nullifier = session.query(Nullifier).filter_by(nullifier_hash=nullifier_hash).first()
        assert nullifier is not None
        assert nullifier.commitment_hash == commitment_hash
        
        session.close()
    
    def test_complete_transaction_workflow(self, temp_db):
        """Test complete transaction workflow."""
        session = temp_db.get_session()
        
        # Deposit
        deposit_hash = "tx_deposit_complete"
        temp_db.add_transaction(session, deposit_hash, TransactionType.DEPOSIT, 1000.0)
        
        # Add commitment
        commitment_hash = b'\x1a' * 32
        temp_db.add_commitment(
            session,
            commitment_hash=commitment_hash,
            commitment_index=0,
            transaction_hash=deposit_hash,
            merkle_root=b'\x1b' * 32,
            encrypted_secret=b'\x1c' * 64,
            encrypted_randomness=b'\x1d' * 64,
            amount=1000.0
        )
        
        # Withdrawal
        withdrawal_hash = "tx_withdrawal_complete"
        nullifier_hash = b'\x1e' * 32
        
        temp_db.add_nullifier(session, nullifier_hash, commitment_hash)
        temp_db.add_transaction(session, withdrawal_hash, TransactionType.WITHDRAWAL, 1000.0)
        temp_db.mark_nullifier_spent(session, nullifier_hash, withdrawal_hash)
        
        # Audit
        audit_hash = "audit_complete"
        temp_db.add_audit_record(session, audit_hash, deposit_hash, "alice@example.com")
        temp_db.update_transaction_status(session, deposit_hash, TransactionStatus.AUDITED)
        
        # Verify complete workflow
        deposit = temp_db.get_transaction(session, deposit_hash)
        assert deposit.status == TransactionStatus.AUDITED
        
        commitment = temp_db.get_commitment_by_hash(session, commitment_hash)
        assert commitment.amount == 1000.0
        
        assert temp_db.is_nullifier_spent(session, nullifier_hash)
        
        audits = temp_db.get_audits_for_transaction(session, deposit_hash)
        assert len(audits) == 1
        assert audits[0].decrypted_identity == "alice@example.com"
        
        session.close()
