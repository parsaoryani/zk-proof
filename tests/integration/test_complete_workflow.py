"""Integration tests for the complete ZK-Mixer system."""

import pytest
from zkm.core.mixer import ZKMixer
from zkm.core.zkproof import ZKProofSystem
from zkm.core.commitment import Commitment
from zkm.exceptions import WithdrawalError, DoubleSpendError, AuditError


class TestCompleteMixerWorkflow:
    """Tests for complete mixer workflows."""
    
    @pytest.fixture
    def mixer(self):
        """Create a mixer for testing."""
        return ZKMixer(merkle_tree_height=8)
    
    def test_single_user_deposit_and_withdrawal(self, mixer):
        """Test complete deposit and withdrawal cycle for single user."""
        identity = "alice@example.com"
        amount = 1000
        
        # Step 1: Deposit
        deposit_receipt = mixer.deposit(identity, amount)
        assert deposit_receipt.commitment_index == 0
        assert deposit_receipt.commitment is not None
        assert deposit_receipt.deposit_hash is not None
        
        # Verify transaction recorded
        tx = mixer.get_transaction(deposit_receipt.deposit_hash)
        assert tx is not None
        assert tx["type"] == "deposit"
        assert tx["amount"] == amount
        
        # Step 2: Get deposit info for withdrawal
        deposit_info = mixer.deposits[deposit_receipt.commitment_index]
        secret = bytes.fromhex(deposit_info["secret"])
        randomness = bytes.fromhex(deposit_info["randomness"])
        
        # Step 3: Generate withdrawal proof
        merkle_path = mixer.merkle_tree.get_path(deposit_receipt.commitment_index)
        proof = ZKProofSystem.generate_withdrawal_proof(
            secret=secret,
            randomness=randomness,
            merkle_path=merkle_path,
            leaf_index=deposit_receipt.commitment_index,
            auditor_pk=mixer.auditor.public_key,
            identity=identity
        )
        
        # Step 4: Withdraw
        withdrawal_receipt = mixer.withdraw(proof)
        assert withdrawal_receipt.status == "success"
        assert withdrawal_receipt.transaction_hash is not None
        
        # Verify withdrawal recorded
        tx = mixer.get_transaction(withdrawal_receipt.transaction_hash)
        assert tx["type"] == "withdrawal"
    
    def test_double_spend_prevention(self, mixer):
        """Test that double-spending is prevented."""
        identity = "bob@example.com"
        amount = 500
        
        # Deposit
        deposit_receipt = mixer.deposit(identity, amount)
        
        # Get deposit info
        deposit_info = mixer.deposits[deposit_receipt.commitment_index]
        secret = bytes.fromhex(deposit_info["secret"])
        randomness = bytes.fromhex(deposit_info["randomness"])
        
        # Generate proof
        merkle_path = mixer.merkle_tree.get_path(deposit_receipt.commitment_index)
        proof = ZKProofSystem.generate_withdrawal_proof(
            secret=secret,
            randomness=randomness,
            merkle_path=merkle_path,
            leaf_index=deposit_receipt.commitment_index,
            auditor_pk=mixer.auditor.public_key,
            identity=identity
        )
        
        # First withdrawal succeeds
        receipt1 = mixer.withdraw(proof)
        assert receipt1.status == "success"
        
        # Second withdrawal with same proof fails
        with pytest.raises(WithdrawalError):
            mixer.withdraw(proof)
    
    def test_multiple_users(self, mixer):
        """Test mixer with multiple users."""
        users = [
            ("alice@example.com", 1000),
            ("bob@example.com", 500),
            ("charlie@example.com", 2000),
        ]
        
        receipts = []
        for identity, amount in users:
            receipt = mixer.deposit(identity, amount)
            receipts.append((receipt, identity, amount))
        
        assert len(mixer.merkle_tree) == 3
        assert mixer.total_volume == sum(amount for identity, amount in users)
        
        # Withdraw from all users
        for receipt, identity, amount in receipts:
            deposit_info = mixer.deposits[receipt.commitment_index]
            secret = bytes.fromhex(deposit_info["secret"])
            randomness = bytes.fromhex(deposit_info["randomness"])
            
            merkle_path = mixer.merkle_tree.get_path(receipt.commitment_index)
            proof = ZKProofSystem.generate_withdrawal_proof(
                secret=secret,
                randomness=randomness,
                merkle_path=merkle_path,
                leaf_index=receipt.commitment_index,
                auditor_pk=mixer.auditor.public_key,
                identity=identity
            )
            
            withdrawal_receipt = mixer.withdraw(proof)
            assert withdrawal_receipt.status == "success"
        
        assert len(mixer.nullifier_set) == 3
    
    def test_audit_functionality(self, mixer):
        """Test audit transaction functionality."""
        identity = "audit_test@example.com"
        amount = 1500
        
        # Deposit
        deposit_receipt = mixer.deposit(identity, amount)
        deposit_hash = deposit_receipt.deposit_hash
        
        # Audit transaction
        audit_result = mixer.audit_transaction(
            transaction_hash=deposit_hash,
            auditor_private_key=mixer.auditor.private_key
        )
        
        assert audit_result.decrypted_identity == identity
        assert audit_result.transaction_hash == deposit_hash
        assert audit_result.audit_timestamp is not None
        
        # Verify transaction marked as audited
        tx = mixer.get_transaction(deposit_hash)
        assert tx["status"] == "audited"
    
    def test_mixer_state_consistency(self, mixer):
        """Test that mixer state remains consistent."""
        # Initial state
        state1 = mixer.get_mixer_state()
        assert state1.num_commitments == 0
        assert state1.num_nullifiers == 0
        
        # After deposits
        mixer.deposit("user1@example.com", 100)
        mixer.deposit("user2@example.com", 200)
        
        state2 = mixer.get_mixer_state()
        assert state2.num_commitments == 2
        assert state2.num_nullifiers == 0
        
        # After withdrawal
        deposit_info = mixer.deposits[0]
        secret = bytes.fromhex(deposit_info["secret"])
        randomness = bytes.fromhex(deposit_info["randomness"])
        
        merkle_path = mixer.merkle_tree.get_path(0)
        proof = ZKProofSystem.generate_withdrawal_proof(
            secret=secret,
            randomness=randomness,
            merkle_path=merkle_path,
            leaf_index=0,
            auditor_pk=mixer.auditor.public_key,
            identity="user1@example.com"
        )
        
        mixer.withdraw(proof)
        
        state3 = mixer.get_mixer_state()
        assert state3.num_commitments == 2  # Commitments don't change
        assert state3.num_nullifiers == 1


class TestMixerStatistics:
    """Tests for mixer statistics."""
    
    def test_statistics_calculation(self):
        """Test statistics are calculated correctly."""
        mixer = ZKMixer(merkle_tree_height=8)
        
        # Add some transactions
        mixer.deposit("user1@example.com", 1000)
        mixer.deposit("user2@example.com", 500)
        mixer.deposit("user3@example.com", 2000)
        
        stats = mixer.get_statistics()
        
        assert stats["total_deposits"] == 3
        assert stats["total_withdrawals"] == 0
        assert stats["total_volume"] == 3500
        assert stats["num_commitments"] == 3
        assert stats["audited_transactions"] == 0


class TestMixerErrorHandling:
    """Tests for error handling in mixer."""
    
    def test_invalid_proof_rejection(self):
        """Test that invalid proofs are rejected."""
        mixer = ZKMixer(merkle_tree_height=8)
        
        identity = "user@example.com"
        deposit_receipt = mixer.deposit(identity, 1000)
        
        # Create invalid proof (wrong commitment)
        import os
        from zkm.core.zkproof import WithdrawalProof
        
        invalid_proof = WithdrawalProof(
            nullifier=os.urandom(32),
            merkle_path=[os.urandom(32) for _ in range(8)],
            leaf_index=0,
            identity_encryption_proof=os.urandom(32),
            encrypted_identity=os.urandom(256),
            timestamp=__import__('datetime').datetime.now(),
            proof_hash=os.urandom(32)
        )
        
        with pytest.raises(WithdrawalError):
            mixer.withdraw(invalid_proof)
    
    def test_audit_nonexistent_transaction(self):
        """Test auditing non-existent transaction."""
        mixer = ZKMixer(merkle_tree_height=8)
        
        with pytest.raises(AuditError):
            mixer.audit_transaction(
                transaction_hash="nonexistent_tx",
                auditor_private_key=mixer.auditor.private_key
            )
    
    def test_audit_wrong_key(self):
        """Test auditing with wrong auditor key."""
        mixer = ZKMixer(merkle_tree_height=8)
        
        # Deposit
        deposit_receipt = mixer.deposit("user@example.com", 1000)
        
        # Create different auditor
        from zkm.core.auditor import Auditor
        wrong_auditor = Auditor()
        
        # Attempt audit with wrong key
        with pytest.raises(AuditError):
            mixer.audit_transaction(
                transaction_hash=deposit_receipt.deposit_hash,
                auditor_private_key=wrong_auditor.private_key
            )


class TestMixerPrivacy:
    """Tests for privacy properties of the mixer."""
    
    def test_commitment_hides_secret(self):
        """Test that commitments hide secrets."""
        mixer = ZKMixer(merkle_tree_height=8)
        
        identity = "user@example.com"
        deposit_receipt = mixer.deposit(identity, 1000)
        
        # Commitment should not reveal secret
        deposit_info = mixer.deposits[deposit_receipt.commitment_index]
        secret = bytes.fromhex(deposit_info["secret"])
        
        assert deposit_receipt.commitment != secret
        assert deposit_receipt.commitment.hex() != secret.hex()
    
    def test_nullifier_prevents_linking(self):
        """Test that nullifier prevents transaction linking."""
        mixer = ZKMixer(merkle_tree_height=8)
        
        identity = "user@example.com"
        deposit_receipt = mixer.deposit(identity, 1000)
        
        # Get nullifier
        deposit_info = mixer.deposits[deposit_receipt.commitment_index]
        nullifier_hex = deposit_info["nullifier"]
        
        # Nullifier should not be visible during withdrawal proof
        # (It's used for prevention, but not revealed to system)
        assert len(mixer.nullifier_set) == 0  # Not added until withdrawal
    
    def test_default_anonymity(self):
        """Test that transactions are anonymous by default."""
        mixer = ZKMixer(merkle_tree_height=8)
        
        identity = "alice@example.com"
        deposit_receipt = mixer.deposit(identity, 1000)
        
        # Get deposit info
        deposit_info = mixer.deposits[deposit_receipt.commitment_index]
        secret = bytes.fromhex(deposit_info["secret"])
        randomness = bytes.fromhex(deposit_info["randomness"])
        
        # Generate withdrawal proof
        merkle_path = mixer.merkle_tree.get_path(deposit_receipt.commitment_index)
        proof = ZKProofSystem.generate_withdrawal_proof(
            secret=secret,
            randomness=randomness,
            merkle_path=merkle_path,
            leaf_index=deposit_receipt.commitment_index,
            auditor_pk=mixer.auditor.public_key,
            identity=identity
        )
        
        # Withdraw
        withdrawal_receipt = mixer.withdraw(proof)
        
        # Check withdrawal record - should not contain identity
        withdrawal_tx = mixer.get_transaction(withdrawal_receipt.transaction_hash)
        assert "identity" not in withdrawal_tx
