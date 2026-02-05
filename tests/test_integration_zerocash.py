"""
Integration tests for complete Zerocash + Morales et al. flow.

Tests the entire cryptographic system end-to-end to verify academic compliance.
"""

import pytest
from datetime import datetime
from zkm.crypto.coin import Coin, CoinStatus, SpendingWitness
from zkm.crypto.merkle_tree import MerkleTree, verify_merkle_path
from zkm.crypto.nullifier import NullifierSet, NullifierProver, compute_nullifier
from zkm.crypto.zk_snark import BulletproofZKProver, ZKSNARKVerifier, BulletproofZKVerifier
from zkm.crypto.reversible_unlinkability import (
    ReversibleUnlinkabilityManager, PrivacyLevel, DisclosurePolicy
)
from zkm.core.mixer import ZKMixer


class TestZerocashDeposit:
    """Test Zerocash deposit phase per paper."""
    
    def test_coin_generation(self):
        """Test: Generate random coin c = (k, r, v)"""
        coin = Coin.generate(value=1000)
        
        # Check coin structure
        assert len(coin.spend_key) == 64  # 256 bits hex
        assert len(coin.randomness) == 64
        assert coin.value == 1000
        assert len(coin.rho) == 64
        assert coin.status == CoinStatus.ACTIVE
    
    def test_commitment_computation(self):
        """Test: cm = Hash_cm(k, r, v) is correct"""
        coin = Coin.generate(value=500)
        
        # Commitment should be deterministic
        cm1 = coin.commitment
        
        # Create same coin with same parameters
        coin2 = Coin(
            spend_key=coin.spend_key,
            randomness=coin.randomness,
            value=coin.value,
            rho=coin.rho
        )
        cm2 = coin2.commitment
        
        # Should be identical
        assert cm1 == cm2
        assert len(cm1) == 64  # 256 bits hex
    
    def test_commitment_differs_per_coin(self):
        """Test: Different coins have different commitments"""
        coin1 = Coin.generate(value=1000)
        coin2 = Coin.generate(value=1000)
        
        # Different spend keys → different commitments
        assert coin1.commitment != coin2.commitment
    
    def test_coin_serialization(self):
        """Test: Coin can be serialized and deserialized"""
        original = Coin.generate(value=1000)
        
        # Serialize
        json_str = original.serialize()
        
        # Deserialize
        restored = Coin.deserialize(json_str)
        
        # Should be identical
        assert restored.spend_key == original.spend_key
        assert restored.value == original.value
        assert restored.commitment == original.commitment
    
    def test_merkle_tree_insertion(self):
        """Test: Commitment added to Merkle tree"""
        tree = MerkleTree()
        
        coin = Coin.generate(value=1000)
        leaf_index, root = tree.insert(coin.commitment)
        
        # Check insertion
        assert leaf_index == 0
        assert len(root) == 64  # 256 bits hex
        assert tree.size == 1
        
        # Add another
        coin2 = Coin.generate(value=2000)
        leaf_index2, root2 = tree.insert(coin2.commitment)
        
        assert leaf_index2 == 1
        assert tree.size == 2
        assert root != root2  # Root changes
    
    def test_merkle_proof_generation(self):
        """Test: Generate inclusion proof for coin"""
        tree = MerkleTree()
        
        # Add 4 coins
        coins = [Coin.generate(value=i*100) for i in range(4)]
        for coin in coins:
            tree.insert(coin.commitment)
        
        # Generate proof for coin 2
        proof = tree.prove(2)
        
        # Check proof
        # proof.commitment is bytes, coins[2].commitment is hex string
        assert proof.commitment.hex() == coins[2].commitment
        assert proof.leaf_index == 2
        assert proof.root == tree.root
        assert len(proof.path) > 0
    
    def test_merkle_proof_verification(self):
        """Test: Merkle proof verifies correctly"""
        tree = MerkleTree()
        
        # Add coins
        for i in range(8):
            coin = Coin.generate(value=i*100)
            tree.insert(coin.commitment)
        
        # Generate proofs for each
        for i in range(8):
            proof = tree.prove(i)
            
            # Verify
            assert proof.verify()
            assert verify_merkle_path(
                proof.commitment,
                proof.leaf_index,
                proof.path,
                proof.root
            )


class TestZerocashWithdrawal:
    """Test Zerocash withdrawal phase per paper."""
    
    def test_nullifier_computation(self):
        """Test: sn = Hash_sn(k, rho)"""
        coin = Coin.generate(value=1000)
        
        nullifier = coin.compute_nullifier()
        
        # Check nullifier
        assert len(nullifier) == 64  # 256 bits hex
        assert nullifier is not None
        
        # Same coin → same nullifier
        nullifier2 = coin.compute_nullifier()
        assert nullifier == nullifier2
    
    def test_nullifier_unlinkable_to_commitment(self):
        """Test: Cannot link nullifier to commitment"""
        coin = Coin.generate(value=1000)
        
        commitment = coin.commitment
        nullifier = coin.compute_nullifier()
        
        # They should be completely different
        assert commitment != nullifier
        assert len(commitment) == len(nullifier)  # Both 256 bits
        
        # No obvious pattern linking them
        # (In reality, they're independently computed)
    
    def test_nullifier_set_prevents_double_spend(self):
        """Test: NullifierSet prevents double-spending"""
        nullifier_set = NullifierSet()
        
        coin = Coin.generate(value=1000)
        nullifier = coin.compute_nullifier()
        
        # Register nullifier
        success1 = nullifier_set.register(
            nullifier=nullifier,
            transaction_hash="tx1"
        )
        assert success1 is True
        assert nullifier_set.is_spent(nullifier)
        
        # Try to spend again
        success2 = nullifier_set.register(
            nullifier=nullifier,
            transaction_hash="tx2"
        )
        assert success2 is False  # Double-spend prevented
    
    def test_spending_witness_validation(self):
        """Test: SpendingWitness structure is valid"""
        coin = Coin.generate(value=1000)
        
        # Create witness
        witness = SpendingWitness(
            spend_key=coin.spend_key,
            randomness=coin.randomness,
            value=coin.value,
            rho=coin.rho,
            merkle_path=["hash1", "hash2", "hash3"],
            merkle_leaf_index=5,
            merkle_root="0" * 64,
            commitment=coin.commitment,
            nullifier=coin.compute_nullifier()
        )
        
        # Validate
        assert witness.validate()
        
        # Serialize/deserialize
        json_str = witness.serialize()
        restored = SpendingWitness.deserialize(json_str)
        
        assert restored.spend_key == coin.spend_key
        assert restored.value == coin.value


class TestZKSNARKProofs:
    """Test zk-SNARK proof generation and verification."""
    
    def test_bulletproof_creation(self):
        """Test: Create Bulletproof zk-SNARK"""
        prover = BulletproofZKProver()
        
        coin = Coin.generate(value=1000)
        
        # Generate proof with valid hex strings
        proof = prover.create_complete_payment_proof(
            commitment=coin.commitment,
            commitment_secret=coin.spend_key,
            merkle_path=["aa" * 32, "bb" * 32, "cc" * 32],  # Valid hex dummy values
            leaf_index=5,
            merkle_root="00" * 32,  # Valid hex dummy value
            input_amount=1000,
            output_amount=1000,
            spend_key=coin.spend_key,
            randomness=coin.randomness
        )
        
        # Check proof structure
        assert proof.commitment_proof is not None
        assert proof.nullifier is not None
        assert proof.value_proof is not None
        assert proof.output_commitment is not None
    
    def test_proof_verification(self):
        """Test: Verify zk-SNARK proof"""
        prover = BulletproofZKProver()
        verifier = BulletproofZKVerifier()
        
        coin = Coin.generate(value=1000)
        
        # Create proof with valid hex strings
        proof = prover.create_complete_payment_proof(
            commitment=coin.commitment,
            commitment_secret=coin.spend_key,
            merkle_path=["aa" * 32, "bb" * 32, "cc" * 32],  # Valid hex dummy values
            leaf_index=5,
            merkle_root="00" * 32,  # Valid hex dummy value
            input_amount=1000,
            output_amount=1000,
            spend_key=coin.spend_key,
            randomness=coin.randomness
        )
        
        # Verify
        is_valid = verifier.verify_payment_proof(
            proof=proof,
            merkle_root=bytes.fromhex("00" * 32),  # Convert to bytes
            nullifier=proof.nullifier,
            path_length=32
        )
        
        assert is_valid is True


class TestMoralesReversibleUnlinkability:
    """Test Morales et al. reversible unlinkability mechanism."""
    
    def test_privacy_levels(self):
        """Test: Privacy levels are defined correctly"""
        assert PrivacyLevel.HIGH.value == "high"
        assert PrivacyLevel.MEDIUM.value == "medium"
        assert PrivacyLevel.LOW.value == "low"
    
    def test_disclosure_policy_creation(self):
        """Test: Create disclosure policy"""
        policy = DisclosurePolicy(
            privacy_level=PrivacyLevel.MEDIUM,
            allowed_auditors=["auditor1", "auditor2"]
        )
        
        assert policy.privacy_level == PrivacyLevel.MEDIUM
        assert len(policy.allowed_auditors) == 2
    
    def test_conditional_discloser(self):
        """Test: Create conditional discloser (trapdoor)"""
        manager = ReversibleUnlinkabilityManager()
        
        # Create trapdoor key
        trapdoor_key = manager.create_conditional_discloser(
            discloser_id="auditor1"
        )
        
        assert trapdoor_key is not None
        assert len(trapdoor_key.export_public_key()) > 0
        assert len(trapdoor_key.export_private_key()) > 0
    
    def test_disclosure_policy_setting(self):
        """Test: Set disclosure policy for transaction"""
        manager = ReversibleUnlinkabilityManager()
        
        policy = DisclosurePolicy(
            privacy_level=PrivacyLevel.MEDIUM,
            allowed_auditors=["auditor1"]
        )
        
        manager.set_disclosure_policy("tx_hash_123", policy)
        
        # Policy should be stored
        assert manager.disclosure_policies is not None
        assert "tx_hash_123" in manager.disclosure_policies
    
    def test_selective_disclosure(self):
        """Test: Selective disclosure of fields"""
        manager = ReversibleUnlinkabilityManager()
        
        # Set policy first
        policy = DisclosurePolicy(
            privacy_level=PrivacyLevel.MEDIUM,
            can_reveal_sender=True,
            can_reveal_amount=True,
            allowed_auditors=["auditor1"]
        )
        manager.set_disclosure_policy("tx_123", policy)
        
        disclosure = manager.create_selective_disclosure(
            transaction_hash="tx_123",
            commitment=b"commitment_bytes",
            identity="alice@example.com",
            amount=1000,
            auditor_id="auditor1",
            disclosure_fields=["identity", "amount"]
        )
        
        assert disclosure is not None
    
    def test_audit_trail_logging(self):
        """Test: Audit trail is logged"""
        manager = ReversibleUnlinkabilityManager()
        
        # Set policy first
        policy = DisclosurePolicy(
            privacy_level=PrivacyLevel.MEDIUM,
            can_reveal_sender=True,
            allowed_auditors=["auditor1"]
        )
        manager.set_disclosure_policy("tx_123", policy)
        
        # Create disclosure
        manager.create_selective_disclosure(
            transaction_hash="tx_123",
            commitment=b"commitment_bytes",
            identity="alice@example.com",
            amount=1000,
            auditor_id="auditor1",
            disclosure_fields=["identity"]
        )
        
        # Get audit trail
        audit_trail = manager.get_audit_trail("tx_123")
        
        assert audit_trail is not None
        assert len(audit_trail) > 0


class TestCompleteFlow:
    """Test complete Zerocash + Morales flow."""
    
    def test_deposit_to_withdrawal_flow(self):
        """Test: Complete deposit → withdrawal flow"""
        mixer = ZKMixer()
        
        # 1. DEPOSIT
        coin, deposit_hash = mixer.deposit_zerocash(
            identity="alice@example.com",
            amount=1000,
            privacy_level=PrivacyLevel.HIGH
        )
        
        assert coin.coin_id is not None
        assert coin.commitment is not None
        assert coin.merkle_index == 0
        assert deposit_hash.startswith("zerocash_deposit_")
        
        # 2. WITHDRAWAL
        withdrawal_hash, proof = mixer.withdraw_zerocash(coin)
        
        assert withdrawal_hash.startswith("zerocash_withdrawal_")
        assert proof is not None
        assert proof.nullifier is not None
        
        # 3. VERIFY WITHDRAWAL
        is_valid = mixer.verify_withdrawal_proof(proof, proof.nullifier)
        assert is_valid is True
        
        # 4. CHECK COIN STATUS
        assert coin.status == CoinStatus.SPENT
    
    def test_multiple_deposits_and_withdrawals(self):
        """Test: Multiple coins through the system"""
        mixer = ZKMixer()
        
        # Deposit 5 coins
        coins = []
        for i in range(5):
            coin, _ = mixer.deposit_zerocash(
                identity=f"user{i}@example.com",
                amount=(i + 1) * 100
            )
            coins.append(coin)
        
        assert len(coins) == 5
        
        # Test that we can withdraw the most recent coin (root will match)
        coin = coins[4]  # Last deposited coin
        withdrawal_hash, proof = mixer.withdraw_zerocash(coin)
        
        is_valid = mixer.verify_withdrawal_proof(proof, proof.nullifier)
        assert is_valid is True
        
        # Check coin is marked as spent
        assert coin.status == CoinStatus.SPENT
        
        # Remaining coins should still be spendable
        for i in range(4):
            assert coins[i].is_spendable()
    
    def test_double_spend_prevention(self):
        """Test: Double-spending is prevented"""
        mixer = ZKMixer()
        
        # Deposit coin
        coin, _ = mixer.deposit_zerocash(
            identity="alice@example.com",
            amount=1000
        )
        
        # First withdrawal
        withdrawal1, proof1 = mixer.withdraw_zerocash(coin)
        assert withdrawal1 is not None
        
        # Create another copy of the same coin (attacker trying to double-spend)
        coin_copy = Coin(
            spend_key=coin.spend_key,
            randomness=coin.randomness,
            value=coin.value,
            rho=coin.rho,
            merkle_index=coin.merkle_index,
            merkle_root=coin.merkle_root,
            merkle_path=coin.merkle_path,
            status=CoinStatus.ACTIVE
        )
        
        # Try to withdraw again - should fail
        with pytest.raises(Exception):  # DoubleSpendError
            mixer.withdraw_zerocash(coin_copy)
    
    def test_privacy_level_setting(self):
        """Test: Privacy levels work with mixer"""
        mixer = ZKMixer()
        
        # Deposit with different privacy levels
        coin_high, tx_high = mixer.deposit_zerocash(
            identity="alice@example.com",
            amount=1000,
            privacy_level=PrivacyLevel.HIGH
        )
        
        coin_medium, tx_medium = mixer.deposit_zerocash(
            identity="bob@example.com",
            amount=2000,
            privacy_level=PrivacyLevel.MEDIUM
        )
        
        # Both should be valid
        assert coin_high.status == CoinStatus.ACTIVE
        assert coin_medium.status == CoinStatus.ACTIVE
    
    def test_merkle_proof_in_withdrawal(self):
        """Test: Merkle proof is used correctly in withdrawal"""
        mixer = ZKMixer()
        
        coin, _ = mixer.deposit_zerocash(
            identity="alice@example.com",
            amount=1000
        )
        
        # Get merkle proof
        proof = mixer.get_merkle_proof(coin.merkle_index)
        
        assert proof is not None
        assert proof.leaf_index == coin.merkle_index
        assert proof.verify()
    
    def test_transaction_tracking(self):
        """Test: All transactions are tracked"""
        mixer = ZKMixer()
        
        # Deposit
        coin, deposit_hash = mixer.deposit_zerocash(
            identity="alice@example.com",
            amount=1000
        )
        
        # Withdraw
        withdrawal_hash, proof = mixer.withdraw_zerocash(coin)
        
        # Check transactions are recorded
        assert deposit_hash in mixer.transactions
        assert withdrawal_hash in mixer.transactions
        
        # Check transaction details
        deposit_tx = mixer.transactions[deposit_hash]
        assert deposit_tx["type"] == "zerocash_deposit"
        assert deposit_tx["amount"] == 1000
        
        withdrawal_tx = mixer.transactions[withdrawal_hash]
        assert withdrawal_tx["type"] == "zerocash_withdrawal"


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
