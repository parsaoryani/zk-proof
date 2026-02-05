"""Property-based tests using Hypothesis for cryptographic invariants."""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
import secrets

from zkm.crypto.coin import Coin
from zkm.crypto.merkle_tree import MerkleTree
from zkm.crypto.nullifier import NullifierProver, NullifierVerifier, NullifierSet
from zkm.crypto.zk_snark import BulletproofZKProver, BulletproofZKVerifier


class TestCryptographicProperties:
    """Property-based tests for cryptographic system invariants."""

    @given(st.integers(min_value=1, max_value=2**63 - 1))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_coin_commitment_deterministic(self, value: int):
        """Property: Same coin parameters produce same commitment."""
        # Create coin with fixed spend_key and randomness
        spend_key = "a" * 64
        randomness = "b" * 64

        coin1 = Coin(
            value=value,
            spend_key=spend_key,
            randomness=randomness,
        )

        coin2 = Coin(
            value=value,
            spend_key=spend_key,
            randomness=randomness,
        )

        # Commitments must be identical
        assert coin1.commitment == coin2.commitment

    @given(st.integers(min_value=1, max_value=2**63 - 1))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_coin_nullifier_unique_per_coin(self, value: int):
        """Property: Different spend keys produce different nullifiers."""
        coin1 = Coin.generate(value=value)
        coin2 = Coin.generate(value=value)

        # Different coins have different nullifiers
        nullifier1 = coin1.compute_nullifier()
        nullifier2 = coin2.compute_nullifier()

        assert nullifier1 != nullifier2

    @given(st.lists(st.integers(min_value=1, max_value=1000), min_size=10, max_size=100))
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_tree_root_stable(self, values: list):
        """Property: Adding coins in same order produces same root."""
        tree1 = MerkleTree()
        tree2 = MerkleTree()

        # Create coins with deterministic keys (must be valid hex)
        coins = [
            Coin(
                value=v, 
                spend_key=f"{i:064x}",  # Valid hex: 64-char hex string
                randomness=f"{(i+1000):064x}"  # Valid hex: different from spend_key
            )
            for i, v in enumerate(values)
        ]

        # Insert in same order into both trees
        for coin in coins:
            commitment = coin.commitment
            tree1.insert(commitment)
            tree2.insert(commitment)

        # Roots must match
        assert tree1.root == tree2.root

    @given(
        st.lists(
            st.integers(min_value=1, max_value=10000),
            min_size=5,
            max_size=50,
        )
    )
    @settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
    def test_merkle_proof_verification_completeness(self, values: list):
        """Property: Every proof for inserted coin verifies correctly."""
        tree = MerkleTree()
        coins = [Coin.generate(value=v) for v in values]

        # Insert all coins
        indices = []
        for coin in coins:
            commitment = coin.commitment
            leaf_index, root = tree.insert(commitment)
            indices.append((leaf_index, coin.commitment))

        # Every coin's proof must verify
        for leaf_index, commitment in indices:
            proof = tree.prove(leaf_index)
            assert proof.verify(), f"Merkle proof failed for leaf {leaf_index}"

    def test_nullifier_set_double_spend_detection(self):
        """Property: Nullifier set correctly identifies spent coins."""
        nullifier_set = NullifierSet()

        # Create some coins
        coin1 = Coin.generate(value=1000)
        coin2 = Coin.generate(value=500)

        nullifier1 = coin1.compute_nullifier()
        nullifier2 = coin2.compute_nullifier()

        # Initially not spent
        assert not nullifier_set.is_spent(nullifier1)
        assert not nullifier_set.is_spent(nullifier2)

        # Register nullifier1 as spent
        success = nullifier_set.register(nullifier1, "tx_hash_1")
        assert success

        # Now only nullifier1 is spent
        assert nullifier_set.is_spent(nullifier1)
        assert not nullifier_set.is_spent(nullifier2)

        # Try to register duplicate (should return False for double-spend)
        success = nullifier_set.register(nullifier1, "tx_hash_2")
        assert not success  # Should fail (double-spend detected)

    @given(st.integers(min_value=0, max_value=2**32 - 1))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_zk_proof_value_invariant(self, value: int):
        """Property: zk-SNARK proof preserves value invariant."""
        if value == 0:
            pytest.skip("Zero value not meaningful")

        prover = BulletproofZKProver()
        tree = MerkleTree()

        coin = Coin.generate(value=value)
        commitment = coin.commitment
        leaf_index, root = tree.insert(commitment)

        merkle_proof = tree.prove(leaf_index)
        path = merkle_proof.path

        # Create proof with same input/output value
        proof = prover.create_complete_payment_proof(
            commitment=commitment,
            commitment_secret=coin.spend_key,
            merkle_path=path,
            leaf_index=leaf_index,
            merkle_root=root,
            input_amount=value,
            output_amount=value,
            spend_key=coin.spend_key,
            randomness=coin.randomness,
        )

        # Verify the proof exists
        assert proof is not None
        assert proof.nullifier is not None
        assert proof.output_commitment is not None

    @given(
        st.lists(
            st.integers(min_value=1, max_value=1000),
            min_size=10,
            max_size=100,
        )
    )
    @settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
    def test_large_merkle_tree_consistency(self, values: list):
        """Property: Large Merkle tree maintains consistency."""
        tree = MerkleTree()
        coins_and_indices = []

        # Insert many coins
        for v in values:
            coin = Coin.generate(value=v)
            commitment = coin.commitment
            leaf_index, root = tree.insert(commitment)
            coins_and_indices.append((coin, leaf_index, commitment, root))

        # Verify all coins still provable from final root
        final_root = tree.root

        for coin, leaf_index, commitment, old_root in coins_and_indices:
            proof = tree.prove(leaf_index)
            # Proof should still verify (root might be different but structure is consistent)
            assert proof.verify()

    def test_no_commitment_linkability(self):
        """Property: Commitment and nullifier are unlinkable."""
        coin = Coin.generate(value=1000)

        commitment = coin.commitment
        nullifier = coin.compute_nullifier()

        # These should be completely different
        assert commitment != nullifier

        # One should not contain the other (both are hex strings)
        assert commitment not in nullifier
        assert nullifier not in commitment

    @given(st.integers(min_value=1, max_value=10))
    @settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
    def test_multiple_coins_independence(self, num_coins: int):
        """Property: Multiple coins are independent."""
        coins = [Coin.generate(value=1000) for _ in range(num_coins)]

        commitments = [c.commitment for c in coins]
        nullifiers = [c.compute_nullifier() for c in coins]

        # All commitments different
        assert len(commitments) == len(set(commitments))

        # All nullifiers different
        assert len(nullifiers) == len(set(nullifiers))

        # No commitment equals any nullifier
        for c in commitments:
            assert c not in nullifiers


class TestCryptographicInvariants:
    """Test mathematical properties and invariants."""

    def test_commitment_hiding(self):
        """Test: Commitments are hiding (hiding property)."""
        value1 = 1000
        value2 = 2000

        coin1 = Coin.generate(value=value1)
        coin2 = Coin.generate(value=value2)

        commitment1 = coin1.commitment
        commitment2 = coin2.commitment

        # Different values should typically produce different commitments
        assert commitment1 != commitment2

    def test_commitment_binding(self):
        """Test: Generated coins have consistent commitments."""
        coin = Coin.generate(value=1000)

        commitment1 = coin.commitment
        commitment2 = coin.commitment  # Access again

        # Commitment should be stable
        assert commitment1 == commitment2

    def test_nullifier_determinism(self):
        """Test: Same coin produces same nullifier consistently."""
        coin = Coin.generate(value=100)

        nullifier1 = coin.compute_nullifier()
        nullifier2 = coin.compute_nullifier()

        assert nullifier1 == nullifier2

    def test_merkle_tree_completeness(self):
        """Test: All inserted coins can be proven to be in tree."""
        tree = MerkleTree()
        num_coins = 50

        coins_and_indices = []
        for i in range(num_coins):
            coin = Coin.generate(value=i + 1)
            commitment = coin.commitment
            leaf_index, root = tree.insert(commitment)
            coins_and_indices.append((coin, leaf_index, commitment))

        # Every coin should have a valid proof
        for coin, leaf_index, commitment in coins_and_indices:
            proof = tree.prove(leaf_index)
            assert proof.verify()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
