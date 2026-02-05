"""Performance benchmarking suite for Zerocash system."""

import pytest
import time
import json
from datetime import datetime, UTC
from statistics import mean, stdev
import sys

from zkm.crypto.coin import Coin
from zkm.crypto.merkle_tree import MerkleTree
from zkm.crypto.nullifier import NullifierProver, NullifierVerifier, NullifierSet
from zkm.crypto.zk_snark import BulletproofZKProver, BulletproofZKVerifier


class PerformanceBenchmark:
    """Benchmarking harness for cryptographic operations."""

    def __init__(self, name: str, iterations: int = 10):
        self.name = name
        self.iterations = iterations
        self.times = []

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *args):
        elapsed = time.perf_counter() - self.start
        self.times.append(elapsed)

    def report(self):
        """Print benchmark results."""
        if not self.times:
            return

        avg = mean(self.times)
        min_time = min(self.times)
        max_time = max(self.times)
        std_dev = stdev(self.times) if len(self.times) > 1 else 0

        print(f"\n{'='*70}")
        print(f"Benchmark: {self.name}")
        print(f"{'='*70}")
        print(f"Iterations:     {len(self.times)}")
        print(f"Average Time:   {avg*1000:.2f} ms")
        print(f"Min Time:       {min_time*1000:.2f} ms")
        print(f"Max Time:       {max_time*1000:.2f} ms")
        print(f"Std Dev:        {std_dev*1000:.2f} ms")
        print(f"Throughput:     {1/avg:.2f} ops/sec")

        return {
            "name": self.name,
            "iterations": len(self.times),
            "avg_ms": avg * 1000,
            "min_ms": min_time * 1000,
            "max_ms": max_time * 1000,
            "std_dev_ms": std_dev * 1000,
            "throughput_ops_sec": 1 / avg,
        }


@pytest.mark.benchmark
class TestPerformanceBenchmarks:
    """Performance benchmarks for core cryptographic operations."""

    def test_coin_generation(self):
        """Benchmark coin generation."""
        benchmark = PerformanceBenchmark("Coin Generation", iterations=100)

        for _ in range(benchmark.iterations):
            with benchmark:
                coin = Coin.generate(value=1000)

        stats = benchmark.report()
        assert stats["avg_ms"] < 50  # Should be very fast
        return stats

    def test_commitment_computation(self):
        """Benchmark commitment computation."""
        coin = Coin.generate(value=1000)
        benchmark = PerformanceBenchmark("Commitment Computation", iterations=100)

        for _ in range(benchmark.iterations):
            with benchmark:
                commitment = coin.compute_commitment()

        stats = benchmark.report()
        assert stats["avg_ms"] < 10
        return stats

    def test_nullifier_computation(self):
        """Benchmark nullifier generation."""
        coin = Coin.generate(value=1000)
        benchmark = PerformanceBenchmark("Nullifier Generation", iterations=100)

        for _ in range(benchmark.iterations):
            with benchmark:
                nullifier = coin.compute_nullifier()

        stats = benchmark.report()
        assert stats["avg_ms"] < 10
        return stats

    def test_merkle_tree_insertion(self):
        """Benchmark Merkle tree insertion."""
        tree = MerkleTree()
        benchmark = PerformanceBenchmark("Merkle Tree Insertion", iterations=100)

        for i in range(benchmark.iterations):
            commitment = Coin.generate(value=i).compute_commitment()
            with benchmark:
                tree.insert(commitment)

        stats = benchmark.report()
        assert stats["avg_ms"] < 5  # Should be logarithmic
        return stats

    def test_merkle_proof_generation(self):
        """Benchmark Merkle proof generation."""
        tree = MerkleTree()

        # Insert some commitments
        for i in range(100):
            commitment = Coin.generate(value=i).compute_commitment()
            tree.insert(commitment)

        benchmark = PerformanceBenchmark("Merkle Proof Generation", iterations=50)

        for leaf_index in range(50):
            with benchmark:
                proof = tree.prove(leaf_index)

        stats = benchmark.report()
        assert stats["avg_ms"] < 5  # Logarithmic in tree size
        return stats

    def test_merkle_proof_verification(self):
        """Benchmark Merkle proof verification."""
        tree = MerkleTree()

        # Insert commitments and generate proofs
        proofs = []
        for i in range(100):
            commitment = Coin.generate(value=i).compute_commitment()
            tree.insert(commitment)
            if i < 50:
                proofs.append(tree.prove(i))

        benchmark = PerformanceBenchmark("Merkle Proof Verification", iterations=50)

        for i, proof in enumerate(proofs):
            with benchmark:
                result = proof.verify()

        stats = benchmark.report()
        assert stats["avg_ms"] < 5
        return stats

    def test_zk_snark_proof_generation(self):
        """Benchmark zk-SNARK proof generation."""
        prover = BulletproofZKProver()
        tree = MerkleTree()
        coin = Coin.generate(value=1000)

        # Insert coin into tree
        commitment = coin.compute_commitment()
        leaf_index, root = tree.insert(commitment)

        # Get proof path
        merkle_proof = tree.prove(leaf_index)
        path = merkle_proof.path

        benchmark = PerformanceBenchmark("zk-SNARK Proof Generation", iterations=10)

        for _ in range(benchmark.iterations):
            with benchmark:
                proof = prover.create_complete_payment_proof(
                    commitment=commitment,
                    commitment_secret=coin.spend_key,
                    merkle_path=path,
                    leaf_index=leaf_index,
                    merkle_root=root,
                    input_amount=1000,
                    output_amount=1000,
                    spend_key=coin.spend_key,
                    randomness=coin.randomness,
                )

        stats = benchmark.report()
        assert stats["avg_ms"] < 500  # Can be slow for complex proof
        return stats

    def test_zk_snark_proof_verification(self):
        """Benchmark zk-SNARK proof verification."""
        prover = BulletproofZKProver()
        verifier = BulletproofZKVerifier()
        tree = MerkleTree()
        coin = Coin.generate(value=1000)

        # Create proof
        commitment = coin.compute_commitment()
        leaf_index, root = tree.insert(commitment)
        merkle_proof = tree.prove(leaf_index)
        path = merkle_proof.path

        proof = prover.create_complete_payment_proof(
            commitment=commitment,
            commitment_secret=coin.spend_key,
            merkle_path=path,
            leaf_index=leaf_index,
            merkle_root=root,
            input_amount=1000,
            output_amount=1000,
            spend_key=coin.spend_key,
            randomness=coin.randomness,
        )

        benchmark = PerformanceBenchmark("zk-SNARK Proof Verification", iterations=50)

        for _ in range(benchmark.iterations):
            with benchmark:
                result = verifier.verify_payment_proof(
                    proof=proof,
                    merkle_root=root,
                    nullifier=proof.nullifier,
                    path_length=32,
                )

        stats = benchmark.report()
        assert stats["avg_ms"] < 50
        return stats

    def test_nullifier_set_lookup(self):
        """Benchmark nullifier set membership checking."""
        nullifier_set = NullifierSet()

        # Insert nullifiers
        nullifiers = []
        for i in range(10000):
            coin = Coin.generate(value=i)
            nullifier = coin.compute_nullifier()
            nullifiers.append(nullifier)
            nullifier_set.register(nullifier, transaction_hash=f"tx_{i}")

        benchmark = PerformanceBenchmark("Nullifier Set Lookup", iterations=10000)

        for i in range(benchmark.iterations):
            nullifier = nullifiers[i % len(nullifiers)]
            with benchmark:
                is_spent = nullifier_set.is_spent(nullifier)

        stats = benchmark.report()
        assert stats["avg_ms"] < 1  # Should be O(1)
        return stats

    @pytest.mark.skip(reason="Generates large report")
    def test_full_transaction_flow(self):
        """Benchmark complete deposit + withdrawal flow."""
        tree = MerkleTree()
        prover = BulletproofZKProver()
        verifier = BulletproofZKVerifier()
        nullifier_set = NullifierSet()

        benchmark = PerformanceBenchmark("Full Transaction Flow", iterations=10)

        for _ in range(benchmark.iterations):
            with benchmark:
                # Deposit phase
                coin = Coin.generate(value=1000)
                commitment = coin.compute_commitment()
                leaf_index, root = tree.insert(commitment)

                # Withdrawal phase
                merkle_proof = tree.prove(leaf_index)
                path = merkle_proof.path

                proof = prover.create_complete_payment_proof(
                    commitment=commitment,
                    commitment_secret=coin.spend_key,
                    merkle_path=path,
                    leaf_index=leaf_index,
                    merkle_root=root,
                    input_amount=1000,
                    output_amount=1000,
                    spend_key=coin.spend_key,
                    randomness=coin.randomness,
                )

                # Verification
                is_valid = verifier.verify_payment_proof(
                    proof=proof,
                    merkle_root=root,
                    nullifier=proof.nullifier,
                    path_length=32,
                )

                # Record nullifier
                nullifier_set.register(proof.nullifier, transaction_hash=f"tx_{_}")

        stats = benchmark.report()
        return stats


if __name__ == "__main__":
    # Run benchmarks manually
    pytest.main([__file__, "-v", "-m", "benchmark", "-s"])
