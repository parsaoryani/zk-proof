#!/usr/bin/env python3
"""
Quick start guide for the ZK-Mixer system.

Run this to see a complete workflow example.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from zkm.core.mixer import ZKMixer
from zkm.core.zkproof import ZKProofSystem


def main():
    """Run a simple example of the ZK-Mixer system."""
    
    print("=" * 70)
    print("ZK-MIXER QUICK START EXAMPLE")
    print("=" * 70)
    print()
    
    # Step 1: Initialize the mixer
    print("Step 1: Initialize the ZK-Mixer")
    print("-" * 70)
    mixer = ZKMixer(merkle_tree_height=8)
    print("✓ Mixer created with 8-level Merkle tree (supports 256 deposits)")
    print()
    
    # Step 2: Alice deposits
    print("Step 2: Alice deposits $1000 (private)")
    print("-" * 70)
    alice_receipt = mixer.deposit("alice@example.com", 1000)
    print(f"✓ Deposit created")
    print(f"  Deposit Hash: {alice_receipt.deposit_hash}")
    print(f"  Commitment: {alice_receipt.commitment.hex()[:32]}...")
    print(f"  Tree Index: {alice_receipt.commitment_index}")
    print()
    
    # Step 3: Bob deposits
    print("Step 3: Bob deposits $500 (private)")
    print("-" * 70)
    bob_receipt = mixer.deposit("bob@example.com", 500)
    print(f"✓ Deposit created")
    print(f"  Deposit Hash: {bob_receipt.deposit_hash}")
    print()
    
    # Step 4: Alice withdraws anonymously
    print("Step 4: Alice withdraws $1000 anonymously")
    print("-" * 70)
    
    # Get Alice's secret and randomness
    alice_data = mixer.deposits[alice_receipt.commitment_index]
    alice_secret = bytes.fromhex(alice_data["secret"])
    alice_randomness = bytes.fromhex(alice_data["randomness"])
    
    # Generate proof
    alice_merkle_path = mixer.merkle_tree.get_path(alice_receipt.commitment_index)
    alice_proof = ZKProofSystem.generate_withdrawal_proof(
        secret=alice_secret,
        randomness=alice_randomness,
        merkle_path=alice_merkle_path,
        leaf_index=alice_receipt.commitment_index,
        auditor_pk=mixer.auditor.public_key,
        identity="alice@example.com"
    )
    
    # Withdraw
    alice_withdrawal = mixer.withdraw(alice_proof)
    print(f"✓ Withdrawal successful!")
    print(f"  Withdrawal Hash: {alice_withdrawal.transaction_hash}")
    print(f"  Status: {alice_withdrawal.status}")
    print()
    
    # Step 5: Auditor checks transaction
    print("Step 5: Regulatory Auditor reviews deposit")
    print("-" * 70)
    audit_result = mixer.audit_transaction(
        transaction_hash=alice_receipt.deposit_hash,
        auditor_private_key=mixer.auditor.private_key
    )
    print(f"✓ Audit completed")
    print(f"  Identity: {audit_result.decrypted_identity}")
    print(f"  Timestamp: {audit_result.audit_timestamp}")
    print()
    
    # Step 6: System status
    print("Step 6: System Status")
    print("-" * 70)
    stats = mixer.get_statistics()
    print(f"✓ Mixer Statistics:")
    print(f"  Total Deposits: {stats['total_deposits']}")
    print(f"  Total Withdrawals: {stats['total_withdrawals']}")
    print(f"  Total Value Mixed: ${stats['total_volume']}")
    print(f"  Double-Spend Prevention: {stats['num_nullifiers']} nullifiers used")
    print(f"  Audited Transactions: {stats['audited_transactions']}")
    print()
    
    print("=" * 70)
    print("✓ QUICK START COMPLETE")
    print("=" * 70)
    print()
    print("Key Features Demonstrated:")
    print("  1. Privacy: Alice's identity was hidden during withdrawal")
    print("  2. Security: Double-spending prevented by nullifiers")
    print("  3. Compliance: Auditor could decrypt specific transactions")
    print("  4. Scalability: Merkle tree provides O(log n) proofs")
    print()
    print("For more details, run:")
    print("  python examples/complete_demo.py")
    print()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
