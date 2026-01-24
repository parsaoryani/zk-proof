"""Core Mixer orchestration system integrating all components."""

from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
import uuid
import json

from zkm.core.merkle_tree import MerkleTree
from zkm.core.commitment import Commitment, CoinData
from zkm.core.auditor import Auditor, IdentityEncryptionProof
from zkm.core.zkproof import ZKProofSystem, WithdrawalProof
from zkm.utils.hash import sha256
from zkm.utils.encoding import bytes_to_hex, hex_to_bytes
from zkm.exceptions import (
    DepositError,
    WithdrawalError,
    AuditError,
    DoubleSpendError,
    InvalidProofError,
)


class DepositReceipt:
    """Receipt for a successful deposit."""
    
    def __init__(
        self,
        commitment: bytes,
        commitment_index: int,
        merkle_root: bytes,
        encrypted_identity_proof: bytes,
        deposit_hash: str,
        timestamp: datetime
    ):
        self.commitment = commitment
        self.commitment_index = commitment_index
        self.merkle_root = merkle_root
        self.encrypted_identity_proof = encrypted_identity_proof
        self.deposit_hash = deposit_hash
        self.timestamp = timestamp
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "commitment": bytes_to_hex(self.commitment),
            "commitment_index": self.commitment_index,
            "merkle_root": bytes_to_hex(self.merkle_root),
            "encrypted_identity_proof": bytes_to_hex(self.encrypted_identity_proof),
            "deposit_hash": self.deposit_hash,
            "timestamp": self.timestamp.isoformat(),
        }


class WithdrawalReceipt:
    """Receipt for a successful withdrawal."""
    
    def __init__(
        self,
        transaction_hash: str,
        status: str,
        timestamp: datetime,
        withdrawal_amount: int
    ):
        self.transaction_hash = transaction_hash
        self.status = status
        self.timestamp = timestamp
        self.withdrawal_amount = withdrawal_amount
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "transaction_hash": self.transaction_hash,
            "status": self.status,
            "timestamp": self.timestamp.isoformat(),
            "withdrawal_amount": self.withdrawal_amount,
        }


class AuditResult:
    """Result of an audit operation."""
    
    def __init__(
        self,
        transaction_hash: str,
        decrypted_identity: str,
        audit_timestamp: datetime,
        auditor_note: Optional[str] = None
    ):
        self.transaction_hash = transaction_hash
        self.decrypted_identity = decrypted_identity
        self.audit_timestamp = audit_timestamp
        self.auditor_note = auditor_note
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "transaction_hash": self.transaction_hash,
            "decrypted_identity": self.decrypted_identity,
            "audit_timestamp": self.audit_timestamp.isoformat(),
            "auditor_note": self.auditor_note,
        }


class MixerState:
    """State of the mixer."""
    
    def __init__(
        self,
        merkle_root: bytes,
        tree_height: int,
        num_commitments: int,
        num_nullifiers: int
    ):
        self.merkle_root = merkle_root
        self.tree_height = tree_height
        self.num_commitments = num_commitments
        self.num_nullifiers = num_nullifiers
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "merkle_root": bytes_to_hex(self.merkle_root),
            "tree_height": self.tree_height,
            "num_commitments": self.num_commitments,
            "num_nullifiers": self.num_nullifiers,
        }


class ZKMixer:
    """
    Main ZK-Mixer orchestration system.
    
    Combines all cryptographic modules (Zerocash + Morales) into a complete
    privacy-preserving mixer with regulatory compliance capabilities.
    
    Paper References:
    - Zerocash: Ben-Sasson et al. (2014)
    - Morales et al.: Morales-Sandoval & Ferrer-Gómez (2021)
    """
    
    def __init__(self, merkle_tree_height: int = 32):
        """
        Initialize mixer with empty state.
        
        Args:
            merkle_tree_height: Height of Merkle tree (default 32)
        """
        self.merkle_tree = MerkleTree(tree_height=merkle_tree_height)
        self.auditor = Auditor()
        self.nullifier_set: Set[bytes] = set()
        
        # Track transactions
        self.transactions: Dict[str, dict] = {}
        self.deposits: Dict[int, dict] = {}  # leaf_index -> deposit info
        self.withdrawals: Dict[str, dict] = {}  # nullifier_hex -> withdrawal info
        self.audit_records: Dict[str, dict] = {}  # transaction_hash -> audit info
        
        # Statistics
        self.total_volume = 0
        self.start_time = datetime.now()
    
    def deposit(self, identity: str, amount: int) -> DepositReceipt:
        """
        Execute deposit transaction.
        
        Steps:
        1. Generate secret and randomness (Zerocash)
        2. Compute commitment C = H(s || r)
        3. Encrypt identity with auditor key (Morales)
        4. Add commitment to Merkle tree
        5. Create audit record
        6. Return commitment + encrypted proof
        
        Args:
            identity: User's address or ID
            amount: Amount to deposit
            
        Returns:
            DepositReceipt: Commitment, index, and proof
            
        Raises:
            DepositError: If deposit fails
        """
        try:
            # Generate coin
            coin = Commitment.create_coin(amount=amount)
            
            # Add commitment to tree
            leaf_index = self.merkle_tree.insert(coin.commitment)
            
            # Encrypt identity
            encrypted_identity = self.auditor.encrypt_identity(identity)
            
            # Generate identity proof
            identity_proof = IdentityEncryptionProof.generate_proof(
                identity=identity,
                ciphertext=encrypted_identity,
                auditor_pk=self.auditor.public_key
            )
            
            # Create transaction hash
            deposit_hash = "deposit_" + str(uuid.uuid4())
            
            # Store deposit info
            self.deposits[leaf_index] = {
                "identity": identity,
                "amount": amount,
                "commitment": coin.commitment.hex(),
                "secret": coin.secret.hex(),
                "randomness": coin.randomness.hex(),
                "nullifier": coin.nullifier.hex(),
                "encrypted_identity": encrypted_identity.hex(),
                "timestamp": datetime.now(),
                "deposit_hash": deposit_hash,
            }
            
            # Store transaction
            self.transactions[deposit_hash] = {
                "type": "deposit",
                "amount": amount,
                "identity": identity,
                "status": "confirmed",
                "timestamp": datetime.now(),
                "commitment_index": leaf_index,
            }
            
            self.total_volume += amount
            
            # Create receipt
            return DepositReceipt(
                commitment=coin.commitment,
                commitment_index=leaf_index,
                merkle_root=self.merkle_tree.root,
                encrypted_identity_proof=identity_proof,
                deposit_hash=deposit_hash,
                timestamp=datetime.now()
            )
        
        except Exception as e:
            raise DepositError(f"Deposit failed: {e}")
    
    def withdraw(self, proof: WithdrawalProof) -> WithdrawalReceipt:
        """
        Execute withdrawal transaction.
        
        Steps:
        1. Verify Merkle path contains commitment
        2. Check nullifier NOT in set (prevent double-spend)
        3. Verify ZK-proof validity
        4. Add nullifier to set
        5. Execute anonymous withdrawal
        
        Args:
            proof: User's withdrawal proof
            
        Returns:
            WithdrawalReceipt: Transaction hash and status
            
        Raises:
            WithdrawalError: If withdrawal fails
            DoubleSpendError: If nullifier already used
        """
        try:
            # Verify proof
            try:
                is_valid = ZKProofSystem.verify_withdrawal_proof(
                    proof=proof,
                    merkle_root=self.merkle_tree.root,
                    nullifier_set=self.nullifier_set,
                    auditor_pk=self.auditor.public_key
                )
            except DoubleSpendError as e:
                raise WithdrawalError(f"Double-spend detected: {e}")
            
            if not is_valid:
                raise WithdrawalError("Proof verification failed")
            
            # Add nullifier to set
            self.nullifier_set.add(proof.nullifier)
            
            # Create transaction hash
            withdrawal_hash = "withdrawal_" + str(uuid.uuid4())
            
            # Store withdrawal info
            nullifier_hex = proof.nullifier.hex()
            self.withdrawals[nullifier_hex] = {
                "status": "confirmed",
                "timestamp": datetime.now(),
                "withdrawal_hash": withdrawal_hash,
                "proof_hash": proof.proof_hash.hex(),
            }
            
            # Store transaction
            self.transactions[withdrawal_hash] = {
                "type": "withdrawal",
                "status": "confirmed",
                "timestamp": datetime.now(),
                "nullifier": nullifier_hex,
            }
            
            # Return receipt
            return WithdrawalReceipt(
                transaction_hash=withdrawal_hash,
                status="success",
                timestamp=datetime.now(),
                withdrawal_amount=0  # Amount is private
            )
        
        except (WithdrawalError, DoubleSpendError):
            raise
        except Exception as e:
            raise WithdrawalError(f"Withdrawal failed: {e}")
    
    def audit_transaction(
        self,
        transaction_hash: str,
        auditor_private_key: bytes
    ) -> AuditResult:
        """
        Audit specific transaction to reveal identity.
        
        Steps:
        1. Retrieve transaction info
        2. Get encrypted identity
        3. Decrypt using private key
        4. Link identity to transaction
        5. Return audit result for compliance
        
        Args:
            transaction_hash: Transaction identifier
            auditor_private_key: Auditor's private key (PEM)
            
        Returns:
            AuditResult: Identity, timestamp, proof
            
        Raises:
            AuditError: If audit fails
        """
        try:
            # Find transaction
            if transaction_hash not in self.transactions:
                raise AuditError(f"Transaction not found: {transaction_hash}")
            
            tx = self.transactions[transaction_hash]
            
            if tx["type"] != "deposit":
                raise AuditError("Can only audit deposit transactions")
            
            # Find the encrypted identity
            deposit_info = None
            for leaf_idx, dep in self.deposits.items():
                if dep["deposit_hash"] == transaction_hash:
                    deposit_info = dep
                    break
            
            if not deposit_info:
                raise AuditError(f"Deposit info not found: {transaction_hash}")
            
            # Create auditor instance with provided key
            auditor = Auditor(private_key=auditor_private_key)
            
            # Decrypt identity
            encrypted_identity_bytes = bytes.fromhex(deposit_info["encrypted_identity"])
            decrypted_identity = auditor.decrypt_identity(encrypted_identity_bytes)
            
            # Store audit record
            audit_result = AuditResult(
                transaction_hash=transaction_hash,
                decrypted_identity=decrypted_identity,
                audit_timestamp=datetime.now(),
                auditor_note=f"Identity recovery for regulatory compliance"
            )
            
            self.audit_records[transaction_hash] = {
                "decrypted_identity": decrypted_identity,
                "audit_timestamp": datetime.now(),
                "auditor_note": audit_result.auditor_note,
            }
            
            # Update transaction status
            self.transactions[transaction_hash]["status"] = "audited"
            
            return audit_result
        
        except Exception as e:
            raise AuditError(f"Audit failed: {e}")
    
    def get_mixer_state(self) -> MixerState:
        """
        Return current mixer state for verification.
        
        Returns:
            MixerState: Merkle root, tree height, nullifier count, etc.
        """
        return MixerState(
            merkle_root=self.merkle_tree.root,
            tree_height=self.merkle_tree.height,
            num_commitments=len(self.merkle_tree),
            num_nullifiers=len(self.nullifier_set)
        )
    
    def get_transaction(self, transaction_hash: str) -> Optional[dict]:
        """Get transaction details."""
        return self.transactions.get(transaction_hash)
    
    def get_statistics(self) -> dict:
        """Get mixer statistics."""
        total_deposits = sum(1 for tx in self.transactions.values() if tx["type"] == "deposit")
        total_withdrawals = sum(1 for tx in self.transactions.values() if tx["type"] == "withdrawal")
        uptime = (datetime.now() - self.start_time).total_seconds() / 3600
        
        return {
            "total_deposits": total_deposits,
            "total_withdrawals": total_withdrawals,
            "total_volume": self.total_volume,
            "num_commitments": len(self.merkle_tree),
            "num_nullifiers": len(self.nullifier_set),
            "audited_transactions": len(self.audit_records),
            "uptime_hours": uptime,
            "merkle_root": bytes_to_hex(self.merkle_tree.root),
        }
    
    def export_state(self) -> str:
        """Export mixer state as JSON."""
        return json.dumps({
            "merkle_root": bytes_to_hex(self.merkle_tree.root),
            "tree_height": self.merkle_tree.height,
            "num_commitments": len(self.merkle_tree),
            "num_nullifiers": len(self.nullifier_set),
            "transactions": self.transactions,
            "timestamp": datetime.now().isoformat(),
        }, indent=2)
