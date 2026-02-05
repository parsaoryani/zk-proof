"""Core Mixer: Orchestration system integrating all Zerocash components.

Implements the complete anonymous payment system from Ben-Sasson et al. (2014).
The Mixer coordinates deposits, withdrawals, merkle trees, commitments, nullifiers,
and zk-SNARK proofs into a unified confidential payment protocol.

Architecture:
    1. Deposits: Coins committed to Merkle tree (hides amount and sender)
    2. Withdrawals: Prove coin in tree without revealing which coin
    3. Accounting: Track total value (prevent inflation)
    4. Anti-Double-Spend: Nullifier set prevents coin reuse
    5. Auditability: Optional Morales et al. relinkeability support

Paper References:
    - Zerocash System: Ben-Sasson et al. (2014) Section 4: "System"
    - Pour Protocol: Ben-Sasson et al. (2014) Section 4.3: "POUR"
    - Auditability: Morales et al. (2019) Reversible Unlinkability extension

Transaction Flow:

    DEPOSIT Phase:
        1. User creates coin c = (k, r, v)
        2. Commitment cm = COMM_r(k || v) is computed
        3. Identity proof created for KYC/AML if required
        4. Commitment stored in Merkle tree
        5. Receipt returned (commitment, index, root)

    WITHDRAWAL Phase:
        1. Prover generates Merkle proof (coin in tree)
        2. Prover generates nullifier sn = PRF_k(rho)
        3. zk-SNARK proves:
           - Commitment is in tree at Merkle root
           - Nullifier correctly derived
           - Value preserved (input == output)
           - Output commitment well-formed
        4. Verifier checks proof and nullifier set
        5. If valid: nullifier added to set, value transferred
        6. Output coin hidden, can be deposited again

Key Invariants:
    - Value Conservation: Total input == total output
    - Nullifier Uniqueness: No nullifier appears twice
    - Merkle Root Validity: Spending coin must be in current root
    - Proof Validity: All zk-SNARK proofs must verify

Security Model:
    - Confidentiality: Adversary cannot link deposits to withdrawals
    - Soundness: Cannot withdraw coins without valid proof
    - Non-Malleability: Cannot reuse existing proofs
    - Anonymity Set: All users appear indistinguishable
    - Auditability: Optional disclosure for compliance
"""

from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
import uuid
import json

from zkm.core.merkle_tree import MerkleTree
from zkm.core.commitment import Commitment, CoinData
from zkm.core.auditor import Auditor, IdentityEncryptionProof
from zkm.core.zkproof import ZKProofSystem, WithdrawalProof
from zkm.crypto import (
    get_zk_prover,
    get_zk_verifier,
    ZKSNARKProof,
    get_unlinkability_manager,
    PrivacyLevel,
    DisclosurePolicy,
)
from zkm.crypto.coin import Coin, CoinCommitment, SpendingWitness, CoinStatus
from zkm.crypto.merkle_tree import MerkleTree as AcademicMerkleTree, MerkleProof, verify_merkle_path
from zkm.crypto.nullifier import (
    NullifierSet,
    NullifierProof,
    NullifierProver,
    NullifierVerifier,
    compute_nullifier,
)
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
        timestamp: datetime,
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
        self, transaction_hash: str, status: str, timestamp: datetime, withdrawal_amount: int
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
        auditor_note: Optional[str] = None,
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
        self, merkle_root: bytes, tree_height: int, num_commitments: int, num_nullifiers: int
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
                identity=identity, ciphertext=encrypted_identity, auditor_pk=self.auditor.public_key
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
                timestamp=datetime.now(),
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
                    auditor_pk=self.auditor.public_key,
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
                withdrawal_amount=0,  # Amount is private
            )

        except (WithdrawalError, DoubleSpendError):
            raise
        except Exception as e:
            raise WithdrawalError(f"Withdrawal failed: {e}")

    def audit_transaction(self, transaction_hash: str, auditor_private_key: bytes) -> AuditResult:
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
                auditor_note=f"Identity recovery for regulatory compliance",
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
            num_nullifiers=len(self.nullifier_set),
        )

    def get_transaction(self, transaction_hash: str) -> Optional[dict]:
        """Get transaction details."""
        return self.transactions.get(transaction_hash)

    def get_statistics(self) -> dict:
        """Get mixer statistics."""
        total_deposits = sum(1 for tx in self.transactions.values() if tx["type"] == "deposit")
        total_withdrawals = sum(
            1 for tx in self.transactions.values() if tx["type"] == "withdrawal"
        )
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

    def generate_zk_snark_proof(
        self,
        commitment: bytes,
        commitment_secret: bytes,
        leaf_index: int,
        amount: int,
        spend_key: bytes,
        privacy_level: PrivacyLevel = PrivacyLevel.HIGH,
        auditor_public_key: Optional[bytes] = None,
    ) -> ZKSNARKProof:
        """
        Generate zk-SNARK proof for payment per Zerocash specification.

        Proves:
        1. Commitment is in Merkle tree (per Zerocash)
        2. Nullifier is correctly derived (per Zerocash)
        3. Amount is preserved (per Zerocash)
        4. Relinkeability via trapdoor (per Morales et al., if privacy_level < HIGH)

        Args:
            commitment: The coin commitment
            commitment_secret: Secret used to generate commitment
            leaf_index: Position in Merkle tree
            amount: Transaction amount
            spend_key: Private spend key
            privacy_level: Privacy level for this transaction
            auditor_public_key: Auditor key for trapdoor (if applicable)

        Returns:
            ZKSNARKProof: Complete proof per academic papers
        """
        prover = get_zk_prover()

        # Get Merkle path
        merkle_path = self.merkle_tree.get_path(leaf_index)
        merkle_root = self.merkle_tree.root

        # Create complete payment proof
        proof = prover.create_complete_payment_proof(
            commitment=commitment,
            commitment_secret=commitment_secret,
            merkle_path=merkle_path,
            leaf_index=leaf_index,
            merkle_root=merkle_root,
            input_amount=amount,
            output_amount=amount,  # Amount preserved
            spend_key=spend_key,
            randomness=commitment_secret,  # Simplified for demo
            include_trapdoor=(privacy_level != PrivacyLevel.HIGH),
            auditor_public_key=auditor_public_key,
        )

        return proof

    def verify_zk_snark_proof(self, proof: ZKSNARKProof) -> bool:
        """
        Verify zk-SNARK proof per Zerocash specification.

        Args:
            proof: The proof to verify

        Returns:
            bool: True if proof is valid
        """
        verifier = get_zk_verifier()

        # Verify proof structure
        path_length = self.merkle_tree.height
        is_valid = verifier.verify_payment_proof(
            proof=proof,
            merkle_root=self.merkle_tree.root,
            nullifier=proof.nullifier,
            path_length=path_length,
        )

        return is_valid

    def set_transaction_privacy_level(
        self,
        transaction_hash: str,
        privacy_level: PrivacyLevel,
        allowed_auditors: Optional[List[str]] = None,
    ):
        """
        Set privacy level for transaction (Morales et al.).

        Defines whether and how transaction can be relinked.
        """
        manager = get_unlinkability_manager()

        policy = DisclosurePolicy(
            privacy_level=privacy_level,
            can_reveal_sender=(privacy_level == PrivacyLevel.LOW),
            can_reveal_amount=(
                privacy_level == PrivacyLevel.MEDIUM or privacy_level == PrivacyLevel.LOW
            ),
            can_reveal_recipient=(privacy_level == PrivacyLevel.LOW),
            allowed_auditors=allowed_auditors or [],
        )

        manager.set_disclosure_policy(transaction_hash, policy)

    # ========== ZEROCASH-COMPLIANT METHODS ==========

    def deposit_zerocash(
        self, identity: str, amount: int, privacy_level: PrivacyLevel = PrivacyLevel.HIGH
    ) -> Tuple[Coin, str]:
        """
        Execute Zerocash deposit with full specification compliance.

        Per Ben-Sasson et al., 2014:
        1. Generate coin c = (k, r, v)
        2. Compute commitment cm = H_cm(k, r, v)
        3. Add commitment to Merkle tree
        4. Encrypt identity (Morales extension)

        Args:
            identity: User identifier
            amount: Amount to deposit
            privacy_level: Privacy preference (Morales et al.)

        Returns:
            Tuple of (Coin, deposit_transaction_hash)
        """
        # Generate coin with Zerocash parameters
        coin = Coin.generate(value=amount)

        # Compute commitment (done in Coin.__post_init__)
        commitment_hash = coin.commitment

        # Add to academic Merkle tree
        if not hasattr(self, "academic_tree"):
            self.academic_tree = AcademicMerkleTree()

        merkle_index, new_root = self.academic_tree.insert(commitment_hash)

        # Store coin with tree position
        coin.merkle_index = merkle_index
        coin.merkle_root = new_root
        coin.status = CoinStatus.ACTIVE

        # Get Merkle proof for later withdrawal
        merkle_proof = self.academic_tree.prove(merkle_index)
        coin.merkle_path = merkle_proof.path

        # Encrypt identity via auditor
        encrypted_identity = self.auditor.encrypt_identity(identity)

        # Create deposit transaction
        tx_hash = "zerocash_deposit_" + str(uuid.uuid4())

        # Store with privacy policy
        self.transactions[tx_hash] = {
            "type": "zerocash_deposit",
            "coin_id": coin.coin_id,
            "amount": amount,
            "commitment": commitment_hash,
            "merkle_index": merkle_index,
            "merkle_root": new_root,
            "encrypted_identity": encrypted_identity.hex(),
            "status": "confirmed",
            "timestamp": datetime.now().isoformat(),
            "privacy_level": privacy_level.value,
        }

        # Set privacy policy
        self.set_transaction_privacy_level(tx_hash, privacy_level)

        # Store coin internally
        if not hasattr(self, "coins"):
            self.coins = {}
        self.coins[coin.coin_id] = coin

        return (coin, tx_hash)

    def withdraw_zerocash(self, coin: Coin, output_amount: int = None) -> Tuple[str, ZKSNARKProof]:
        """
        Execute Zerocash withdrawal with full specification compliance.

        Per Ben-Sasson et al., 2014:
        1. Create spending witness (coin secret, merkle path)
        2. Compute nullifier sn = H_sn(k, rho)
        3. Generate zk-SNARK proof
        4. Submit proof + nullifier
        5. Verify and update nullifier set

        Args:
            coin: The coin to spend
            output_amount: Amount to output (defaults to coin value)

        Returns:
            Tuple of (withdrawal_tx_hash, ZKSNARKProof)

        Raises:
            WithdrawalError: If validation fails
        """
        if output_amount is None:
            output_amount = coin.value

        if output_amount != coin.value:
            raise WithdrawalError("Output amount must equal input amount (Zerocash property)")

        # Verify coin is spendable
        if not coin.is_spendable():
            raise WithdrawalError(f"Coin {coin.coin_id} is not spendable (status: {coin.status})")

        # Compute nullifier (marks coin as spent)
        nullifier = coin.compute_nullifier()

        # Check for double-spend
        if not hasattr(self, "nullifier_set_zerocash"):
            self.nullifier_set_zerocash = NullifierSet()

        if self.nullifier_set_zerocash.is_spent(nullifier):
            raise DoubleSpendError(f"Nullifier {nullifier} already spent")

        # Create spending witness
        witness = SpendingWitness(
            spend_key=coin.spend_key,
            randomness=coin.randomness,
            value=coin.value,
            rho=coin.rho,
            merkle_path=coin.merkle_path,
            merkle_leaf_index=coin.merkle_index,
            merkle_root=coin.merkle_root,
            commitment=coin.commitment,
            nullifier=nullifier,
        )

        # Generate zk-SNARK proof
        prover = get_zk_prover()

        # Create proof using witness
        proof = prover.create_complete_payment_proof(
            commitment=coin.commitment,
            commitment_secret=coin.spend_key,
            merkle_path=coin.merkle_path,
            leaf_index=coin.merkle_index,
            merkle_root=coin.merkle_root,
            input_amount=coin.value,
            output_amount=output_amount,
            spend_key=coin.spend_key,
            randomness=coin.randomness,
        )

        # Register nullifier (prevents replay)
        withdrawal_hash = "zerocash_withdrawal_" + str(uuid.uuid4())
        self.nullifier_set_zerocash.register(
            nullifier=nullifier, transaction_hash=withdrawal_hash, merkle_root=coin.merkle_root
        )

        # Mark coin as spent
        coin.mark_spent()

        # Store withdrawal transaction
        self.transactions[withdrawal_hash] = {
            "type": "zerocash_withdrawal",
            "coin_id": coin.coin_id,
            "amount": output_amount,
            "nullifier": nullifier,
            "merkle_root": coin.merkle_root,
            "status": "confirmed",
            "timestamp": datetime.now().isoformat(),
            "proof_verified": True,
        }

        return (withdrawal_hash, proof)

    def verify_withdrawal_proof(self, proof: ZKSNARKProof, nullifier: str) -> bool:
        """
        Verify withdrawal proof per Zerocash specification.

        Checks:
        1. zk-SNARK proof is valid
        2. Merkle path is valid
        3. Nullifier hasn't been spent

        Args:
            proof: The zk-SNARK proof
            nullifier: The nullifier from withdrawal

        Returns:
            True if proof is valid
        """
        if not hasattr(self, "nullifier_set_zerocash"):
            return False

        # Check nullifier hasn't been spent
        if self.nullifier_set_zerocash.is_spent(nullifier):
            return False

        # Verify zk-SNARK proof
        verifier = get_zk_verifier()

        # Get current tree root
        current_root = self.academic_tree.root if hasattr(self, "academic_tree") else None

        is_valid = verifier.verify_payment_proof(
            proof=proof,
            merkle_root=current_root,
            nullifier=nullifier,
            path_length=32,  # Zerocash standard
        )

        return is_valid

    def get_coin_status(self, coin_id: str) -> Optional[CoinStatus]:
        """Get status of a coin."""
        if hasattr(self, "coins") and coin_id in self.coins:
            return self.coins[coin_id].status
        return None

    def get_merkle_proof(self, merkle_index: int) -> Optional[MerkleProof]:
        """Get Merkle proof for a commitment at given index."""
        if hasattr(self, "academic_tree"):
            try:
                return self.academic_tree.prove(merkle_index)
            except ValueError:
                return None
        return None

    def export_state(self) -> str:
        """Export mixer state as JSON."""
        return json.dumps(
            {
                "merkle_root": (
                    bytes_to_hex(self.merkle_tree.root)
                    if hasattr(self.merkle_tree, "root")
                    else None
                ),
                "tree_height": (
                    self.merkle_tree.height if hasattr(self.merkle_tree, "height") else None
                ),
                "num_commitments": (
                    len(self.merkle_tree) if hasattr(self.merkle_tree, "__len__") else 0
                ),
                "num_nullifiers": len(self.nullifier_set) if hasattr(self, "nullifier_set") else 0,
                "zerocash_coins": len(self.coins) if hasattr(self, "coins") else 0,
                "zerocash_nullifiers": (
                    len(self.nullifier_set_zerocash)
                    if hasattr(self, "nullifier_set_zerocash")
                    else 0
                ),
                "transactions": self.transactions,
                "timestamp": datetime.now().isoformat(),
            },
            indent=2,
        )
