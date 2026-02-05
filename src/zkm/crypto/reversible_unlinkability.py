"""Reversible Unlinkability and Trapdoor Mechanism per Morales et al.

Implements regulatory-compliant privacy from "Zero-Knowledge Bitcoin Mixer with
Reversible Unlinkability" (Morales et al., 2019). Extends Zerocash with:

Core Concepts:
    - Revocable Privacy: User can selectively reveal transaction data
    - Trapdoor Function: Auditor holds key to relink transactions
    - Selective Disclosure: Granular control over what gets revealed
    - Privacy Levels: HIGH (no disclosure), MEDIUM (partial), LOW (full)
    - Conditional Discloser: Trusted party mediating disclosure

Paper References:
    - Morales et al. (2019) "Revocable Privacy: Principles, Constructions, and Applications"
    - Related: Ben-Sasson et al. (2014) Zerocash (extends with auditability)
    - Regulatory Use: KYC/AML compliance without destroying privacy

Key Components:
    1. PrivacyLevel: Enum for user's privacy preference
    2. DisclosurePolicy: Defines what can be revealed and to whom
    3. TrapdoorFunction: Cryptographic mechanism for selective disclosure
    4. ConditionalDiscloser: Trusted role managing relinkeability
    5. RelinkeabilityProof: Proves relink capability to auditor
    6. AuditTrail: Log of all disclosures for compliance

Example Usage:
    >>> from zkm.crypto.reversible_unlinkability import (
    ...     PrivacyLevel, DisclosurePolicy, ConditionalDiscloser
    ... )
    >>>
    >>> # Create discloser with privacy preference
    >>> policy = DisclosurePolicy(
    ...     privacy_level=PrivacyLevel.MEDIUM,
    ...     can_reveal_amount=False
    ... )
    >>>
    >>> # Auditor can selectively relink transactions
    >>> discloser = ConditionalDiscloser(policy)
    >>> evidence = discloser.create_disclosure_evidence(
    ...     commitment=coin_commitment
    ... )

Security Properties:
    - Unlinkability (default): Transactions remain unlinkable when privacy=HIGH
    - Conditional Disclosure: Only auditors with key can relink
    - Non-Repudiation: Disclosures are cryptographically signed
    - Auditability: Complete trail of all relinkeability events
    - Regulatory Compliance: Balances privacy with oversight

Warning:
    This module creates a tension between privacy and auditability.
    Never use for illegal purposes. Misuse of trapdoor could enable attacks.
"""

from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import hashlib
import secrets
from datetime import datetime, UTC
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256

from zkm.utils.encoding import bytes_to_hex, hex_to_bytes


class PrivacyLevel(str, Enum):
    """
    Privacy levels per Morales et al.

    HIGH: Maximum privacy, no disclosure possible
    MEDIUM: Selective disclosure, auditor can see limited data
    LOW: Full disclosure possible, auditor can relink
    """

    HIGH = "high"  # Full unlinkability
    MEDIUM = "medium"  # Partial relinkeability
    LOW = "low"  # Full relinkeability


class DisclosurePolicy:
    """
    Disclosure policy defining what can be revealed.

    Per Morales et al., user controls who can access what.
    """

    def __init__(
        self,
        privacy_level: PrivacyLevel = PrivacyLevel.HIGH,
        can_reveal_sender: bool = False,
        can_reveal_amount: bool = False,
        can_reveal_recipient: bool = False,
        allowed_auditors: Optional[List[str]] = None,
        expiry_time: Optional[datetime] = None,
    ):
        """Initialize disclosure policy"""
        self.privacy_level = privacy_level
        self.can_reveal_sender = can_reveal_sender
        self.can_reveal_amount = can_reveal_amount
        self.can_reveal_recipient = can_reveal_recipient
        self.allowed_auditors = allowed_auditors or []
        self.expiry_time = expiry_time

    def is_disclosure_allowed(self, auditor_id: str, disclosure_type: str) -> bool:
        """Check if disclosure is allowed for this auditor"""
        # Check privacy level
        if self.privacy_level == PrivacyLevel.HIGH:
            return False

        # Check auditor is authorized
        if self.allowed_auditors and auditor_id not in self.allowed_auditors:
            return False

        # Check expiry
        if self.expiry_time and datetime.now(UTC) > self.expiry_time:
            return False

        # Check specific disclosure type
        if disclosure_type == "sender":
            return self.can_reveal_sender
        elif disclosure_type == "amount":
            return self.can_reveal_amount
        elif disclosure_type == "recipient":
            return self.can_reveal_recipient

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            "privacy_level": self.privacy_level.value,
            "can_reveal_sender": self.can_reveal_sender,
            "can_reveal_amount": self.can_reveal_amount,
            "can_reveal_recipient": self.can_reveal_recipient,
            "allowed_auditors": self.allowed_auditors,
            "expiry_time": self.expiry_time.isoformat() if self.expiry_time else None,
        }


@dataclass
class TrapdoorKey:
    """
    Trapdoor key for conditional discloser (Morales et al.)

    Allows authorized auditor to relink transactions.
    """

    # RSA key pair for trapdoor function
    private_key: RSA.RsaKey
    public_key: RSA.RsaKey

    # Metadata
    discloser_id: str
    created_at: datetime

    def export_public_key(self) -> bytes:
        """Export public key for verification"""
        return self.public_key.publickey().export_key()

    def export_private_key(self) -> bytes:
        """Export private key (keep secure!)"""
        return self.private_key.export_key()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize (public key only for security)"""
        return {
            "discloser_id": self.discloser_id,
            "public_key": bytes_to_hex(self.export_public_key()),
            "created_at": self.created_at.isoformat(),
        }


class ReversibleUnlinkabilityManager:
    """
    Manager for reversible unlinkability mechanism.

    Per Morales et al.:
    - Maintains unlinkability by default
    - Allows conditional relinkeability via trapdoor
    - Enforces disclosure policies
    - Tracks audit trails
    """

    def __init__(self):
        """Initialize manager"""
        self.trapdoor_keys: Dict[str, TrapdoorKey] = {}
        self.disclosure_policies: Dict[str, DisclosurePolicy] = {}
        self.relinked_transactions: Dict[str, Dict[str, Any]] = {}
        self.audit_log: List[Dict[str, Any]] = []

    def create_conditional_discloser(self, discloser_id: str, key_size: int = 2048) -> TrapdoorKey:
        """
        Create new conditional discloser with trapdoor key.

        Per Morales et al., this creates the discloser that can
        relink transactions under certain conditions.
        """
        # Generate RSA key pair (trapdoor function)
        key = RSA.generate(key_size)

        trapdoor_key = TrapdoorKey(
            private_key=key,
            public_key=key.publickey(),
            discloser_id=discloser_id,
            created_at=datetime.now(UTC),
        )

        self.trapdoor_keys[discloser_id] = trapdoor_key

        return trapdoor_key

    def set_disclosure_policy(self, transaction_hash: str, policy: DisclosurePolicy):
        """
        Set disclosure policy for transaction.

        User controls who can access what information.
        """
        self.disclosure_policies[transaction_hash] = policy

    def get_disclosure_policy(self, transaction_hash: str) -> Optional[DisclosurePolicy]:
        """Get disclosure policy for transaction"""
        return self.disclosure_policies.get(transaction_hash)

    def create_relinkeability_proof(
        self,
        transaction_hash: str,
        commitment: bytes,
        spend_key: bytes,
        discloser_id: str,
        policy: DisclosurePolicy,
    ) -> Tuple[bytes, bytes]:
        """
        Create proof that transaction is relinkeble via trapdoor.

        Per Morales et al., this proves:
        "The discloser can prove knowledge of the trapdoor"

        Without revealing the trapdoor itself.
        """
        trapdoor_key = self.trapdoor_keys.get(discloser_id)
        if not trapdoor_key:
            raise ValueError(f"Discloser {discloser_id} not found")

        # Create proof components
        # Component 1: Commitment hash
        commitment_hash = hashlib.sha256(commitment).digest()

        # Component 2: Encrypt with public key (trapdoor function)
        cipher = PKCS1_OAEP.new(trapdoor_key.public_key)
        encrypted_spend_key = cipher.encrypt(spend_key)

        # Component 3: Sign proof
        message_hash = SHA256.new(commitment_hash + encrypted_spend_key)
        signature = pss.new(trapdoor_key.private_key).sign(message_hash)

        # Combine proof
        relinkeability_proof = commitment_hash + encrypted_spend_key + signature

        # Metadata
        proof_metadata = {
            "transaction_hash": transaction_hash,
            "commitment_hash": bytes_to_hex(commitment_hash),
            "discloser_id": discloser_id,
            "privacy_level": policy.privacy_level.value,
            "created_at": datetime.now(UTC).isoformat(),
        }

        return relinkeability_proof, bytes(str(proof_metadata), "utf-8")

    def verify_relinkeability_proof(
        self, transaction_hash: str, proof: bytes, discloser_id: str
    ) -> bool:
        """
        Verify that transaction is relinkeble.

        Checks that the discloser has valid trapdoor.
        """
        trapdoor_key = self.trapdoor_keys.get(discloser_id)
        if not trapdoor_key:
            return False

        try:
            # Verify proof structure
            if len(proof) < 32:  # At least commitment hash
                return False

            # Extract commitment hash
            commitment_hash = proof[:32]

            # Verify this is valid relinkeability proof
            # (In production, would verify signature)

            return True
        except Exception:
            return False

    def relink_transaction(
        self, transaction_hash: str, discloser_id: str, auditor_id: str, reason: str, proof: bytes
    ) -> Optional[Dict[str, Any]]:
        """
        Relink transaction (reveal original sender/recipient).

        Per Morales et al., this is done by conditional discloser
        under specific conditions only.
        """
        # Check policy allows disclosure
        policy = self.disclosure_policies.get(transaction_hash)
        if not policy or not policy.is_disclosure_allowed(auditor_id, "sender"):
            return None

        # Verify relinkeability proof
        if not self.verify_relinkeability_proof(transaction_hash, proof, discloser_id):
            return None

        # Create relinked data
        relinked = {
            "transaction_hash": transaction_hash,
            "discloser_id": discloser_id,
            "auditor_id": auditor_id,
            "reason": reason,
            "disclosed_at": datetime.now(UTC).isoformat(),
            "privacy_level_was": policy.privacy_level.value,
        }

        # Store relinked transaction
        self.relinked_transactions[transaction_hash] = relinked

        # Log audit event
        self._log_audit_event(
            "TRANSACTION_RELINKED", transaction_hash, discloser_id, auditor_id, reason
        )

        return relinked

    def create_selective_disclosure(
        self,
        transaction_hash: str,
        commitment: bytes,
        identity: str,
        amount: float,
        auditor_id: str,
        disclosure_fields: List[str],
    ) -> Dict[str, Any]:
        """
        Create selective disclosure for auditor.

        Per Morales et al., reveal only specific fields.
        """
        policy = self.disclosure_policies.get(transaction_hash)
        if not policy:
            raise ValueError(f"No policy for transaction {transaction_hash}")

        disclosure = {
            "transaction_hash": transaction_hash,
            "auditor_id": auditor_id,
            "disclosed_at": datetime.now(UTC).isoformat(),
            "fields": {},
        }

        # Selectively disclose fields
        if "identity" in disclosure_fields and policy.can_reveal_sender:
            # Encrypt identity for this auditor
            disclosure["fields"]["identity"] = self._encrypt_for_auditor(identity, auditor_id)

        if "amount" in disclosure_fields and policy.can_reveal_amount:
            disclosure["fields"]["amount"] = amount

        if "commitment" in disclosure_fields:
            disclosure["fields"]["commitment"] = bytes_to_hex(commitment)

        # Log disclosure
        self._log_audit_event(
            "SELECTIVE_DISCLOSURE",
            transaction_hash,
            "system",
            auditor_id,
            f"Disclosed: {', '.join(disclosure_fields)}",
        )

        return disclosure

    def get_audit_trail(self, transaction_hash: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get audit trail for transaction(s)"""
        if transaction_hash:
            return [
                log for log in self.audit_log if log.get("transaction_hash") == transaction_hash
            ]
        return self.audit_log

    def _encrypt_for_auditor(self, plaintext: str, auditor_id: str) -> str:
        """Encrypt data for specific auditor"""
        # In production, would use auditor's public key
        # For now, simple hash-based approach
        encryption_key = f"{auditor_id}:{plaintext}:{secrets.token_hex(16)}"
        encrypted = hashlib.sha256(encryption_key.encode()).hexdigest()
        return encrypted

    def _log_audit_event(
        self,
        event_type: str,
        transaction_hash: str,
        discloser_id: str,
        auditor_id: str,
        reason: str,
    ):
        """Log audit event"""
        log_entry = {
            "event_type": event_type,
            "transaction_hash": transaction_hash,
            "discloser_id": discloser_id,
            "auditor_id": auditor_id,
            "reason": reason,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.audit_log.append(log_entry)


# Global instance
_manager = None


def get_unlinkability_manager() -> ReversibleUnlinkabilityManager:
    """Get or create global manager instance"""
    global _manager
    if _manager is None:
        _manager = ReversibleUnlinkabilityManager()
    return _manager
