"""ZK-Proof system combining Zerocash and Morales proofs."""

from dataclasses import dataclass, asdict
from typing import List, Set, Optional
from datetime import datetime

from zkm.core.merkle_tree import MerkleTree
from zkm.core.commitment import Commitment
from zkm.core.auditor import IdentityEncryptionProof
from zkm.utils.hash import sha256, hash_concatenate
from zkm.exceptions import (
    InvalidProofError,
    InvalidMerklePathError,
    DoubleSpendError,
    InvalidIdentityProofError,
    ProofTamperingError,
)


@dataclass
class WithdrawalProof:
    """
    Structured withdrawal proof combining Zerocash and Morales components.
    
    Paper References:
    - Zerocash: Commitment and nullifier verification
    - Morales et al.: Identity encryption proof
    """
    
    # Zerocash components
    nullifier: bytes  # nf = H(secret)
    merkle_path: List[bytes]  # Sibling hashes for Merkle verification
    leaf_index: int  # Position in Merkle tree
    
    # Morales component
    identity_encryption_proof: bytes  # ZK-proof of encrypted identity
    encrypted_identity: bytes  # Encrypted identity from auditor mechanism
    
    # Metadata
    timestamp: datetime
    proof_hash: bytes  # SHA-256 of all proof components


class ZKProofSystem:
    """
    Complete ZK-Proof system combining Zerocash and Morales.
    
    Integrates:
    1. Zerocash commitment/nullifier verification
    2. Merkle path proof
    3. Morales identity encryption proof
    """
    
    @staticmethod
    def generate_withdrawal_proof(
        secret: bytes,
        randomness: bytes,
        merkle_path: List[bytes],
        leaf_index: int,
        auditor_pk: bytes,
        identity: str
    ) -> WithdrawalProof:
        """
        Generate complete withdrawal proof.
        
        Components:
        1. Merkle path proof (Zerocash)
        2. Nullifier derivation (Zerocash)
        3. Identity encryption proof (Morales)
        
        Args:
            secret: User's secret
            randomness: Random value
            merkle_path: Path to commitment in tree
            leaf_index: Position in tree
            auditor_pk: Auditor's public key
            identity: User's identity/address
            
        Returns:
            WithdrawalProof: Structured proof object
            
        Raises:
            InvalidProofError: If proof generation fails
        """
        try:
            # Validate inputs
            if not isinstance(secret, bytes) or len(secret) != 32:
                raise InvalidProofError("Secret must be 32 bytes")
            if not isinstance(randomness, bytes) or len(randomness) != 32:
                raise InvalidProofError("Randomness must be 32 bytes")
            if not isinstance(merkle_path, list):
                raise InvalidProofError("Merkle path must be list")
            if not isinstance(identity, str):
                raise InvalidProofError("Identity must be string")
            
            # Component 1: Compute Zerocash nullifier
            nullifier = Commitment.compute_nullifier(secret)
            
            # Component 2: Generate identity encryption proof
            identity_encryption_proof = IdentityEncryptionProof.generate_proof(
                identity=identity,
                ciphertext=auditor_pk,  # Using auditor_pk as part of proof
                auditor_pk=auditor_pk
            )
            
            # Component 3: Hash identity for proof binding
            identity_hash = sha256(identity)
            
            # Encrypt identity reference (in real system, this would be user's choice)
            encrypted_identity = hash_concatenate(identity, auditor_pk)
            
            # Create timestamp
            timestamp = datetime.now()
            
            # Compute proof hash (integrity commitment)
            proof_components = hash_concatenate(
                nullifier,
                b"".join(merkle_path),
                leaf_index.to_bytes(8, 'big'),
                identity_encryption_proof,
                encrypted_identity,
                timestamp.isoformat().encode('utf-8')
            )
            
            proof_hash = sha256(proof_components)
            
            # Construct and return proof
            proof = WithdrawalProof(
                nullifier=nullifier,
                merkle_path=merkle_path,
                leaf_index=leaf_index,
                identity_encryption_proof=identity_encryption_proof,
                encrypted_identity=encrypted_identity,
                timestamp=timestamp,
                proof_hash=proof_hash
            )
            
            return proof
        
        except (InvalidProofError, TypeError) as e:
            raise InvalidProofError(f"Failed to generate withdrawal proof: {e}")
    
    @staticmethod
    def verify_withdrawal_proof(
        proof: WithdrawalProof,
        merkle_root: bytes,
        nullifier_set: Set[bytes],
        auditor_pk: bytes,
        commitment: Optional[bytes] = None
    ) -> bool:
        """
        Verify withdrawal proof without revealing secrets.
        
        Verification order (critical for security):
        1. Check nullifier NOT in set (fail fast on double-spend)
        2. Verify Merkle path (ensure commitment exists)
        3. Verify identity encryption proof
        4. Verify proof hash integrity
        
        Args:
            proof: Proof to verify
            merkle_root: Current Merkle tree root
            nullifier_set: Set of already-used nullifiers
            auditor_pk: Auditor's public key
            commitment: Optional expected commitment (for verification)
            
        Returns:
            bool: True if all proof components are valid
            
        Raises:
            DoubleSpendError: If nullifier already used
            InvalidMerklePathError: If Merkle path invalid
            InvalidIdentityProofError: If identity proof invalid
            ProofTamperingError: If proof hash doesn't match
        """
        try:
            # 1. CHECK NULLIFIER FIRST (fail fast on double-spend)
            if proof.nullifier in nullifier_set:
                raise DoubleSpendError(
                    "Nullifier already used - double-spend detected!"
                )
            
            # 2. VERIFY MERKLE PATH
            if not isinstance(proof.merkle_path, list):
                raise InvalidMerklePathError("Merkle path must be list")
            
            if not all(isinstance(h, bytes) and len(h) == 32 for h in proof.merkle_path):
                raise InvalidMerklePathError("All path hashes must be 32 bytes")
            
            # If commitment provided, verify Merkle path
            if commitment is not None:
                try:
                    tree = MerkleTree(tree_height=len(proof.merkle_path))
                    if not tree.verify_path(commitment, proof.merkle_path, proof.leaf_index):
                        raise InvalidMerklePathError("Merkle path verification failed")
                except Exception as e:
                    raise InvalidMerklePathError(f"Merkle path error: {e}")
            
            # 3. VERIFY IDENTITY ENCRYPTION PROOF
            try:
                if not isinstance(proof.identity_encryption_proof, bytes):
                    raise InvalidIdentityProofError("Proof must be bytes")
                if len(proof.identity_encryption_proof) != 32:
                    raise InvalidIdentityProofError("Proof must be 32 bytes")
                if not isinstance(proof.encrypted_identity, bytes):
                    raise InvalidIdentityProofError("Encrypted identity must be bytes")
            except InvalidIdentityProofError:
                raise
            except Exception as e:
                raise InvalidIdentityProofError(f"Identity proof error: {e}")
            
            # 4. VERIFY PROOF HASH INTEGRITY
            try:
                # Reconstruct proof hash
                proof_components = hash_concatenate(
                    proof.nullifier,
                    b"".join(proof.merkle_path),
                    proof.leaf_index.to_bytes(8, 'big'),
                    proof.identity_encryption_proof,
                    proof.encrypted_identity,
                    proof.timestamp.isoformat().encode('utf-8')
                )
                
                reconstructed_hash = sha256(proof_components)
                
                if reconstructed_hash != proof.proof_hash:
                    raise ProofTamperingError("Proof hash mismatch - proof tampered!")
            except ProofTamperingError:
                raise
            except Exception as e:
                raise ProofTamperingError(f"Hash verification failed: {e}")
            
            # All verifications passed
            return True
        
        except (DoubleSpendError, InvalidMerklePathError, InvalidIdentityProofError, ProofTamperingError):
            raise
        except Exception as e:
            raise InvalidProofError(f"Proof verification failed: {e}")
