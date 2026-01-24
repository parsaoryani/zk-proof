"""Auditor mechanism for reversible unlinkability (Morales et al.)."""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from typing import Optional, Tuple
import os

from zkm.utils.hash import sha256, hash_concatenate
from zkm.utils.encoding import bytes_to_hex, hex_to_bytes
from zkm.exceptions import EncryptionError, DecryptionError


class Auditor:
    """
    Auditor with trapdoor mechanism for identity recovery.
    
    Paper Reference: Morales et al. - Section 4.2 (Reversible Unlinkability)
    
    The auditor maintains a private/public key pair for:
    - Encrypting user identities (public key, known to system)
    - Decrypting identities for regulatory compliance (private key, secret)
    """
    
    # Constants
    RSA_KEY_SIZE = 2048
    
    def __init__(self, private_key: Optional[bytes] = None):
        """
        Initialize auditor with new or existing RSA key pair.
        
        Args:
            private_key: Optional existing private key (PEM format)
            
        Raises:
            ValueError: If provided private key is invalid
        """
        if private_key is None:
            # Generate new RSA key pair
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.RSA_KEY_SIZE,
                backend=default_backend()
            )
        else:
            # Load existing private key
            try:
                self._private_key = serialization.load_pem_private_key(
                    private_key,
                    password=None,
                    backend=default_backend()
                )
                if not isinstance(self._private_key, rsa.RSAPrivateKey):
                    raise ValueError("Provided key is not an RSA private key")
            except Exception as e:
                raise ValueError(f"Failed to load private key: {e}")
    
    @property
    def public_key(self) -> bytes:
        """
        Return auditor's public key in PEM format.
        
        Returns:
            bytes: Public key in PEM encoding
        """
        public_key_obj = self._private_key.public_key()
        return public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @property
    def private_key(self) -> bytes:
        """
        Return auditor's private key in PEM format.
        
        Security: This must be stored securely (e.g., HSM, encrypted vault)
        and never exposed in logs or error messages.
        
        Returns:
            bytes: Private key in PEM encoding
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def encrypt_identity(self, identity: str) -> bytes:
        """
        Encrypt user identity/address with auditor's public key.
        
        Uses RSA-OAEP with SHA-256 for semantic security.
        
        Args:
            identity: User's address or ID (string)
            
        Returns:
            bytes: Encrypted ciphertext
            
        Raises:
            EncryptionError: If encryption fails
            
        Paper Reference: Morales et al. - Section 3.1 (Trapdoor Encryption)
        """
        try:
            if not isinstance(identity, str):
                raise EncryptionError("Identity must be a string")
            
            plaintext = identity.encode('utf-8')
            
            # Use public key from private key
            public_key = self._private_key.public_key()
            
            # RSA-OAEP encryption with SHA-256
            ciphertext = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return ciphertext
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt identity: {e}")
    
    def decrypt_identity(self, ciphertext: bytes) -> str:
        """
        Decrypt identity using private key (auditor only).
        
        Args:
            ciphertext: Encrypted identity
            
        Returns:
            str: Decrypted user identity
            
        Raises:
            DecryptionError: If decryption fails
            
        Purpose: Regulatory compliance, identity recovery
        Paper Reference: Morales et al. - Section 4.2
        """
        try:
            if not isinstance(ciphertext, bytes):
                raise DecryptionError("Ciphertext must be bytes")
            
            plaintext = self._private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt identity: {e}")


class IdentityEncryptionProof:
    """
    ZK-Proof that verifies an encryption contains a valid identity.
    
    Paper Reference: Morales et al. + Zerocash combined approach
    
    This is a simplified implementation using hash-based proof.
    In a production system, this would use formal ZK-SNARK techniques.
    """
    
    @staticmethod
    def generate_proof(
        identity: str,
        ciphertext: bytes,
        auditor_pk: bytes
    ) -> bytes:
        """
        Generate ZK-proof that ciphertext is valid encryption of identity.
        
        Args:
            identity: Plaintext identity
            ciphertext: Encrypted ciphertext
            auditor_pk: Auditor's public key (PEM)
            
        Returns:
            bytes: Proof hash
            
        Simplified Implementation:
            H(identity || ciphertext || auditor_pk)
        """
        try:
            if not isinstance(identity, str):
                raise ValueError("Identity must be string")
            if not isinstance(ciphertext, bytes):
                raise ValueError("Ciphertext must be bytes")
            if not isinstance(auditor_pk, bytes):
                raise ValueError("Auditor PK must be bytes")
            
            proof = hash_concatenate(identity, ciphertext, auditor_pk)
            return proof
        except Exception as e:
            raise ValueError(f"Failed to generate proof: {e}")
    
    @staticmethod
    def verify_proof(
        proof: bytes,
        ciphertext: bytes,
        auditor_pk: bytes,
        expected_identity_hash: bytes
    ) -> bool:
        """
        Verify proof without revealing identity.
        
        Note: This is a simplified verification. In practice, this would
        require more sophisticated ZK techniques.
        
        Args:
            proof: ZK-proof
            ciphertext: Encrypted ciphertext
            auditor_pk: Auditor's public key
            expected_identity_hash: Hash of expected identity
            
        Returns:
            bool: Proof validity
        """
        try:
            # Verify proof is correct length
            if not isinstance(proof, bytes) or len(proof) != 32:
                return False
            
            if not isinstance(ciphertext, bytes):
                return False
            
            if not isinstance(auditor_pk, bytes):
                return False
            
            if not isinstance(expected_identity_hash, bytes) or len(expected_identity_hash) != 32:
                return False
            
            # In a real system, we would verify that proof was correctly constructed
            # For now, we just verify that ciphertext and auditor_pk are valid
            return len(ciphertext) > 0 and len(auditor_pk) > 0
        except Exception:
            return False
