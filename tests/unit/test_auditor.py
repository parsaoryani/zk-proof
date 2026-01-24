"""Tests for Auditor mechanism."""

import pytest
import os
from zkm.core.auditor import Auditor, IdentityEncryptionProof
from zkm.exceptions import EncryptionError, DecryptionError


class TestAuditorInitialization:
    """Tests for Auditor initialization."""
    
    def test_auditor_creation_new_keypair(self):
        """Test creating auditor with new key pair."""
        auditor = Auditor()
        
        assert auditor.public_key is not None
        assert auditor.private_key is not None
        assert isinstance(auditor.public_key, bytes)
        assert isinstance(auditor.private_key, bytes)
    
    def test_auditor_public_key_pem_format(self):
        """Test that public key is in PEM format."""
        auditor = Auditor()
        pk = auditor.public_key
        
        assert b"-----BEGIN PUBLIC KEY-----" in pk
        assert b"-----END PUBLIC KEY-----" in pk
    
    def test_auditor_private_key_pem_format(self):
        """Test that private key is in PEM format."""
        auditor = Auditor()
        sk = auditor.private_key
        
        assert b"-----BEGIN RSA PRIVATE KEY-----" in sk or b"-----BEGIN PRIVATE KEY-----" in sk
        assert b"-----END RSA PRIVATE KEY-----" in sk or b"-----END PRIVATE KEY-----" in sk
    
    def test_auditor_different_keypairs(self):
        """Test that different auditors have different keypairs."""
        auditor1 = Auditor()
        auditor2 = Auditor()
        
        assert auditor1.public_key != auditor2.public_key
        assert auditor1.private_key != auditor2.private_key
    
    def test_auditor_load_existing_key(self):
        """Test loading an existing private key."""
        # Create first auditor
        auditor1 = Auditor()
        private_key_bytes = auditor1.private_key
        
        # Load same key in new auditor
        auditor2 = Auditor(private_key=private_key_bytes)
        
        assert auditor2.public_key == auditor1.public_key
        assert auditor2.private_key == auditor1.private_key


class TestIdentityEncryption:
    """Tests for identity encryption."""
    
    @pytest.fixture
    def auditor(self):
        """Create an auditor for testing."""
        return Auditor()
    
    def test_encrypt_identity(self, auditor):
        """Test encrypting an identity."""
        identity = "alice@example.com"
        ciphertext = auditor.encrypt_identity(identity)
        
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) > 0
        assert ciphertext != identity.encode()  # Should be encrypted
    
    def test_encrypt_decrypt_roundtrip(self, auditor):
        """Test encryption and decryption roundtrip."""
        identity = "bob@example.com"
        
        ciphertext = auditor.encrypt_identity(identity)
        decrypted = auditor.decrypt_identity(ciphertext)
        
        assert decrypted == identity
    
    def test_encrypt_different_identities(self, auditor):
        """Test encrypting different identities produces different ciphertexts."""
        identity1 = "alice@example.com"
        identity2 = "bob@example.com"
        
        ciphertext1 = auditor.encrypt_identity(identity1)
        ciphertext2 = auditor.encrypt_identity(identity2)
        
        assert ciphertext1 != ciphertext2
    
    def test_decrypt_with_wrong_key_fails(self, auditor):
        """Test that decryption with wrong key fails."""
        identity = "alice@example.com"
        ciphertext = auditor.encrypt_identity(identity)
        
        # Create different auditor
        auditor2 = Auditor()
        
        # Should raise DecryptionError
        with pytest.raises(DecryptionError):
            auditor2.decrypt_identity(ciphertext)
    
    def test_encrypt_invalid_identity_type(self, auditor):
        """Test that invalid identity type raises error."""
        with pytest.raises(EncryptionError):
            auditor.encrypt_identity(12345)  # Not a string
        
        with pytest.raises(EncryptionError):
            auditor.encrypt_identity(b"bytes")  # Bytes, not string
    
    def test_decrypt_invalid_ciphertext(self, auditor):
        """Test that invalid ciphertext raises error."""
        with pytest.raises(DecryptionError):
            auditor.decrypt_identity(b"invalid ciphertext")
    
    def test_encrypt_long_identity(self, auditor):
        """Test encrypting long identity."""
        identity = "very.long.email.address.with.many.parts@subdomain.example.com"
        ciphertext = auditor.encrypt_identity(identity)
        decrypted = auditor.decrypt_identity(ciphertext)
        
        assert decrypted == identity
    
    def test_encrypt_unicode_identity(self, auditor):
        """Test encrypting identity with unicode characters."""
        identity = "用户@例子.com"  # Chinese characters
        ciphertext = auditor.encrypt_identity(identity)
        decrypted = auditor.decrypt_identity(ciphertext)
        
        assert decrypted == identity


class TestIdentityEncryptionProof:
    """Tests for identity encryption proofs."""
    
    @pytest.fixture
    def auditor(self):
        """Create an auditor for testing."""
        return Auditor()
    
    def test_generate_proof(self, auditor):
        """Test generating an identity encryption proof."""
        identity = "alice@example.com"
        ciphertext = auditor.encrypt_identity(identity)
        
        proof = IdentityEncryptionProof.generate_proof(
            identity=identity,
            ciphertext=ciphertext,
            auditor_pk=auditor.public_key
        )
        
        assert isinstance(proof, bytes)
        assert len(proof) == 32  # SHA-256
    
    def test_generate_proof_different_inputs_different_proofs(self, auditor):
        """Test that different inputs produce different proofs."""
        identity1 = "alice@example.com"
        identity2 = "bob@example.com"
        
        ciphertext1 = auditor.encrypt_identity(identity1)
        ciphertext2 = auditor.encrypt_identity(identity2)
        
        proof1 = IdentityEncryptionProof.generate_proof(
            identity=identity1,
            ciphertext=ciphertext1,
            auditor_pk=auditor.public_key
        )
        
        proof2 = IdentityEncryptionProof.generate_proof(
            identity=identity2,
            ciphertext=ciphertext2,
            auditor_pk=auditor.public_key
        )
        
        assert proof1 != proof2
    
    def test_verify_proof_valid(self, auditor):
        """Test verifying a valid proof."""
        identity = "alice@example.com"
        ciphertext = auditor.encrypt_identity(identity)
        
        identity_hash = os.urandom(32)
        
        proof = IdentityEncryptionProof.generate_proof(
            identity=identity,
            ciphertext=ciphertext,
            auditor_pk=auditor.public_key
        )
        
        is_valid = IdentityEncryptionProof.verify_proof(
            proof=proof,
            ciphertext=ciphertext,
            auditor_pk=auditor.public_key,
            expected_identity_hash=identity_hash
        )
        
        assert is_valid is True
    
    def test_verify_proof_invalid_proof_format(self, auditor):
        """Test that invalid proof format fails verification."""
        identity = "alice@example.com"
        ciphertext = auditor.encrypt_identity(identity)
        identity_hash = os.urandom(32)
        
        # Use wrong proof format (not 32 bytes)
        wrong_proof = b"short"
        
        is_valid = IdentityEncryptionProof.verify_proof(
            proof=wrong_proof,
            ciphertext=ciphertext,
            auditor_pk=auditor.public_key,
            expected_identity_hash=identity_hash
        )
        
        assert is_valid is False
    
    def test_generate_proof_invalid_inputs(self, auditor):
        """Test that invalid inputs raise errors."""
        ciphertext = auditor.encrypt_identity("alice@example.com")
        
        with pytest.raises(ValueError):
            IdentityEncryptionProof.generate_proof(
                identity=123,  # Not a string
                ciphertext=ciphertext,
                auditor_pk=auditor.public_key
            )
        
        with pytest.raises(ValueError):
            IdentityEncryptionProof.generate_proof(
                identity="alice@example.com",
                ciphertext="not bytes",  # Not bytes
                auditor_pk=auditor.public_key
            )


class TestAuditorSecurityProperties:
    """Tests for security properties of auditor."""
    
    def test_encryption_randomness(self):
        """Test that encryption is randomized (RSA-OAEP)."""
        auditor = Auditor()
        identity = "alice@example.com"
        
        # Encrypt same identity twice
        ciphertext1 = auditor.encrypt_identity(identity)
        ciphertext2 = auditor.encrypt_identity(identity)
        
        # Should be different due to randomization
        assert ciphertext1 != ciphertext2
        
        # But both should decrypt to same value
        assert auditor.decrypt_identity(ciphertext1) == identity
        assert auditor.decrypt_identity(ciphertext2) == identity
    
    def test_key_isolation(self):
        """Test that different auditors have isolated keys."""
        auditor1 = Auditor()
        auditor2 = Auditor()
        
        identity = "alice@example.com"
        
        # Encrypt with first auditor
        ciphertext = auditor1.encrypt_identity(identity)
        
        # Should decrypt successfully
        assert auditor1.decrypt_identity(ciphertext) == identity
        
        # Should fail with second auditor
        with pytest.raises(DecryptionError):
            auditor2.decrypt_identity(ciphertext)
