import unittest
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

# Import the core cryptographic functions
from discovery import (
    encrypt_message, 
    decrypt_message, 
    sign_file_data, 
    verify_and_strip_data
)

class TestP2PCryptography(unittest.TestCase):

    def setUp(self):
        """Set up dummy keys and data before each test runs."""
        # 1. Generate a dummy 32-byte AES session key
        self.session_key = os.urandom(32)
        
        # 2. Generate a dummy Ed25519 Identity Keypair
        self.priv_key = ed25519.Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        
        # 3. Calculate the fingerprint to mock the trusted_peers dictionary
        pub_bytes = self.pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.fingerprint = hashlib.sha256(pub_bytes).hexdigest()[:12]
        
        self.trusted_peers = {
            f"peer_{self.fingerprint}.pem": self.pub_key
        }
        
        # 4. Dummy file data
        self.test_data = b"Hello This is a highly classified secret file."

    # --- REQUIREMENT 7: CONFIDENTIALITY & INTEGRITY (AES-GCM) ---

    def test_aes_encryption_decryption_success(self):
        """Test that a file can be successfully encrypted and decrypted."""
        ciphertext = encrypt_message(self.session_key, self.test_data)
        
        # The ciphertext should be longer than plaintext (12-byte nonce + 16-byte MAC tag)
        self.assertEqual(len(ciphertext), len(self.test_data) + 28)
        
        plaintext = decrypt_message(self.session_key, ciphertext)
        self.assertEqual(plaintext, self.test_data)

    def test_aes_tampering_rejection(self):
        """Test that altering a single byte of ciphertext causes a fatal decryption error."""
        ciphertext = bytearray(encrypt_message(self.session_key, self.test_data))
        
        # Simulating a Man-in-the-Middle flipping one bit in transit
        ciphertext[-1] ^= 0xFF 
        
        # AES-GCM should detect the tampered MAC tag and throw an exception
        with self.assertRaises(Exception):
            decrypt_message(self.session_key, bytes(ciphertext))

    # --- REQUIREMENT 5: OFFLINE VERIFICATION (DIGITAL SIGNATURES) ---

    def test_signature_verification_success(self):
        """Test that the 76-byte attached signature correctly verifies."""
        signed_bundle = sign_file_data(self.test_data, self.priv_key)
        
        # The bundle should be exactly 76 bytes larger than the original data
        self.assertEqual(len(signed_bundle), len(self.test_data) + 76)
        
        is_valid, extracted_data = verify_and_strip_data(signed_bundle, self.trusted_peers)
        
        self.assertTrue(is_valid)
        self.assertEqual(extracted_data, self.test_data)

    def test_signature_tampering_rejection(self):
        """Test that altering the file data causes the signature verification to fail."""
        signed_bundle = bytearray(sign_file_data(self.test_data, self.priv_key))
        
        # Simulating an offline peer altering the PDF text before forwarding it
        signed_bundle[0] ^= 0xFF 
        
        is_valid, error_msg = verify_and_strip_data(bytes(signed_bundle), self.trusted_peers)
        
        self.assertFalse(is_valid)
        self.assertEqual(error_msg, "Signature verification failed! File was tampered with.")

    def test_signature_unknown_author_rejection(self):
        """Test that a file signed by an untrusted peer is rejected."""
        signed_bundle = sign_file_data(self.test_data, self.priv_key)
        
        # Pass in an empty trusted_peers dictionary so the author is unknown
        empty_trust_store = {}
        is_valid, error_msg = verify_and_strip_data(signed_bundle, empty_trust_store)
        
        self.assertFalse(is_valid)
        self.assertTrue("Unknown creator" in error_msg)

if __name__ == '__main__':
    unittest.main(verbosity=2)