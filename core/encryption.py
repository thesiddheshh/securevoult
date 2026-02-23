import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class AESCipher:
    def __init__(self):
        self.nonce_size = 12  # 96-bit nonce for GCM

    def generate_key(self) -> bytes:
        """Generates a secure random 256-bit key."""
        return os.urandom(32)

    def encrypt(self, data: bytes, key: bytes) -> dict:
        """
        Encrypts data using AES-256-GCM.
        Returns dict containing nonce, ciphertext, and tag.
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(self.nonce_size)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # GCM ciphertext includes the tag at the end usually, 
        # but cryptography library returns ciphertext + tag combined.
        # We will split them for clarity in storage simulation.
        # Actually, standard practice is ciphertext + tag. 
        # Let's keep it simple: nonce + (ciphertext + tag)
        
        return {
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "payload": base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt(self, encrypted_data: dict, key: bytes) -> bytes:
        """
        Decrypts data using AES-256-GCM.
        """
        aesgcm = AESGCM(key)
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['payload'])
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: Integrity check failed or wrong key. {str(e)}")