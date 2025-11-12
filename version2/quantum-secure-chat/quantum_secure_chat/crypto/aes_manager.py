"""
AES Encryption Manager for quantum-secured messages
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

class QuantumAESManager:
    """
    Manages AES encryption using quantum-derived keys
    """
    
    def __init__(self):
        self.backend = default_backend()
    
    @staticmethod
    def generate_iv():
        """Generate a random initialization vector"""
        return os.urandom(16)
    
    def encrypt_aes_cbc(self, plaintext: bytes, key: bytes, iv: bytes = None) -> dict:
        """
        Encrypt using AES-CBC mode
        Returns: {'ciphertext': base64, 'iv': base64}
        """
        if iv is None:
            iv = self.generate_iv()
        
        # Ensure key is 16, 24, or 32 bytes
        if len(key) not in [16, 24, 32]:
            # Hash to get proper key length
            import hashlib
            key = hashlib.sha256(key).digest()[:32]  # Use SHA256 and take 32 bytes
        
        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
    
    def decrypt_aes_cbc(self, ciphertext_b64: str, key: bytes, iv_b64: str) -> bytes:
        """
        Decrypt AES-CBC encrypted message
        """
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            
            # Ensure proper key length
            if len(key) not in [16, 24, 32]:
                import hashlib
                key = hashlib.sha256(key).digest()[:32]
            
            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def encrypt_aes_gcm(self, plaintext: bytes, key: bytes, associated_data: bytes = None) -> dict:
        """
        Encrypt using AES-GCM mode (authenticated encryption)
        Returns: {'ciphertext': base64, 'tag': base64, 'nonce': base64}
        """
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Ensure proper key length
        if len(key) not in [16, 24, 32]:
            import hashlib
            key = hashlib.sha256(key).digest()[:32]
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Add associated data if provided
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8')
        }
    
    def decrypt_aes_gcm(self, ciphertext_b64: str, key: bytes, tag_b64: str, nonce_b64: str, 
                       associated_data: bytes = None) -> bytes:
        """
        Decrypt AES-GCM encrypted message
        """
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            tag = base64.b64decode(tag_b64)
            nonce = base64.b64decode(nonce_b64)
            
            # Ensure proper key length
            if len(key) not in [16, 24, 32]:
                import hashlib
                key = hashlib.sha256(key).digest()[:32]
            
            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            
            # Add associated data if provided
            if associated_data:
                decryptor.authenticate_additional_data(associated_data)
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def encrypt_with_quantum_key(self, plaintext: str, quantum_key: bytes, mode: str = 'CBC') -> dict:
        """
        High-level encryption using quantum-derived key
        """
        if mode.upper() == 'GCM':
            return self.encrypt_aes_gcm(plaintext.encode('utf-8'), quantum_key)
        else:  # Default to CBC
            return self.encrypt_aes_cbc(plaintext.encode('utf-8'), quantum_key)
    
    def decrypt_with_quantum_key(self, encrypted_data: dict, quantum_key: bytes, mode: str = 'CBC') -> str:
        """
        High-level decryption using quantum-derived key
        """
        try:
            if mode.upper() == 'GCM':
                plaintext_bytes = self.decrypt_aes_gcm(
                    encrypted_data['ciphertext'],
                    quantum_key,
                    encrypted_data['tag'],
                    encrypted_data['nonce']
                )
            else:  # CBC
                plaintext_bytes = self.decrypt_aes_cbc(
                    encrypted_data['ciphertext'],
                    quantum_key,
                    encrypted_data['iv']
                )
            
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            raise Exception(f"Quantum decryption failed: {str(e)}")
