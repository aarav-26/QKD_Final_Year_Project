"""
Key Derivation Functions for quantum keys
"""

import hashlib
import hmac
import base64

class RamanujanKDF:
    """
    A secure Key Derivation Function (KDF) inspired by Ramanujan.
    Uses HMAC-SHA256 for privacy amplification.
    """
    
    SALT = b"ramanujan_theta_modular_forms_salt_v1"
    
    @staticmethod
    def bits_to_bytes(bits: list) -> bytes:
        """Converts a list of bits (0/1) to a bytes object safely, padding to 8 bits."""
        bits = bits.copy()  # avoid mutating original list
        while len(bits) % 8 != 0:
            bits.append(0)  # pad with zeros

        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | (bits[i + j] & 1)
            byte_array.append(byte & 0xFF)
        return bytes(byte_array)
    
    @staticmethod
    def derive_key(key_material: bytes, desired_length_bytes: int = 32, 
                  salt: bytes = None, info: bytes = b"") -> bytes:
        """
        A secure Key Derivation Function (KDF) inspired by Ramanujan.
        Uses HKDF-like construction for key derivation.
        """
        if salt is None:
            salt = RamanujanKDF.SALT
        
        # Extract phase
        prk = hmac.new(salt, key_material, hashlib.sha256).digest()
        
        # Expand phase
        output = b""
        counter = 1
        while len(output) < desired_length_bytes:
            hmac_obj = hmac.new(prk, info + bytes([counter]), hashlib.sha256)
            output += hmac_obj.digest()
            counter += 1
        
        return output[:desired_length_bytes]
    
    @staticmethod
    def derive_from_quantum_bits(quantum_bits: list, desired_length_bytes: int = 32) -> bytes:
        """Derive key directly from quantum bits"""
        quantum_bytes = RamanujanKDF.bits_to_bytes(quantum_bits)
        return RamanujanKDF.derive_key(quantum_bytes, desired_length_bytes)
    
    @staticmethod
    def strengthen_quantum_key(quantum_key: bytes, iterations: int = 1000) -> bytes:
        """
        Additional strengthening for quantum keys using multiple rounds
        """
        strengthened_key = quantum_key
        for i in range(iterations):
            strengthened_key = hashlib.sha384(
                strengthened_key + quantum_key + bytes([i % 256])
            ).digest()
        
        return strengthened_key[:len(quantum_key)]

# Backward compatibility function
def ramanujan_inspired_kdf(key_material: bytes, desired_length_bytes: int = 32) -> bytes:
    return RamanujanKDF.derive_key(key_material, desired_length_bytes)
