# quantum_key_distribution/ramanujan.py
import hashlib
import hmac

def bits_to_bytes(bits: list[int]) -> bytes:
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


def ramanujan_inspired_kdf(key_material: bytes, desired_length_bytes: int = 32) -> bytes:
    """
    A secure Key Derivation Function (KDF) inspired by Ramanujan.
    Uses HMAC-SHA256 for privacy amplification.
    """
    salt = b"ramanujan_theta_modular_forms_salt_v1"
    prk = hmac.new(salt, key_material, hashlib.sha256).digest()
    final_key = hmac.new(prk, b'\x01', hashlib.sha256).digest()
    return final_key[:desired_length_bytes]
