# quantum_key_distribution/brahmagupta.py
import hashlib

class BrahmaguptaComposer:
    """
    Combines multiple quantum keys using Brahmagupta-inspired composition
    and mathematical operations for enhanced security.
    """
    
    @staticmethod
    def compose_keys(key1_bytes: bytes, key2_bytes: bytes) -> bytes:
        """
        Combines two byte keys securely using a Brahmagupta-inspired composition.
        Ensures outputs are always in 0–255 range.
        """
        max_len = max(len(key1_bytes), len(key2_bytes))
        key1_bytes = key1_bytes.ljust(max_len, b'\0')
        key2_bytes = key2_bytes.ljust(max_len, b'\0')

        N = 37
        combined_key = bytearray()

        for i in range(0, len(key1_bytes), 2):
            if i + 1 >= len(key1_bytes):
                combined_key.append(key1_bytes[i] ^ key2_bytes[i])
                continue

            a, b = key1_bytes[i], key1_bytes[i+1]
            c, d = key2_bytes[i], key2_bytes[i+1]

            # Ensure outputs are safely masked to 0–255
            new_byte1 = (a * c - N * b * d) & 0xFF
            new_byte2 = (a * d + b * c) & 0xFF
            combined_key.extend([new_byte1, new_byte2])

        return bytes(combined_key)
    
    @staticmethod
    def compose_multiple_keys(*keys: bytes) -> bytes:
        """Compose multiple keys together"""
        if not keys:
            return b''
        
        result = keys[0]
        for key in keys[1:]:
            result = BrahmaguptaComposer.compose_keys(result, key)
        
        return result
    
    @staticmethod
    def generate_hybrid_quantum_key():
        """Generate a hybrid key using both BB84 and E91 protocols"""
        # Generate keys from both protocols
        bb84 = QKDProtocol(key_length=512)
        e91 = EntanglementQKD(key_length=512)
        
        bb84_key = bb84.generate_key_bytes()
        e91_key = e91.generate_key_bytes()
        
        # Compose them using Brahmagupta method
        hybrid_key = BrahmaguptaComposer.compose_keys(bb84_key, e91_key)
        
        # Apply KDF for final key
        from ..crypto.key_derivation import RamanujanKDF
        final_key = RamanujanKDF.derive_key(hybrid_key)
        
        return final_key

# Backward compatibility
def brahmagupta_key_composition(key1_bytes: bytes, key2_bytes: bytes) -> bytes:
    return BrahmaguptaComposer.compose_keys(key1_bytes, key2_bytes)
