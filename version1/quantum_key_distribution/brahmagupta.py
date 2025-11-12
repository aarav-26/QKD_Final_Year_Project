# quantum_key_distribution/brahmagupta.py
def brahmagupta_key_composition(key1_bytes: bytes, key2_bytes: bytes) -> bytes:
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
