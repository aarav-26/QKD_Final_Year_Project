import unittest
from quantum_key_distribution.bb84 import QKDProtocol

class TestQKDProtocol(unittest.TestCase):
    def test_key_generation(self):
        qkd = QKDProtocol(key_length=128)
        key = qkd.generate_key()
        self.assertGreaterEqual(len(key), 32)  # Should have at least 32 bits after sifting
    
    def test_key_uniqueness(self):
        qkd = QKDProtocol()
        key1 = qkd.generate_key()
        key2 = qkd.generate_key()
        self.assertNotEqual(key1, key2)  # Keys should be different each time

if __name__ == '__main__':
    unittest.main()
