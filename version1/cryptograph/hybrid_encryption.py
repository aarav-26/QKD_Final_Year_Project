from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import base64

class HybridEncryption:
    def __init__(self, key_bytes):
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode()
        self.key = key_bytes.ljust(32, b'\0')[:32]
        self.salt = b'\x00' * 16

    def _derive_key(self):
        return scrypt(
            password=self.key,
            salt=self.salt,
            key_len=32,
            N=2**14,
            r=8,
            p=1
        )

    def encrypt(self, plaintext):
        key = self._derive_key()
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(
            pad(plaintext.encode('utf-8'), AES.block_size)
        )
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt(self, encrypted_data):
        data = base64.b64decode(encrypted_data)
        if len(data) < 32:
            raise ValueError("Message too short")

        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]

        key = self._derive_key()
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size).decode('utf-8')

    def encrypt_bytes(self, data: bytes) -> bytes:
        encoded = base64.b64encode(data).decode('utf-8')
        return self.encrypt(encoded).encode('utf-8')

    def decrypt_bytes(self, encrypted_data: bytes) -> bytes:
        decrypted = self.decrypt(encrypted_data.decode('utf-8'))
        return base64.b64decode(decrypted.encode('utf-8'))
