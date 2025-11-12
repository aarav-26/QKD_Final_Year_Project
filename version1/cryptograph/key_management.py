import os
import pickle
from cryptography.hybrid_encryption import HybridEncryption

class KeyManager:
    def __init__(self, storage_path="keys"):
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)
    
    def store_key(self, key_id, key_data):
        with open(f"{self.storage_path}/{key_id}.key", 'wb') as f:
            pickle.dump(key_data, f)
    
    def retrieve_key(self, key_id):
        try:
            with open(f"{self.storage_path}/{key_id}.key", 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            return None
    
    def rotate_key(self, old_key_id, new_key_data):
        self.store_key(old_key_id + "_old", self.retrieve_key(old_key_id))
        self.store_key(old_key_id, new_key_data)
