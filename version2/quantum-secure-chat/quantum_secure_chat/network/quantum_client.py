"""
Quantum Security Client - USING REAL QKD PROTOCOLS (YOUR CODE)
"""

import requests
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..qkd.bb84 import QKDProtocol
from ..qkd.entanglement_qkd import EntanglementQKD
from ..qkd.key_composer import BrahmaguptaComposer
from ..crypto.key_derivation import RamanujanKDF

class QuantumSecurityClient:
    """
    Client-side quantum security manager USING REAL QKD
    """
    
    def __init__(self, user_port, central_server_url):
        self.user_port = str(user_port)
        self.central_server = central_server_url
        self.quantum_keys = {}  # {target_port: quantum_key_bytes} - LOCAL CACHE
        self.fernet_objects = {}  # {target_port: Fernet_object} - LOCAL CACHE
        self.established_sessions = set()  # Track established sessions
        
        # REAL Quantum protocols - YOUR ACTUAL CODE
        self.bb84 = QKDProtocol(key_length=256)
        self.e91 = EntanglementQKD(key_length=256)
        print("🔬 REAL QKD Protocols Loaded: BB84 + E91 + Brahmagupta + Ramanujan")
    
    def get_session_id(self, user1_port, user2_port):
        """Generate session ID in ascending order as simple string"""
        # Validate different ports
        if user1_port == user2_port:
            print(f"❌ ERROR: Cannot create session with same port: {user1_port}")
            return None
            
        ports = sorted([int(user1_port), int(user2_port)])
        session_id = f"{ports[0]}{ports[1]}"  # "20002001" format
        return session_id
    
    def establish_secure_channel(self, target_port):
        """
        Establish quantum-secure channel ONCE per user pair
        Returns: True if successful, False if failed
        """
        print(f"🔐 Establishing quantum security with {target_port}...")
        
        # VALIDATION: Check if same port
        if self.user_port == target_port:
            print(f"❌ ERROR: Cannot establish quantum security with yourself")
            return False
        
        # CHECK LOCAL CACHE FIRST - FAST PATH
        if self.is_secure_channel_established(target_port):
            print(f"✅ Quantum security already established (cached)")
            return True
        
        session_id = self.get_session_id(self.user_port, target_port)
        if not session_id:
            return False
            
        print(f"📡 Session ID: {session_id}")
        
        # STEP 1: Check if key already exists on SERVER
        existing_key = self._check_existing_key(session_id)
        if existing_key:
            print("🎯 Found existing quantum key - caching locally!")
            self._cache_key_locally(target_port, existing_key)
            self.established_sessions.add(session_id)
            return True
        
        # STEP 2: Initialize quantum session
        if not self._init_quantum_session(target_port):
            print("❌ Failed to initialize quantum session")
            return False
        
        # STEP 3: Determine who generates the key
        is_initiator = self._should_generate_key(target_port)
        print(f"🎯 Role: {'KEY GENERATOR' if is_initiator else 'KEY RECEIVER'}")
        
        if is_initiator:
            success = self._generate_and_share_quantum_key(session_id, target_port)
        else:
            success = self._receive_quantum_key(session_id, target_port)
        
        if success:
            self.established_sessions.add(session_id)
            print(f"✅ Quantum security ESTABLISHED")
        
        return success
    
    def _check_existing_key(self, session_id):
        """Check if quantum key exists on SERVER - ONE TIME CHECK"""
        try:
            response = requests.get(f"{self.central_server}/quantum/get_key/{session_id}", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'key_ready':
                    quantum_key_b64 = data.get('quantum_key')
                    if quantum_key_b64:
                        quantum_key_bytes = base64.b64decode(quantum_key_b64)
                        print(f"✅ Found quantum key on server")
                        return quantum_key_bytes
        except Exception as e:
            print(f"❌ Error checking key: {e}")
        return None
    
    def _cache_key_locally(self, target_port, quantum_key_bytes):
        """Cache quantum key locally for fast access"""
        self.quantum_keys[target_port] = quantum_key_bytes
        self._create_fernet_object(target_port, quantum_key_bytes)
        print(f"💾 Key cached locally for {target_port}")
    
    def _generate_and_share_quantum_key(self, session_id, target_port):
        """Generate quantum key ONCE and share it"""
        try:
            print("⚛️  Generating quantum keys...")
            
            # GENERATE BB84 KEY
            bb84_key_bits = self.bb84.generate_key()
            bb84_key_bytes = self._bits_to_bytes(bb84_key_bits)
            
            # GENERATE E91 KEY  
            e91_key_bits = self.e91.generate_key()
            e91_key_bytes = self._bits_to_bytes(e91_key_bits)
            
            # COMBINE USING BRAHMAGUPTA
            composed_key = BrahmaguptaComposer.compose_keys(bb84_key_bytes, e91_key_bytes)
            
            # STRENGTHEN WITH RAMANUJAN KDF
            final_quantum_key = RamanujanKDF.derive_key(composed_key, 32)
            
            # Convert to base64 for storage
            quantum_key_b64 = base64.b64encode(final_quantum_key).decode('utf-8')
            
            # Store on server and cache locally
            if self._store_quantum_key(session_id, quantum_key_b64):
                self._cache_key_locally(target_port, final_quantum_key)
                print(f"✅ Quantum key GENERATED and stored")
                return True
                
        except Exception as e:
            print(f"❌ Quantum key generation failed: {e}")
        return False
    
    def _receive_quantum_key(self, session_id, target_port):
        """Receive quantum key from server - WITH TIMEOUT"""
        print("⏳ Waiting for quantum key...")
        
        start_time = time.time()
        max_wait_time = 15  # Reduced timeout
        
        while time.time() - start_time < max_wait_time:
            try:
                response = requests.get(f"{self.central_server}/quantum/get_key/{session_id}", timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'key_ready':
                        quantum_key_b64 = data.get('quantum_key')
                        if quantum_key_b64:
                            quantum_key_bytes = base64.b64decode(quantum_key_b64)
                            self._cache_key_locally(target_port, quantum_key_bytes)
                            print(f"✅ Quantum key RECEIVED")
                            return True
                
                time.sleep(2)
                print(f"⏳ Waiting... ({int(time.time() - start_time)}s)")
                
            except Exception as e:
                print(f"❌ Error receiving key: {e}")
                time.sleep(2)
        
        print(f"❌ Timeout waiting for quantum key")
        return False
    
    def _bits_to_bytes(self, bits):
        """Convert bits to bytes"""
        while len(bits) % 8 != 0:
            bits.append(0)
        
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            byte_array.append(byte)
        
        return bytes(byte_array)
    
    def _should_generate_key(self, target_port):
        """Determine if this user should generate the quantum key"""
        # User with lower port number generates the key
        return self.user_port < target_port
    
    def _init_quantum_session(self, target_port):
        """Initialize quantum session on central server"""
        try:
            session_id = self.get_session_id(self.user_port, target_port)
            if not session_id:
                return False
                
            response = requests.post(
                f"{self.central_server}/quantum/init_session",
                json={
                    'user1_port': self.user_port,
                    'user2_port': target_port
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'key_exists':
                    print("✅ Key already exists")
                    return True
                elif data.get('session_id'):
                    print(f"✅ Quantum session initialized")
                    return True
            return False
                
        except Exception as e:
            print(f"❌ Quantum session init error: {e}")
        return False
    
    def _store_quantum_key(self, session_id, quantum_key):
        """Store quantum key on central server"""
        try:
            response = requests.post(
                f"{self.central_server}/quantum/store_key", 
                json={
                    'session_id': session_id,
                    'quantum_key': quantum_key,
                    'generated_by': self.user_port
                },
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"❌ Store quantum key error: {e}")
        return False
    
    def _create_fernet_object(self, target_port, quantum_key_bytes):
        """Create Fernet encryption object from quantum key"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'quantum_secure_chat',
                iterations=100000,
            )
            fernet_key = base64.urlsafe_b64encode(kdf.derive(quantum_key_bytes))
            self.fernet_objects[target_port] = Fernet(fernet_key)
            return True
        except Exception as e:
            print(f"❌ Fernet object creation error: {e}")
        return False
    
    def encrypt_message(self, target_port, message):
        """Encrypt message using cached quantum key"""
        if target_port in self.fernet_objects:
            try:
                encrypted_message = self.fernet_objects[target_port].encrypt(message.encode())
                encrypted_b64 = base64.b64encode(encrypted_message).decode('utf-8')
                return encrypted_b64
            except Exception as e:
                print(f"❌ Encryption error: {e}")
        else:
            print(f"❌ No quantum key for {target_port}")
        return None
    
    def decrypt_message(self, target_port, encrypted_message):
        """Decrypt message using cached quantum key"""
        if target_port in self.fernet_objects:
            try:
                encrypted_bytes = base64.b64decode(encrypted_message)
                decrypted_message = self.fernet_objects[target_port].decrypt(encrypted_bytes)
                return decrypted_message.decode('utf-8')
            except Exception as e:
                print(f"❌ Decryption error: {e}")
        return None
    
    def is_secure_channel_established(self, target_port):
        """Check if quantum secure channel is established (LOCAL CHECK)"""
        return target_port in self.quantum_keys
    
    def get_quantum_status(self, target_port=None):
        """Get quantum security status"""
        if target_port:
            session_id = self.get_session_id(self.user_port, target_port)
            return {
                'secure_channel': self.is_secure_channel_established(target_port),
                'target_port': target_port,
                'session_id': session_id
            }
        else:
            return {
                'secure_channels': list(self.quantum_keys.keys()),
                'total_secure': len(self.quantum_keys),
                'established_sessions': list(self.established_sessions)
            }

    def check_existing_key(self, target_port):
        """Public method to check if quantum key exists for target"""
        session_id = self.get_session_id(self.user_port, target_port)
        return {
            'key_exists': self.is_secure_channel_established(target_port),
            'session_id': session_id,
            'secure_channel': self.is_secure_channel_established(target_port)
        }

    def get_session_info(self, target_port):
        """Get session information for a target user"""
        session_id = self.get_session_id(self.user_port, target_port)
        return {
            'session_id': session_id,
            'user1': min(self.user_port, target_port),
            'user2': max(self.user_port, target_port),
            'secure_channel': self.is_secure_channel_established(target_port)
        }

    def clear_cache(self):
        """Clear local cache (for testing/logout)"""
        self.quantum_keys.clear()
        self.fernet_objects.clear()
        self.established_sessions.clear()
        print("🧹 Quantum cache cleared")

# Utility class for quantum operations
class QuantumUtils:
    """Utility functions for quantum operations"""
    
    @staticmethod
    def validate_session_id(session_id):
        """Validate that session ID is in correct format"""
        if not session_id:
            return False
        if not session_id.isdigit():
            return False
        if len(session_id) != 8:  # Should be 8 digits like "20002001"
            return False
        return True
    
    @staticmethod
    def extract_ports_from_session(session_id):
        """Extract user ports from session ID"""
        if not QuantumUtils.validate_session_id(session_id):
            return None, None
        
        port1 = session_id[:4]  # First 4 digits
        port2 = session_id[4:]  # Last 4 digits
        return port1, port2
    
    @staticmethod
    def generate_session_id_direct(port1, port2):
        """Generate session ID directly from ports"""
        if port1 == port2:
            return None
        ports = sorted([int(port1), int(port2)])
        return f"{ports[0]}{ports[1]}"

# Example usage and testing
if __name__ == "__main__":
    # Test the quantum client
    client = QuantumSecurityClient("2000", "http://localhost:5000")
    
    # Test session ID generation
    session_id = client.get_session_id("2000", "2001")
    print(f"Test Session ID: {session_id}")
    
    # Test port extraction
    port1, port2 = QuantumUtils.extract_ports_from_session(session_id)
    print(f"Extracted ports: {port1}, {port2}")
    
    print("✅ Quantum Security Client ready for use!")
