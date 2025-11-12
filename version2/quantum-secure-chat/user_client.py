from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests
import threading
import webbrowser
import time
import os
import sys
import base64
from datetime import datetime
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# Central server URL
CENTRAL_SERVER = "http://localhost:5000"

# Admin credentials (in production, use environment variables or secure storage)
ADMIN_CREDENTIALS = {
    "admin": "quantumsecure123",
    "supervisor": "monitor456"
}

# Import REAL QKD protocols
try:
    from quantum_secure_chat.qkd.bb84 import QKDProtocol
    from quantum_secure_chat.qkd.entanglement_qkd import EntanglementQKD
    from quantum_secure_chat.qkd.key_composer import BrahmaguptaComposer
    from quantum_secure_chat.crypto.key_derivation import RamanujanKDF
    print("✅ SUCCESS: Loaded REAL QKD protocols (BB84 + E91 + Brahmagupta + Ramanujan)")
except ImportError as e:
    print(f"❌ ERROR: Failed to import QKD protocols: {e}")
    print("💡 Make sure you installed thepackage: pip install -e .")
    # Fallback to simulation (shouldn't happen if package is installed)
    class QKDProtocol:
        def generate_key(self): return [0,1]*128
        def bits_to_bytes(self, bits): return bytes([int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)])
    class EntanglementQKD:
        def generate_key(self): return [0,1]*128
        def bits_to_bytes(self, bits): return bytes([int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)])
    class BrahmaguptaComposer:
        @staticmethod
        def compose_keys(a,b): return a+b
    class RamanujanKDF:
        @staticmethod
        def derive_key(key, length): return key[:length]

class QuantumKeyManager:
    """Comprehensive key management system with session tracking"""
    
    def __init__(self):
        self.quantum_sessions = {}  # {session_id: QuantumSession}
        self.user_sessions = {}     # {username: [session_ids]}
        self.key_statistics = {
            'total_keys_generated': 0,
            'active_sessions': 0,
            'failed_key_exchanges': 0,
            'successful_key_exchanges': 0
        }
    
    def create_session(self, user1_port, user2_port, session_id, quantum_key=None):
        """Create a new quantum session"""
        quantum_session = QuantumSession(user1_port, user2_port, session_id, quantum_key)
        self.quantum_sessions[session_id] = quantum_session
        
        # Track user sessions
        for port in [user1_port, user2_port]:
            if port not in self.user_sessions:
                self.user_sessions[port] = []
            if session_id not in self.user_sessions[port]:
                self.user_sessions[port].append(session_id)
        
        if quantum_key:
            self.key_statistics['total_keys_generated'] += 1
            self.key_statistics['successful_key_exchanges'] += 1
            self.key_statistics['active_sessions'] += 1
        
        return quantum_session
    
    def get_session(self, session_id):
        """Get quantum session by ID"""
        return self.quantum_sessions.get(session_id)
    
    def get_user_sessions(self, user_port):
        """Get all sessions for a user"""
        session_ids = self.user_sessions.get(str(user_port), [])
        sessions = []
        for session_id in session_ids:
            session = self.get_session(session_id)
            if session:
                sessions.append(session)
        return sessions
    
    def update_session_key(self, session_id, quantum_key):
        """Update session with quantum key"""
        session = self.get_session(session_id)
        if session:
            session.quantum_key = quantum_key
            session.key_established = True
            session.establishment_time = datetime.now()
            
            self.key_statistics['total_keys_generated'] += 1
            self.key_statistics['successful_key_exchanges'] += 1
            self.key_statistics['active_sessions'] += 1
            
            return True
        return False
    
    def delete_session(self, session_id):
        """Delete a quantum session"""
        if session_id in self.quantum_sessions:
            session = self.quantum_sessions[session_id]
            
            # Remove from user sessions
            for port in [session.user1_port, session.user2_port]:
                port_str = str(port)
                if port_str in self.user_sessions and session_id in self.user_sessions[port_str]:
                    self.user_sessions[port_str].remove(session_id)
            
            # Update statistics
            if session.key_established:
                self.key_statistics['active_sessions'] -= 1
            
            del self.quantum_sessions[session_id]
            return True
        return False
    
    def get_all_sessions(self):
        """Get all quantum sessions"""
        return self.quantum_sessions
    
    def get_statistics(self):
        """Get key management statistics"""
        return self.key_statistics
    
    def record_failed_exchange(self):
        """Record a failed key exchange"""
        self.key_statistics['failed_key_exchanges'] += 1

class QuantumSession:
    """Represents a quantum key exchange session between two users"""
    
    def __init__(self, user1_port, user2_port, session_id, quantum_key=None):
        self.user1_port = str(user1_port)
        self.user2_port = str(user2_port)
        self.session_id = session_id
        self.quantum_key = quantum_key
        self.key_established = quantum_key is not None
        self.creation_time = datetime.now()
        self.establishment_time = datetime.now() if quantum_key else None
        self.last_used = datetime.now()
        
        # Generate a readable session name
        self.session_name = f"{user1_port}-{user2_port}"
    
    def to_dict(self, admin_access=False):
        """Convert session to dictionary for JSON serialization"""
        session_data = {
            'session_id': self.session_id,
            'user1_port': self.user1_port,
            'user2_port': self.user2_port,
            'session_name': self.session_name,
            'key_established': self.key_established,
            'creation_time': self.creation_time.isoformat(),
            'establishment_time': self.establishment_time.isoformat() if self.establishment_time else None,
            'last_used': self.last_used.isoformat(),
            'key_preview': self.quantum_key[:16].hex() + "..." if self.quantum_key else None
        }
        
        # Only show full key to admins
        if admin_access and self.quantum_key:
            session_data['full_key'] = self.quantum_key.hex()
        else:
            session_data['full_key'] = "🔒 RESTRICTED - Admin access required"
            
        return session_data
    
    def update_usage(self):
        """Update last used timestamp"""
        self.last_used = datetime.now()

class QuantumSecurityManager:
    """Manages quantum key exchange and encryption using REAL QKD protocols"""
    
    def __init__(self, user_port, central_server_url):
        self.user_port = str(user_port)
        self.central_server = central_server_url
        self.quantum_keys = {}  # {target_port: quantum_key_bytes} - LOCAL CACHE
        self.fernet_objects = {}  # {target_port: Fernet_object} - LOCAL CACHE
        self.established_sessions = set()  # Track established sessions
        
        # Key Management System
        self.key_manager = QuantumKeyManager()
        
        # REAL Quantum protocols 
        self.bb84 = QKDProtocol(key_length=256)
        self.e91 = EntanglementQKD(key_length=256)
        print(f"🔬 REAL QKD Protocols Loaded for user {user_port}")
    
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
        """Establish quantum-secure channel ONCE per user pair"""
        print(f"🔐 Establishing quantum security with {target_port}...")
        
        # VALIDATION: Check if same port
        if self.user_port == target_port:
            print(f"❌ ERROR: Cannot establish quantum security with yourself (port {target_port})")
            return False
        
        # CHECK LOCAL CACHE FIRST
        if self.is_secure_channel_established(target_port):
            print(f"✅ Quantum security already established with {target_port}")
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
            
            # Register in key manager
            self.key_manager.create_session(
                self.user_port, target_port, session_id, existing_key
            )
            return True
        
        # STEP 2: Initialize quantum session
        print("🔄 Initializing quantum session...")
        if not self._init_quantum_session(target_port):
            print("❌ Failed to initialize quantum session")
            return False
        
        # STEP 3: Determine who generates the key
        is_initiator = self._should_generate_key(session_id, target_port)
        print(f"🎯 Role: {'KEY GENERATOR' if is_initiator else 'KEY RECEIVER'}")
        
        if is_initiator:
            success = self._generate_and_share_quantum_key(session_id, target_port)
        else:
            success = self._receive_quantum_key(session_id, target_port)
        
        if success:
            self.established_sessions.add(session_id)
            print(f"✅ Quantum security ESTABLISHED for session {session_id}")
        
        return success
    
    def _check_existing_key(self, session_id):
        """Check if quantum key exists on SERVER - ONE TIME CHECK"""
        try:
            print(f"🔍 Checking for existing key for session {session_id}...")
            response = requests.get(f"{self.central_server}/quantum/get_key/{session_id}", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'key_ready':
                    quantum_key_b64 = data.get('quantum_key')
                    if quantum_key_b64:
                        quantum_key_bytes = base64.b64decode(quantum_key_b64)
                        print(f"✅ Found existing quantum key on server: {quantum_key_bytes[:16].hex()}...")
                        return quantum_key_bytes
            print(f"📭 No existing key found for session {session_id}")
        except Exception as e:
            print(f"❌ Error checking existing key: {e}")
        return None
    
    def _cache_key_locally(self, target_port, quantum_key_bytes):
        """Cache quantum key locally for fast access"""
        self.quantum_keys[target_port] = quantum_key_bytes
        self._create_fernet_object(target_port, quantum_key_bytes)
        print(f"💾 Quantum key cached locally for {target_port}")
    
    def _generate_and_share_quantum_key(self, session_id, target_port):
        """Generate quantum key ONCE and share it"""
        try:
            print("⚛️  Generating quantum keys using BB84 + E91...")
            
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
                
                # Register in key manager
                self.key_manager.create_session(
                    self.user_port, target_port, session_id, final_quantum_key
                )
                
                print(f"✅ Quantum key GENERATED and stored for session {session_id}")
                return True
                
        except Exception as e:
            print(f"❌ Quantum key generation failed: {e}")
            self.key_manager.record_failed_exchange()
        return False
    
    def _receive_quantum_key(self, session_id, target_port):
        """Receive quantum key from server - WITH TIMEOUT"""
        print("⏳ Waiting for quantum key from partner...")
        
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
                            
                            # Register in key manager
                            self.key_manager.create_session(
                                self.user_port, target_port, session_id, quantum_key_bytes
                            )
                            
                            print(f"✅ Quantum key RECEIVED for session {session_id}")
                            return True
                
                time.sleep(2)
                print(f"⏳ Waiting... ({int(time.time() - start_time)}s)")
                
            except Exception as e:
                print(f"❌ Error receiving quantum key: {e}")
                time.sleep(2)
        
        print(f"❌ Timeout waiting for quantum key after {max_wait_time} seconds")
        self.key_manager.record_failed_exchange()
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
    
    def _should_generate_key(self, session_id, target_port):
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
                    print("✅ Key already exists for this session")
                    return True
                elif data.get('session_id'):
                    print(f"✅ Quantum session initialized: {data.get('session_id')}")
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
            print(f"🔐 Encryption object created for port {target_port}")
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
                
                # Update session usage
                session_id = self.get_session_id(self.user_port, target_port)
                if session_id in self.key_manager.quantum_sessions:
                    self.key_manager.quantum_sessions[session_id].update_usage()
                
                return encrypted_b64
            except Exception as e:
                print(f"❌ Encryption error: {e}")
        else:
            print(f"❌ No quantum key established for port {target_port}")
        return None
    
    def decrypt_message(self, target_port, encrypted_message):
        """Decrypt message using cached quantum key - ONE TIME"""
        if target_port in self.fernet_objects:
            try:
                encrypted_bytes = base64.b64decode(encrypted_message)
                decrypted_message = self.fernet_objects[target_port].decrypt(encrypted_bytes)
                
                # Update session usage
                session_id = self.get_session_id(self.user_port, target_port)
                if session_id in self.key_manager.quantum_sessions:
                    self.key_manager.quantum_sessions[session_id].update_usage()
                
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
                'total_secure': len(self.quantum_keys)
            }
    
    def get_key_management_data(self, admin_access=False):
        """Get comprehensive key management data"""
        user_sessions = self.key_manager.get_user_sessions(self.user_port)
        sessions_data = [session.to_dict(admin_access) for session in user_sessions]
        statistics = self.key_manager.get_statistics()
        
        return {
            'sessions': sessions_data,
            'statistics': statistics,
            'local_cache_size': len(self.quantum_keys),
            'user_port': self.user_port,
            'admin_access': admin_access
        }
    
    def delete_quantum_session(self, session_id):
        """Delete a quantum session and clear local cache"""
        session = self.key_manager.get_session(session_id)
        if session:
            # Clear local cache for both users
            for port in [session.user1_port, session.user2_port]:
                if port in self.quantum_keys:
                    del self.quantum_keys[port]
                if port in self.fernet_objects:
                    del self.fernet_objects[port]
            
            # Remove from established sessions
            if session_id in self.established_sessions:
                self.established_sessions.remove(session_id)
            
            # Delete from key manager
            self.key_manager.delete_session(session_id)
            return True
        return False

class UserSession:
    def __init__(self, username, user_port, session_id):
        self.username = username
        self.user_port = str(user_port)
        self.session_id = session_id
        self.last_active = datetime.now()
        self.is_active = True
        self.quantum_manager = QuantumSecurityManager(user_port, CENTRAL_SERVER)
        self.decrypted_messages = {}  # Cache decrypted messages {message_id: decrypted_content}
        self.sent_messages = {}  # Store original messages we sent {message_id: original_message}
        self.last_message_ids = {}  # Track last message ID per conversation {target_port: last_message_id}
    
    def register_with_central(self):
        try:
            response = requests.post(f"{CENTRAL_SERVER}/register_user", json={
                'port': self.user_port,
                'username': self.username,
                'server_url': f"http://localhost:{self.user_port}"
            }, timeout=5)
            return response.json()
        except Exception as e:
            print(f"❌ Registration error for {self.username}: {e}")
            return {'status': 'error', 'message': 'Cannot connect to central server'}
    
    def get_all_users(self):
        try:
            response = requests.get(f"{CENTRAL_SERVER}/get_all_users", timeout=5)
            return response.json()
        except Exception as e:
            print(f"❌ Get users error for {self.username}: {e}")
            return {}
    
    def send_message(self, to_port, message, message_type='text', file_data=None, file_name=None, file_size=None, quantum_encrypted=False):
        try:
            payload = {
                'from_port': self.user_port,
                'to_port': str(to_port),
                'message': message,
                'type': message_type,
                'quantum_encrypted': quantum_encrypted
            }
            
            if message_type in ['image', 'file'] and file_data:
                payload['file_data'] = file_data
                payload['file_name'] = file_name
                payload['file_size'] = file_size
            
            response = requests.post(f"{CENTRAL_SERVER}/send_message", json=payload, timeout=10)
            result = response.json()
            
            # Store the original message if it's encrypted and we sent it
            if quantum_encrypted and result.get('status') == 'sent':
                message_id = result.get('message_id')
                if message_id:
                    self.sent_messages[message_id] = message  # Store original plaintext
            
            return result
        except Exception as e:
            print(f"❌ Send message error for {self.username}: {e}")
            return {'status': 'error'}
    
    def send_encrypted_message(self, to_port, message):
        """Send message encrypted with quantum key"""
        if not self.quantum_manager.is_secure_channel_established(to_port):
            return {'status': 'error', 'message': 'Quantum security not established'}
        
        encrypted_message = self.quantum_manager.encrypt_message(to_port, message)
        if encrypted_message:
            result = self.send_message(to_port, encrypted_message, 'encrypted_text', quantum_encrypted=True)
            
            # Store the original message for display in our own chat
            if result.get('status') == 'sent':
                message_id = result.get('message_id')
                if message_id:
                    self.sent_messages[message_id] = message
            
            return result
        else:
            return {'status': 'error', 'message': 'Encryption failed'}
    
    def receive_encrypted_message(self, from_port, encrypted_message, message_id):
        """Decrypt an incoming encrypted message - WITH CACHING"""
        # Check if already decrypted
        if message_id in self.decrypted_messages:
            return self.decrypted_messages[message_id]
        
        # Check if we have quantum security
        if not self.quantum_manager.is_secure_channel_established(from_port):
            return "[Encrypted - No Quantum Key]"
        
        # Decrypt the message
        decrypted_message = self.quantum_manager.decrypt_message(from_port, encrypted_message)
        if decrypted_message:
            # Cache the decrypted message
            self.decrypted_messages[message_id] = decrypted_message
            return decrypted_message
        else:
            return "[Quantum Decryption Failed]"
    
    def get_messages(self, to_port, since_message_id=None):
        """Get messages - only new ones if since_message_id is provided"""
        try:
            # Build URL with optional since parameter
            url = f"{CENTRAL_SERVER}/get_messages/{self.user_port}/{to_port}"
            if since_message_id:
                url += f"?since={since_message_id}"
            
            response = requests.get(url, timeout=5)
            messages = response.json()
            
            # Update last message ID for this conversation
            if messages:
                latest_message_id = messages[-1].get('id')
                if latest_message_id:
                    self.last_message_ids[to_port] = latest_message_id
            
            # Process messages with caching
            for message in messages:
                message_id = message.get('id')
                from_port = message.get('from_port')
                
                if message.get('type') == 'encrypted_text' and message.get('quantum_encrypted'):
                    # Check if this is a message WE sent
                    if from_port == self.user_port:
                        # This is our own sent message - use stored original
                        if message_id in self.sent_messages:
                            original_message = self.sent_messages[message_id]
                            message['decrypted_content'] = original_message
                            message['display_message'] = f"🔒 {original_message}"
                        else:
                            # Fallback: show as encrypted (we sent it)
                            message['display_message'] = "🔒 [Encrypted Message You Sent]"
                    else:
                        # This is a message FROM someone else - try to decrypt
                        decrypted_content = self.receive_encrypted_message(
                            from_port, 
                            message['message'],
                            message_id
                        )
                        message['decrypted_content'] = decrypted_content
                        message['display_message'] = f"🔒 {decrypted_content}"
                else:
                    # Regular unencrypted message
                    message['display_message'] = message['message']
            
            return messages
        except Exception as e:
            print(f"❌ Get messages error for {self.username}: {e}")
            return []
    
    def get_new_messages_only(self, to_port):
        """Get only new messages since last check"""
        last_message_id = self.last_message_ids.get(to_port)
        return self.get_messages(to_port, since_message_id=last_message_id)
    
    def send_heartbeat(self):
        try:
            self.last_active = datetime.now()
            requests.get(f"{CENTRAL_SERVER}/heartbeat/{self.user_port}", timeout=3)
        except:
            pass
    
    def get_quantum_status(self, target_port=None):
        """Get quantum security status"""
        return self.quantum_manager.get_quantum_status(target_port)
    
    def get_key_management_data(self, admin_access=False):
        """Get comprehensive key management data"""
        return self.quantum_manager.get_key_management_data(admin_access)
    
    def delete_quantum_session(self, session_id):
        """Delete a quantum session"""
        return self.quantum_manager.delete_quantum_session(session_id)

# Global storage for all user sessions
user_sessions = {}
permanent_port_assignments = {}
active_sessions = {}
MIN_PORT = 2000
MAX_PORT = 3000

def get_available_port():
    """Find an available port that has NEVER been assigned before"""
    for port in range(MIN_PORT, MAX_PORT + 1):
        port_str = str(port)
        if port_str not in permanent_port_assignments:
            return port
    return None

def get_user_session():
    """Get the current user's session"""
    session_id = session.get('session_id')
    if session_id and session_id in user_sessions:
        user_session = user_sessions[session_id]
        user_session.last_active = datetime.now()
        return user_session
    return None

def is_admin_authenticated():
    """Check if user is authenticated as admin"""
    return session.get('admin_authenticated', False)

def get_admin_username():
    """Get admin username from session"""
    return session.get('admin_username')
    

@app.route('/quantum_decrypter')
def quantum_decrypter():
    """Standalone quantum message decrypter tool"""
    return render_template('quantum_decrypter.html')

@app.route('/api/quantum/decrypt_message', methods=['POST'])
def api_quantum_decrypt_message():
    """API endpoint to decrypt quantum messages"""
    try:
        data = request.json
        encrypted_message_b64 = data.get('encrypted_message')
        quantum_key_hex = data.get('quantum_key')
        
        if not encrypted_message_b64 or not quantum_key_hex:
            return jsonify({'status': 'error', 'message': 'Missing encrypted message or quantum key'})
        
        # Convert hex key to bytes
        quantum_key_bytes = bytes.fromhex(quantum_key_hex)
        
        # Create Fernet object from quantum key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'quantum_secure_chat',
            iterations=100000,
        )
        fernet_key = base64.urlsafe_b64encode(kdf.derive(quantum_key_bytes))
        fernet = Fernet(fernet_key)
        
        # Decrypt the message
        encrypted_bytes = base64.b64decode(encrypted_message_b64)
        decrypted_bytes = fernet.decrypt(encrypted_bytes)
        decrypted_message = decrypted_bytes.decode('utf-8')
        
        return jsonify({
            'status': 'success',
            'decrypted_message': decrypted_message,
            'message_length': len(decrypted_message)
        })
        
    except Exception as e:
        print(f"❌ Decryption error: {e}")
        return jsonify({
            'status': 'error', 
            'message': f'Decryption failed: {str(e)}'
        })
    
    

# Admin Authentication Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == password:
            session['admin_authenticated'] = True
            session['admin_username'] = username
            session['admin_login_time'] = datetime.now().isoformat()
            print(f"🔐 Admin logged in: {username}")
            return redirect(url_for('admin_key_management'))
        else:
            return render_template('admin2_login.html', error='Invalid admin credentials')
    
    return render_template('admin2_login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.pop('admin_authenticated', None)
    session.pop('admin_username', None)
    session.pop('admin_login_time', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/key_management')
def admin_key_management():
    """Admin-only key management interface"""
    if not is_admin_authenticated():
        return redirect(url_for('admin_login'))
    
    return render_template('admin_key_management.html',
                         admin_username=get_admin_username(),
                         login_time=session.get('admin_login_time'))

@app.route('/quantum_dashboard')
def quantum_dashboard():
    """Quantum security dashboard - Regular user access"""
    user_session = get_user_session()
    if not user_session:
        return redirect(url_for('login'))
    
    return render_template('quantum_dashboard.html',
                         username=user_session.username,
                         user_port=user_session.user_port,
                         quantum_status=user_session.get_quantum_status())

@app.route('/key_management')
def key_management():
    """Regular user key management interface - Limited access"""
    user_session = get_user_session()
    if not user_session:
        return redirect(url_for('login'))
    
    key_data = user_session.get_key_management_data(admin_access=False)
    
    return render_template('key_management.html',
                         username=user_session.username,
                         user_port=user_session.user_port,
                         key_data=key_data)

@app.route('/')
def index():
    if get_user_session():
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        port_choice = request.form.get('port')
        
        if username:
            user_port = None
            
            if port_choice:
                try:
                    user_port = int(port_choice)
                    if user_port < MIN_PORT or user_port > MAX_PORT:
                        return render_template('login.html', 
                                            error=f"Port must be between {MIN_PORT} and {MAX_PORT}")
                    
                    port_str = str(user_port)
                    
                    if port_str in permanent_port_assignments:
                        assigned_username = permanent_port_assignments[port_str]
                        if assigned_username != username:
                            return render_template('login.html', 
                                                error=f"Port {user_port} is permanently assigned. Choose another port.")
                    else:
                        permanent_port_assignments[port_str] = username
                        
                except ValueError:
                    return render_template('login.html', 
                                        error="Please enter a valid port number")
            else:
                user_port = get_available_port()
                if not user_port:
                    return render_template('login.html', 
                                        error="No available ports. Please try again later.")
                
                port_str = str(user_port)
                permanent_port_assignments[port_str] = username
            
            if username in active_sessions:
                old_session_id = active_sessions[username]
                if old_session_id in user_sessions:
                    del user_sessions[old_session_id]
                del active_sessions[username]
            
            session_id = os.urandom(16).hex()
            user_session = UserSession(username, user_port, session_id)
            
            result = user_session.register_with_central()
            
            if result.get('status') == 'success':
                user_sessions[session_id] = user_session
                active_sessions[username] = session_id
                
                session['session_id'] = session_id
                session['username'] = username
                session['user_port'] = user_port
                
                print(f"✅ User logged in: {username} on port {user_port}")
                return redirect(url_for('chat'))
            else:
                port_str = str(user_port)
                if port_str in permanent_port_assignments and permanent_port_assignments[port_str] == username:
                    del permanent_port_assignments[port_str]
                return render_template('login.html', 
                                    error="Cannot connect to central server. Make sure it's running!")
    
    used_ports = len(permanent_port_assignments)
    available_ports = (MAX_PORT - MIN_PORT + 1) - used_ports
    return render_template('login.html', available_ports=available_ports)

@app.route('/chat')
def chat():
    user_session = get_user_session()
    if not user_session:
        return redirect(url_for('login'))
    
    return render_template('chat.html', 
                         user_port=user_session.user_port,
                         username=user_session.username)

# API ROUTES
@app.route('/api/users')
def api_users():
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        users_data = user_session.get_all_users()
        current_port = user_session.user_port
        if current_port in users_data:
            del users_data[current_port]
        
        for port, user_info in users_data.items():
            user_info['quantum_secure'] = user_session.quantum_manager.is_secure_channel_established(port)
        
        user_session.send_heartbeat()
        return jsonify(users_data)
    except Exception as e:
        print(f"❌ API users error: {e}")
        return jsonify({})

@app.route('/api/messages/<to_port>')
def api_messages(to_port):
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get ALL messages (first load or refresh)
    messages = user_session.get_messages(to_port)
    user_session.send_heartbeat()
    return jsonify(messages)

@app.route('/api/messages/<to_port>/new')
def api_new_messages(to_port):
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get ONLY new messages since last check
    messages = user_session.get_new_messages_only(to_port)
    user_session.send_heartbeat()
    return jsonify(messages)

@app.route('/api/send_message', methods=['POST'])
def api_send_message():
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    to_port = request.json.get('to_port')
    message = request.json.get('message')
    message_type = request.json.get('type', 'text')
    file_data = request.json.get('file_data')
    file_name = request.json.get('file_name')
    file_size = request.json.get('file_size')
    use_quantum = request.json.get('use_quantum', False)
    
    if use_quantum and message_type == 'text':
        result = user_session.send_encrypted_message(to_port, message)
    else:
        result = user_session.send_message(to_port, message, message_type, file_data, file_name, file_size)
    
    user_session.send_heartbeat()
    return jsonify(result)

# QUANTUM SECURITY API ROUTES
@app.route('/api/enable_quantum', methods=['POST'])
def api_enable_quantum():
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    target_port = request.json.get('target_port')
    success = user_session.quantum_manager.establish_secure_channel(target_port)
    
    if success:
        session_id = user_session.quantum_manager.get_session_id(user_session.user_port, target_port)
        return jsonify({
            'status': 'success', 
            'message': 'Quantum security enabled',
            'session_id': session_id
        })
    else:
        return jsonify({'status': 'error', 'message': 'Failed to enable quantum security'})

@app.route('/api/quantum_status')
def api_quantum_status():
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    target_port = request.args.get('target_port')
    status_data = user_session.get_quantum_status(target_port)
    
    return jsonify(status_data)

@app.route('/api/check_quantum_key/<target_port>')
def api_check_quantum_key(target_port):
    """Check if quantum key exists for a specific user"""
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    session_id = user_session.quantum_manager.get_session_id(user_session.user_port, target_port)
    existing_key = user_session.quantum_manager.is_secure_channel_established(target_port)
    
    return jsonify({
        'key_exists': existing_key,
        'session_id': session_id,
        'secure_channel': existing_key
    })

# KEY MANAGEMENT API ROUTES - REGULAR USER
@app.route('/api/key_management/data')
def api_key_management_data():
    """Get comprehensive key management data - Regular user access"""
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    key_data = user_session.get_key_management_data(admin_access=False)
    return jsonify(key_data)

# ADMIN KEY MANAGEMENT API ROUTES
@app.route('/api/admin/key_management/data')
def api_admin_key_management_data():
    """Get comprehensive key management data - Admin access only"""
    if not is_admin_authenticated():
        return jsonify({'error': 'Admin authentication required'}), 403
    
    # For admin, we need to get data from ALL user sessions
    all_sessions_data = []
    total_statistics = {
        'total_keys_generated': 0,
        'active_sessions': 0,
        'failed_key_exchanges': 0,
        'successful_key_exchanges': 0,
        'total_users': len(user_sessions)
    }
    
    for session_id, user_session in user_sessions.items():
        user_key_data = user_session.get_key_management_data(admin_access=True)
        all_sessions_data.extend(user_key_data['sessions'])
        
        # Aggregate statistics
        for key, value in user_key_data['statistics'].items():
            if key in total_statistics:
                total_statistics[key] += value
    
    return jsonify({
        'sessions': all_sessions_data,
        'statistics': total_statistics,
        'total_sessions': len(all_sessions_data),
        'admin_access': True,
        'admin_username': get_admin_username()
    })

@app.route('/api/admin/key_management/delete_session', methods=['POST'])
def api_admin_delete_quantum_session():
    """Delete a quantum session - Admin access only"""
    if not is_admin_authenticated():
        return jsonify({'error': 'Admin authentication required'}), 403
    
    session_id = request.json.get('session_id')
    target_user = request.json.get('target_user')
    
    # Find and delete session from appropriate user
    for user_session in user_sessions.values():
        if user_session.user_port == target_user or target_user in [s.user1_port for s in user_session.quantum_manager.key_manager.get_all_sessions().values()]:
            success = user_session.delete_quantum_session(session_id)
            if success:
                return jsonify({'status': 'success', 'message': 'Quantum session deleted'})
    
    return jsonify({'status': 'error', 'message': 'Session not found'})

@app.route('/api/admin/key_management/refresh_session', methods=['POST'])
def api_admin_refresh_quantum_session():
    """Refresh/regenerate quantum key for a session - Admin access only"""
    if not is_admin_authenticated():
        return jsonify({'error': 'Admin authentication required'}), 403
    
    session_id = request.json.get('session_id')
    target_port = request.json.get('target_port')
    
    # Find the appropriate user session
    for user_session in user_sessions.values():
        if user_session.quantum_manager.get_session_id(user_session.user_port, target_port) == session_id:
            # Delete existing session
            user_session.delete_quantum_session(session_id)
            
            # Re-establish quantum security
            success = user_session.quantum_manager.establish_secure_channel(target_port)
            
            if success:
                return jsonify({'status': 'success', 'message': 'Quantum session refreshed'})
            else:
                return jsonify({'status': 'error', 'message': 'Failed to refresh session'})
    
    return jsonify({'status': 'error', 'message': 'Session not found'})

@app.route('/api/admin/system_status')
def api_admin_system_status():
    """Get system-wide status - Admin access only"""
    if not is_admin_authenticated():
        return jsonify({'error': 'Admin authentication required'}), 403
    
    system_status = {
        'total_users': len(user_sessions),
        'active_ports': list(permanent_port_assignments.keys()),
        'server_uptime': time.time() - start_time if 'start_time' in globals() else 0,
        'admin_online': True,
        'current_time': datetime.now().isoformat()
    }
    
    return jsonify(system_status)

@app.route('/api/key_management/delete_session', methods=['POST'])
def api_delete_quantum_session():
    """Delete a quantum session - Regular user"""
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    session_id = request.json.get('session_id')
    success = user_session.delete_quantum_session(session_id)
    
    if success:
        return jsonify({'status': 'success', 'message': 'Quantum session deleted'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to delete session'})

@app.route('/api/key_management/refresh_session', methods=['POST'])
def api_refresh_quantum_session():
    """Refresh/regenerate quantum key for a session - Regular user"""
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    session_id = request.json.get('session_id')
    target_port = request.json.get('target_port')
    
    # Delete existing session
    user_session.delete_quantum_session(session_id)
    
    # Re-establish quantum security
    success = user_session.quantum_manager.establish_secure_channel(target_port)
    
    if success:
        return jsonify({'status': 'success', 'message': 'Quantum session refreshed'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to refresh session'})

@app.route('/api/heartbeat')
def api_heartbeat():
    user_session = get_user_session()
    if user_session:
        user_session.send_heartbeat()
    return jsonify({'status': 'ok'})

@app.route('/file/<file_type>/<filename>')
def serve_file(file_type, filename):
    """Proxy file requests through user client"""
    try:
        response = requests.get(f"{CENTRAL_SERVER}/download/{file_type}/{filename}")
        if response.status_code == 200:
            return response.content, 200, {'Content-Type': response.headers.get('Content-Type')}
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        print(f"❌ File serve error: {e}")
        return jsonify({'error': 'File service unavailable'}), 503

@app.route('/logout')
def logout():
    user_session = get_user_session()
    if user_session:
        session_id = session.get('session_id')
        user_port = user_session.user_port
        username = user_session.username
        
        if username in active_sessions:
            del active_sessions[username]
        
        if session_id in user_sessions:
            del user_sessions[session_id]
    
    session.clear()
    return redirect(url_for('login'))

# Store server start time
start_time = time.time()

def run_user_server(port=4545):
    print(f"🚀 Starting QUANTUM SECURE Multi-User Talk'n'Go on port {port}")
    print(f"🔐 Quantum Security: OPTIMIZED - One-time key establishment")
    print(f"💾 Local Key Caching: ENABLED")
    print(f"📡 Central server: {CENTRAL_SERVER}")
    print(f"🔑 Key Management: ADMIN-RESTRICTED - Professional access control")
    print(f"👑 Admin Access: http://localhost:{port}/admin/login")
    print(f"🌐 User Access: http://localhost:{port}")
    print("\n" + "="*50)
    print("🔐 ADMIN CREDENTIALS:")
    print("   Username: admin | Password: quantumsecure123")
    print("   Username: supervisor | Password: monitor456")
    print("="*50)
    
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    port = 4545
    if len(sys.argv) == 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("❌ Invalid port number. Using default port 4545.")
    
    def open_browser():
        time.sleep(2)
        webbrowser.open(f'http://localhost:{port}')
    
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    run_user_server(port)
