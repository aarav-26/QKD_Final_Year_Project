"""
Quantum Key Server for managing quantum key exchange sessions
"""

import time
import hashlib
from datetime import datetime
from threading import Lock

class QuantumKeyServer:
    """
    Server-side quantum key session manager
    """
    
    def __init__(self):
        self.sessions = {}  # session_id -> session_data
        self.session_lock = Lock()
    
    def init_key_exchange(self, user1_port, user2_port):
        """
        Initialize a quantum key exchange session between two users
        
        Args:
            user1_port: Port of first user
            user2_port: Port of second user
            
        Returns:
            str: Session ID
        """
        with self.session_lock:
            # Create unique session ID
            session_id = hashlib.sha256(
                f"{user1_port}_{user2_port}_{datetime.now().timestamp()}".encode()
            ).hexdigest()[:16]
            
            # Initialize session
            self.sessions[session_id] = {
                'user1_port': str(user1_port),
                'user2_port': str(user2_port),
                'status': 'initiated',
                'created_at': datetime.now(),
                'quantum_key': None,
                'key_ready': False,
                'last_updated': datetime.now()
            }
            
            return session_id
    
    def store_session_key(self, session_id, quantum_key):
        """
        Store quantum key for a session
        
        Args:
            session_id: Session identifier
            quantum_key: The established quantum key
            
        Returns:
            bool: True if successful, False otherwise
        """
        with self.session_lock:
            if session_id in self.sessions:
                self.sessions[session_id].update({
                    'quantum_key': quantum_key,
                    'key_ready': True,
                    'completed_at': datetime.now(),
                    'last_updated': datetime.now()
                })
                return True
            return False
    
    def get_session_key(self, session_id):
        """
        Get quantum key for a session
        
        Args:
            session_id: Session identifier
            
        Returns:
            str: Quantum key if ready, None otherwise
        """
        with self.session_lock:
            session = self.sessions.get(session_id)
            if session and session.get('key_ready'):
                return session.get('quantum_key')
            return None
    
    def get_session_status(self, session_id):
        """
        Get status of a quantum session
        
        Args:
            session_id: Session identifier
            
        Returns:
            dict: Session status information
        """
        with self.session_lock:
            session = self.sessions.get(session_id)
            if session:
                return {
                    'status': session['status'],
                    'key_ready': session['key_ready'],
                    'users': [session['user1_port'], session['user2_port']],
                    'created_at': session['created_at'].isoformat(),
                    'last_updated': session['last_updated'].isoformat()
                }
            return None
    
    def get_all_sessions(self):
        """
        Get all active quantum sessions
        
        Returns:
            dict: All sessions data
        """
        with self.session_lock:
            return self.sessions.copy()
    
    def get_active_sessions(self):
        """
        Get only active (key-ready) quantum sessions
        
        Returns:
            dict: Active sessions only
        """
        with self.session_lock:
            return {
                session_id: session_data
                for session_id, session_data in self.sessions.items()
                if session_data.get('key_ready', False)
            }
    
    def cleanup_old_sessions(self, max_age_hours=24):
        """
        Clean up old quantum sessions
        
        Args:
            max_age_hours: Maximum age of sessions in hours
        """
        with self.session_lock:
            current_time = datetime.now()
            expired_sessions = []
            
            for session_id, session_data in self.sessions.items():
                session_age = current_time - session_data['last_updated']
                if session_age.total_seconds() > max_age_hours * 3600:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                del self.sessions[session_id]
            
            return len(expired_sessions)
    
    def get_statistics(self):
        """
        Get quantum server statistics
        
        Returns:
            dict: Statistics data
        """
        with self.session_lock:
            total_sessions = len(self.sessions)
            active_sessions = len([s for s in self.sessions.values() if s['key_ready']])
            pending_sessions = total_sessions - active_sessions
            
            return {
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'pending_sessions': pending_sessions,
                'oldest_session': min(
                    [s['created_at'] for s in self.sessions.values()], 
                    default=datetime.now()
                ).isoformat()
            }
