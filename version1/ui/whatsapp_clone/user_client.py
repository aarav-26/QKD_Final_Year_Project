from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests
import threading
import webbrowser
import time
import os
import sys
import base64
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# Central server URL
CENTRAL_SERVER = "http://localhost:5000"

class UserSession:
    def __init__(self, username, user_port, session_id):
        self.username = username
        self.user_port = str(user_port)
        self.session_id = session_id
        self.last_active = datetime.now()
        self.is_active = True
    
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
    
    def send_message(self, to_port, message, message_type='text', file_data=None, file_name=None, file_size=None):
        try:
            payload = {
                'from_port': self.user_port,
                'to_port': str(to_port),
                'message': message,
                'type': message_type
            }
            
            if message_type in ['image', 'file'] and file_data:
                payload['file_data'] = file_data
                payload['file_name'] = file_name
                payload['file_size'] = file_size
            
            response = requests.post(f"{CENTRAL_SERVER}/send_message", json=payload, timeout=10)
            return response.json()
        except Exception as e:
            print(f"❌ Send message error for {self.username}: {e}")
            return {'status': 'error'}
    
    def get_messages(self, to_port):
        try:
            response = requests.get(f"{CENTRAL_SERVER}/get_messages/{self.user_port}/{to_port}", timeout=5)
            return response.json()
        except Exception as e:
            print(f"❌ Get messages error for {self.username}: {e}")
            return []
    
    def send_heartbeat(self):
        try:
            self.last_active = datetime.now()
            requests.get(f"{CENTRAL_SERVER}/heartbeat/{self.user_port}", timeout=3)
        except:
            pass

# Global storage for all user sessions
user_sessions = {}  # {session_id: UserSession}
permanent_port_assignments = {}  # {port: username} - PERMANENT assignment
active_sessions = {}  # {username: session_id} - Track currently active users
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
        user_session.last_active = datetime.now()  # Update activity
        return user_session
    return None

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
                # User specified a port
                try:
                    user_port = int(port_choice)
                    if user_port < MIN_PORT or user_port > MAX_PORT:
                        return render_template('login.html', 
                                            error=f"Port must be between {MIN_PORT} and {MAX_PORT}")
                    
                    port_str = str(user_port)
                    
                    # Check if port is permanently assigned to someone else
                    if port_str in permanent_port_assignments:
                        assigned_username = permanent_port_assignments[port_str]
                        if assigned_username != username:
                            return render_template('login.html', 
                                                error=f"Port {user_port} is permanently assigned. Choose another port.")
                        else:
                            # User is reclaiming their own port
                            print(f"🔄 User {username} reclaiming their permanent port {user_port}")
                    else:
                        # Assign port permanently to this user
                        permanent_port_assignments[port_str] = username
                        print(f"🔐 Port {user_port} permanently assigned to {username}")
                        
                except ValueError:
                    return render_template('login.html', 
                                        error="Please enter a valid port number")
            else:
                # Auto-assign a port (find one that's never been used)
                user_port = get_available_port()
                if not user_port:
                    return render_template('login.html', 
                                        error="No available ports. Please try again later.")
                
                # Assign port permanently to this user
                port_str = str(user_port)
                permanent_port_assignments[port_str] = username
                print(f"🔐 Port {user_port} permanently assigned to {username}")
            
            # Check if user already has an active session
            if username in active_sessions:
                # User is already logged in elsewhere, remove old session
                old_session_id = active_sessions[username]
                if old_session_id in user_sessions:
                    del user_sessions[old_session_id]
                del active_sessions[username]
                print(f"🔁 Terminated previous session for {username}")
            
            # Generate unique session ID
            session_id = os.urandom(16).hex()
            
            # Create user session
            user_session = UserSession(username, user_port, session_id)
            
            # Register with central server
            result = user_session.register_with_central()
            
            if result.get('status') == 'success':
                # Store session
                user_sessions[session_id] = user_session
                active_sessions[username] = session_id
                
                # Store in Flask session
                session['session_id'] = session_id
                session['username'] = username
                session['user_port'] = user_port
                
                print(f"✅ User logged in: {username} on port {user_port}")
                print(f"📊 Active users: {list(active_sessions.keys())}")
                print(f"🔢 Permanent port assignments: {permanent_port_assignments}")
                
                return redirect(url_for('chat'))
            else:
                # Registration failed, free the port if it was newly assigned
                port_str = str(user_port)
                if port_str in permanent_port_assignments and permanent_port_assignments[port_str] == username:
                    del permanent_port_assignments[port_str]
                return render_template('login.html', 
                                    error="Cannot connect to central server. Make sure it's running!")
    
    # Show available port count on login page
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

@app.route('/api/users')
def api_users():
    user_session = get_user_session()
    if not user_session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        users_data = user_session.get_all_users()
        # Remove current user from the list
        current_port = user_session.user_port
        if current_port in users_data:
            del users_data[current_port]
        
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
    
    messages = user_session.get_messages(to_port)
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
    
    result = user_session.send_message(to_port, message, message_type, file_data, file_name, file_size)
    user_session.send_heartbeat()
    return jsonify(result)

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
        
        # Remove from active sessions but KEEP permanent port assignment
        if username in active_sessions:
            del active_sessions[username]
        
        if session_id in user_sessions:
            del user_sessions[session_id]
        
        print(f"👋 User logged out: {username} (port {user_port} remains permanently assigned)")
        print(f"📊 Remaining active users: {list(active_sessions.keys())}")
        print(f"🔢 Permanent port assignments: {permanent_port_assignments}")
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/status')
def status():
    """Admin page to see current users"""
    user_session = get_user_session()
    if not user_session:
        return redirect(url_for('login'))
    
    status_info = {
        'active_users': list(active_sessions.keys()),
        'permanent_assignments': permanent_port_assignments,
        'available_ports': (MAX_PORT - MIN_PORT + 1) - len(permanent_port_assignments),
        'current_user': {
            'username': user_session.username,
            'port': user_session.user_port,
        }
    }
    return jsonify(status_info)

def run_user_server(port=4545):
    print(f"🚀 Starting Multi-User Talk'n'Go on port {port}")
    print(f"🔑 Session key: {app.secret_key[:10]}...")
    print(f"📡 Central server: {CENTRAL_SERVER}")
    print(f"🎯 Port range: {MIN_PORT}-{MAX_PORT}")
    print(f"🔐 PERMANENT PORT ASSIGNMENT: Ports are never reused")
    print(f"👥 Multiple users can register simultaneously")
    print(f"🌐 Access URL: http://localhost:{port}")
    print(f"🌐 Network URL: http://[your-ip]:{port}")
    print("\n" + "="*50)
    
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    # Use port 4545 by default, or allow override
    port = 4545
    if len(sys.argv) == 2:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("❌ Invalid port number. Using default port 4545.")
    
    # Open browser after a short delay
    def open_browser():
        time.sleep(2)
        webbrowser.open(f'http://localhost:{port}')
    
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    run_user_server(port)
