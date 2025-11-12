from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests
import threading
import webbrowser
import time
import os
import sys

# Generate unique secret key for each instance
def generate_secret_key():
    return os.urandom(24).hex()

app = Flask(__name__)
app.secret_key = generate_secret_key()  # Unique for each instance

# Central server URL
CENTRAL_SERVER = "http://localhost:5000"

class UserClient:
    def __init__(self, port, username):
        self.port = str(port)
        self.username = username
        self.server_url = f"http://localhost:{port}"
        print(f"👤 Created UserClient: {username} on port {port}")
    
    def register_with_central(self):
        try:
            print(f"🔗 Registering {self.username} with central server...")
            response = requests.post(f"{CENTRAL_SERVER}/register_user", json={
                'port': self.port,
                'username': self.username,
                'server_url': self.server_url
            }, timeout=5)
            result = response.json()
            print(f"🔗 Registration response: {result}")
            return result
        except requests.exceptions.ConnectionError:
            print("❌ Cannot connect to central server. Make sure it's running on port 5000!")
            return {'status': 'error', 'message': 'Cannot connect to central server'}
        except Exception as e:
            print(f"❌ Registration error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_all_users(self):
        try:
            response = requests.get(f"{CENTRAL_SERVER}/get_all_users", timeout=5)
            return response.json()
        except Exception as e:
            print(f"❌ Get users error: {e}")
            return {}
    
    def send_message(self, to_port, message):
        try:
            print(f"📤 {self.username} sending to {to_port}: {message}")
            response = requests.post(f"{CENTRAL_SERVER}/send_message", json={
                'from_port': self.port,
                'to_port': str(to_port),
                'message': message
            }, timeout=5)
            result = response.json()
            print(f"📤 Send result: {result}")
            return result
        except Exception as e:
            print(f"❌ Send message error: {e}")
            return {'status': 'error'}
    
    def get_messages(self, to_port):
        try:
            response = requests.get(f"{CENTRAL_SERVER}/get_messages/{self.port}/{to_port}", timeout=5)
            messages = response.json()
            return messages
        except Exception as e:
            print(f"❌ Get messages error: {e}")
            return []
    
    def send_heartbeat(self):
        try:
            requests.get(f"{CENTRAL_SERVER}/heartbeat/{self.port}", timeout=3)
        except:
            pass

# Store user clients by port
user_clients = {}

@app.route('/')
def index():
    if 'user_port' in session and 'username' in session:
        user_port = session['user_port']
        if user_port in user_clients:
            return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        port = request.form.get('port')
        username = request.form.get('username')
        
        if port and username:
            port = int(port)
            
            # Create and store user client
            user_client = UserClient(port, username)
            user_clients[port] = user_client
            
            # Register with central server
            result = user_client.register_with_central()
            
            if result.get('status') == 'success':
                # Store in session
                session['user_port'] = port
                session['username'] = username
                print(f"✅ Login successful: {username} on port {port}")
                return redirect(url_for('chat'))
            else:
                # Remove from clients if registration failed
                if port in user_clients:
                    del user_clients[port]
                return render_template('login.html', error="Cannot connect to central server. Make sure it's running on port 5000!")
    
    return render_template('login.html')

@app.route('/chat')
def chat():
    user_port = session.get('user_port')
    username = session.get('username')
    
    if not user_port or user_port not in user_clients:
        print(f"❌ Chat access denied for port {user_port}")
        return redirect(url_for('login'))
    
    print(f"🎯 Rendering chat for {username} on port {user_port}")
    return render_template('chat.html', 
                         user_port=user_port,
                         username=username)

@app.route('/api/users')
def api_users():
    user_port = session.get('user_port')
    if not user_port or user_port not in user_clients:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_client = user_clients[user_port]
    try:
        users_data = user_client.get_all_users()
        print(f"📋 {user_client.username} fetching users, found: {list(users_data.keys())}")
        
        # Remove current user from the list
        current_port = str(user_port)
        if current_port in users_data:
            del users_data[current_port]
        
        return jsonify(users_data)
    except Exception as e:
        print(f"❌ API users error for {user_client.username}: {e}")
        return jsonify({})

@app.route('/api/messages/<to_port>')
def api_messages(to_port):
    user_port = session.get('user_port')
    if not user_port or user_port not in user_clients:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_client = user_clients[user_port]
    messages = user_client.get_messages(to_port)
    print(f"📨 {user_client.username} fetching messages with {to_port}, found {len(messages)} messages")
    return jsonify(messages)

@app.route('/api/send_message', methods=['POST'])
def api_send_message():
    user_port = session.get('user_port')
    if not user_port or user_port not in user_clients:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_client = user_clients[user_port]
    to_port = request.json.get('to_port')
    message = request.json.get('message')
    
    result = user_client.send_message(to_port, message)
    return jsonify(result)

@app.route('/api/heartbeat')
def api_heartbeat():
    user_port = session.get('user_port')
    if user_port and user_port in user_clients:
        user_clients[user_port].send_heartbeat()
    return jsonify({'status': 'ok'})

@app.route('/debug')
def debug():
    user_port = session.get('user_port')
    return jsonify({
        'session': dict(session),
        'user_client_ports': list(user_clients.keys()),
        'current_user_client': user_clients[user_port].username if user_port in user_clients else None,
        'total_clients': len(user_clients)
    })

@app.route('/logout')
def logout():
    user_port = session.get('user_port')
    if user_port and user_port in user_clients:
        print(f"👋 Logging out {user_clients[user_port].username}")
        del user_clients[user_port]
    session.clear()
    return redirect(url_for('login'))

def run_user_server(port):
    print(f"🚀 Starting User Server on port {port}")
    print(f"🌐 Access at: http://localhost:{port}")
    print(f"🔑 Secret key: {app.secret_key[:10]}...")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

def start_heartbeat():
    def heartbeat_loop():
        while True:
            time.sleep(10)
            for user_client in user_clients.values():
                user_client.send_heartbeat()
    
    thread = threading.Thread(target=heartbeat_loop)
    thread.daemon = True
    thread.start()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python user_client.py <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    
    # Start heartbeat thread
    start_heartbeat()
    
    # Open browser after a short delay
    def open_browser():
        time.sleep(3)
        webbrowser.open(f'http://localhost:{port}')
    
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    run_user_server(port)
