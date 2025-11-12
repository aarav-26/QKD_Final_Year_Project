from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
from datetime import datetime
import os
import base64
import uuid
import hashlib

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
IMAGE_FOLDER = os.path.join(UPLOAD_FOLDER, 'images')
FILE_FOLDER = os.path.join(UPLOAD_FOLDER, 'files')
TEMP_FOLDER = os.path.join(UPLOAD_FOLDER, 'temp')

# Create directories if they don't exist
os.makedirs(IMAGE_FOLDER, exist_ok=True)
os.makedirs(FILE_FOLDER, exist_ok=True)
os.makedirs(TEMP_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Central storage for all users and messages
users = {}
messages = {}
quantum_sessions = {}  # Store quantum key exchange sessions

# Monitoring system - SINGLE CONTAINER
monitoring_messages = []  # Store all monitoring messages
MAX_MONITORING_MESSAGES = 5000  # Increased limit for scrolling

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "quantumsecure123"

def get_session_id(user1_port, user2_port):
    """Generate consistent session ID in ascending order as simple string"""
    if user1_port == user2_port:
        print(f"❌ ERROR: Cannot create session with same port: {user1_port}")
        return None
        
    ports = sorted([int(user1_port), int(user2_port)])
    session_id = f"{ports[0]}{ports[1]}"
    return session_id

def add_to_monitoring_log(message_data):
    """Add message to monitoring system"""
    monitoring_entry = {
        'id': message_data['id'],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'from_user': users.get(message_data['from_port'], {}).get('username', 'Unknown'),
        'from_port': message_data['from_port'],
        'to_user': users.get(message_data['to_port'], {}).get('username', 'Unknown'),
        'to_port': message_data['to_port'],
        'message_type': message_data['type'],
        'message_content': message_data['message'],
        'quantum_encrypted': message_data.get('quantum_encrypted', False),
        'file_name': message_data.get('file_name'),
        'file_size': message_data.get('file_size'),
        'session_id': message_data.get('session_id'),
        'full_content': message_data['message']  # Store full content for expansion
    }
    
    # Add to monitoring messages
    monitoring_messages.append(monitoring_entry)
    
    # Keep only the last MAX_MONITORING_MESSAGES entries
    if len(monitoring_messages) > MAX_MONITORING_MESSAGES:
        monitoring_messages.pop(0)

@app.route('/')
def home():
    return jsonify({
        'message': 'WhatsApp Clone Central Server - QUANTUM SECURE',
        'status': 'running',
        'users_count': len(users),
        'online_users': len([u for u in users.values() if u['online']]),
        'quantum_sessions': len(quantum_sessions),
        'active_quantum_channels': len([s for s in quantum_sessions.values() if s['key_ready']])
    })

@app.route('/register_user', methods=['POST'])
def register_user():
    try:
        data = request.json
        port = str(data['port'])
        username = data['username']
        server_url = data['server_url']
        
        users[port] = {
            'username': username,
            'server_url': server_url,
            'online': True,
            'last_seen': datetime.now(),
            'port': port,
            'quantum_capable': True
        }
        
        print(f"✅ User registered: {username} on port {port}")
        print(f"📊 Total users: {len(users)}")
        
        return jsonify({'status': 'success', 'message': 'User registered successfully'})
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/get_all_users')
def get_all_users():
    # Update online status based on last seen (1 minute timeout)
    current_time = datetime.now()
    for port, user in users.items():
        time_diff = (current_time - user['last_seen']).total_seconds()
        user['online'] = time_diff < 60  # 1 minute timeout
    
    return jsonify(users)

@app.route('/send_message', methods=['POST'])
def send_message():
    try:
        data = request.json
        from_port = str(data['from_port'])
        to_port = str(data['to_port'])
        message_text = data['message']
        message_type = data.get('type', 'text')  # text, image, file, encrypted_text
        file_data = data.get('file_data')
        file_name = data.get('file_name')
        file_size = data.get('file_size')
        is_quantum_encrypted = data.get('quantum_encrypted', False)
        
        # Validate users exist
        if from_port not in users:
            return jsonify({'status': 'error', 'message': 'Sender not found'}), 404
        if to_port not in users:
            return jsonify({'status': 'error', 'message': 'Recipient not found'}), 404
        
        # Create consistent conversation key using ascending order
        session_id = get_session_id(from_port, to_port)
        if not session_id:
            return jsonify({'status': 'error', 'message': 'Invalid session (same ports)'}), 400
            
        key = f"{session_id}"  # Use the session ID as conversation key
        
        if key not in messages:
            messages[key] = []
        
        message_id = str(uuid.uuid4())
        
        # Handle file uploads
        file_path = None
        if message_type in ['image', 'file'] and file_data:
            if message_type == 'image':
                file_path = save_base64_image(file_data, file_name, message_id)
            else:
                file_path = save_base64_file(file_data, file_name, message_id)
        
        message_data = {
            'id': message_id,
            'from_port': from_port,
            'to_port': to_port,
            'message': message_text,
            'type': message_type,
            'timestamp': datetime.now().strftime('%H:%M'),
            'date': datetime.now().strftime('%Y-%m-%d'),
            'file_name': file_name,
            'file_size': file_size,
            'file_path': file_path,
            'quantum_encrypted': is_quantum_encrypted,
            'session_id': session_id  # Include session ID in message
        }
        
        messages[key].append(message_data)
        
        # ADD TO MONITORING SYSTEM
        add_to_monitoring_log(message_data)
        
        from_user = users[from_port]['username']
        to_user = users[to_port]['username']
        
        # Enhanced logging with quantum status
        quantum_indicator = " 🔐" if is_quantum_encrypted else ""
        
        if message_type == 'text':
            print(f"💬 Message{quantum_indicator}: {from_user}({from_port}) → {to_user}({to_port}): {message_text[:50]}...")
        elif message_type == 'encrypted_text':
            print(f"🔒 Encrypted: {from_user}({from_port}) → {to_user}({to_port}): [QUANTUM SECURE]")
        elif message_type == 'image':
            print(f"🖼️  Image{quantum_indicator}: {from_user}({from_port}) → {to_user}({to_port}): {file_name}")
        elif message_type == 'file':
            print(f"📎 File{quantum_indicator}: {from_user}({from_port}) → {to_user}({to_port}): {file_name}")
        
        print(f"📁 Session: {session_id}, Total messages: {len(messages[key])}")
        
        return jsonify({'status': 'sent', 'message_id': message_id, 'session_id': session_id})
    except Exception as e:
        print(f"❌ Send message error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

def save_base64_image(base64_data, filename, message_id):
    """Save base64 image to file"""
    try:
        # Extract the base64 data (remove data:image/...;base64, prefix)
        if ',' in base64_data:
            base64_data = base64_data.split(',')[1]
        
        image_data = base64.b64decode(base64_data)
        
        # Generate unique filename
        file_extension = filename.split('.')[-1] if '.' in filename else 'png'
        unique_filename = f"{message_id}.{file_extension}"
        file_path = os.path.join(IMAGE_FOLDER, unique_filename)
        
        with open(file_path, 'wb') as f:
            f.write(image_data)
        
        return unique_filename
    except Exception as e:
        print(f"❌ Error saving image: {e}")
        return None

def save_base64_file(base64_data, filename, message_id):
    """Save base64 file to disk"""
    try:
        file_data = base64.b64decode(base64_data)
        
        # Keep original extension
        file_extension = filename.split('.')[-1] if '.' in filename else 'bin'
        unique_filename = f"{message_id}.{file_extension}"
        file_path = os.path.join(FILE_FOLDER, unique_filename)
        
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        return unique_filename
    except Exception as e:
        print(f"❌ Error saving file: {e}")
        return None

@app.route('/download/<file_type>/<filename>')
def download_file(file_type, filename):
    """Serve uploaded files"""
    try:
        if file_type == 'image':
            file_path = os.path.join(IMAGE_FOLDER, filename)
            mimetype = f'image/{filename.split(".")[-1]}'
        elif file_type == 'file':
            file_path = os.path.join(FILE_FOLDER, filename)
            mimetype = 'application/octet-stream'
        else:
            return jsonify({'error': 'Invalid file type'}), 400
        
        if os.path.exists(file_path):
            return send_file(file_path, mimetype=mimetype, as_attachment=False)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        print(f"❌ Download error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_messages/<from_port>/<to_port>')
def get_messages(from_port, to_port):
    try:
        # Use ascending session ID for message retrieval
        session_id = get_session_id(from_port, to_port)
        if not session_id:
            return jsonify([])
            
        key = f"{session_id}"
        
        # Get since parameter for incremental loading
        since_message_id = request.args.get('since')
        
        if key in messages:
            conversation_messages = messages[key]
            
            # Filter messages if since parameter is provided
            if since_message_id:
                # Find the index of the since_message_id
                since_index = -1
                for i, msg in enumerate(conversation_messages):
                    if msg.get('id') == since_message_id:
                        since_index = i
                        break
                
                # Return only messages after the since_message_id
                if since_index != -1 and since_index < len(conversation_messages) - 1:
                    conversation_messages = conversation_messages[since_index + 1:]
                else:
                    conversation_messages = []  # No new messages
            
            print(f"📩 Returning {len(conversation_messages)} messages for session {session_id}")
            return jsonify(conversation_messages)
        else:
            print(f"📭 No messages found for session {session_id}")
            return jsonify([])
    except Exception as e:
        print(f"❌ Get messages error: {e}")
        return jsonify([])

@app.route('/heartbeat/<port>')
def heartbeat(port):
    if port in users:
        users[port]['last_seen'] = datetime.now()
        users[port]['online'] = True
        return jsonify({'status': 'updated'})
    else:
        return jsonify({'status': 'user_not_found'}), 404

@app.route('/status')
def status():
    online_users = [u for u in users.values() if u['online']]
    active_quantum_sessions = len([s for s in quantum_sessions.values() if s['key_ready']])
    
    return jsonify({
        'server': 'running',
        'total_users': len(users),
        'online_users': len(online_users),
        'total_conversations': len(messages),
        'quantum_sessions': len(quantum_sessions),
        'active_quantum_channels': active_quantum_sessions,
        'users': [{'port': u['port'], 'username': u['username'], 'online': u['online']} for u in users.values()]
    })

# QUANTUM SECURITY ROUTES - OPTIMIZED
@app.route('/quantum/init_session', methods=['POST'])
def init_quantum_session():
    """Initialize quantum key exchange between two users - ONE TIME"""
    try:
        data = request.json
        user1_port = str(data['user1_port'])
        user2_port = str(data['user2_port'])
        
        # Validate users exist
        if user1_port not in users or user2_port not in users:
            return jsonify({'status': 'error', 'message': 'Users not found'}), 404
        
        # Create CONSISTENT session ID in ascending order
        session_id = get_session_id(user1_port, user2_port)
        if not session_id:
            return jsonify({'status': 'error', 'message': 'Invalid session (same ports)'}), 400
        
        # Check if session already exists WITH KEY
        if session_id in quantum_sessions and quantum_sessions[session_id]['key_ready']:
            print(f"✅ Existing quantum key FOUND for session: {session_id}")
            return jsonify({
                'session_id': session_id, 
                'status': 'key_exists',
                'key_ready': True,
                'message': 'Quantum key already exists for this session'
            })
        
        # Check if session exists but no key yet
        if session_id in quantum_sessions:
            print(f"🔁 Reusing existing quantum session: {user1_port} ↔ {user2_port}")
            session_status = 'session_exists'
        else:
            # Initialize new quantum session
            quantum_sessions[session_id] = {
                'user1_port': user1_port,
                'user2_port': user2_port,
                'status': 'initiated',
                'created_at': datetime.now(),
                'quantum_key': None,
                'key_ready': False,
                'key_generated_by': None,
                'last_accessed': datetime.now()
            }
            print(f"🔐 New quantum session: {user1_port} ↔ {user2_port} (Session: {session_id})")
            session_status = 'session_created'
        
        return jsonify({
            'session_id': session_id, 
            'status': session_status,
            'key_ready': False,
            'message': 'Quantum session ready for key exchange'
        })
    except Exception as e:
        print(f"❌ Quantum session init error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/quantum/check_key/<user1_port>/<user2_port>')
def check_quantum_key(user1_port, user2_port):
    """Check if quantum key already exists for a user pair - FAST CHECK"""
    try:
        session_id = get_session_id(user1_port, user2_port)
        if not session_id:
            return jsonify({'status': 'error', 'message': 'Invalid session'}), 400
        
        if session_id in quantum_sessions and quantum_sessions[session_id]['key_ready']:
            # Update last accessed time
            quantum_sessions[session_id]['last_accessed'] = datetime.now()
            return jsonify({
                'status': 'key_exists',
                'session_id': session_id,
                'key_ready': True,
                'message': 'Quantum key already available'
            })
        else:
            return jsonify({
                'status': 'key_not_found', 
                'session_id': session_id,
                'key_ready': False,
                'message': 'No quantum key found for this session'
            })
    except Exception as e:
        print(f"❌ Check quantum key error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/quantum/store_key', methods=['POST'])
def store_quantum_key():
    """Store the established quantum key - ONE TIME STORAGE"""
    try:
        data = request.json
        session_id = data['session_id']
        quantum_key = data['quantum_key']
        generated_by = data.get('generated_by')  # Which user generated the key
        
        if session_id in quantum_sessions:
            quantum_sessions[session_id]['quantum_key'] = quantum_key
            quantum_sessions[session_id]['key_ready'] = True
            quantum_sessions[session_id]['completed_at'] = datetime.now()
            quantum_sessions[session_id]['key_generated_by'] = generated_by
            quantum_sessions[session_id]['last_accessed'] = datetime.now()
            
            user1 = quantum_sessions[session_id]['user1_port']
            user2 = quantum_sessions[session_id]['user2_port']
            
            print(f"🔑 Quantum key stored: {user1} ↔ {user2}")
            print(f"🔑 Generated by: {generated_by}")
            print(f"🔑 Session: {session_id}")
            
            return jsonify({'status': 'success', 'message': 'Quantum key stored successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404
    except Exception as e:
        print(f"❌ Store quantum key error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/quantum/get_key/<session_id>')
def get_quantum_key(session_id):
    """Get the established quantum key - FAST ACCESS"""
    try:
        if session_id in quantum_sessions and quantum_sessions[session_id]['key_ready']:
            # Update last accessed time
            quantum_sessions[session_id]['last_accessed'] = datetime.now()
            
            key_data = quantum_sessions[session_id]
            return jsonify({
                'status': 'key_ready',
                'quantum_key': key_data['quantum_key'],
                'users': [key_data['user1_port'], key_data['user2_port']],
                'created_at': key_data['created_at'].isoformat(),
                'key_generated_by': key_data.get('key_generated_by')
            })
        elif session_id in quantum_sessions:
            return jsonify({'status': 'key_not_ready', 'message': 'Key exchange in progress'})
        else:
            return jsonify({'status': 'session_not_found', 'message': 'Invalid session ID'}), 404
    except Exception as e:
        print(f"❌ Get quantum key error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/quantum/get_session/<session_id>')
def get_quantum_session(session_id):
    """Get quantum session details"""
    try:
        if session_id in quantum_sessions:
            session_data = quantum_sessions[session_id]
            return jsonify({
                'status': 'found',
                'users': [session_data['user1_port'], session_data['user2_port']],
                'key_ready': session_data['key_ready'],
                'created_at': session_data['created_at'].isoformat(),
                'key_generated_by': session_data.get('key_generated_by')
            })
        else:
            return jsonify({'status': 'session_not_found'}), 404
    except Exception as e:
        print(f"❌ Get quantum session error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/quantum/sessions')
def get_quantum_sessions():
    """Get all active quantum sessions"""
    active_sessions = {}
    for session_id, session_data in quantum_sessions.items():
        if session_data['key_ready']:
            active_sessions[session_id] = {
                'users': [session_data['user1_port'], session_data['user2_port']],
                'created_at': session_data['created_at'].isoformat(),
                'completed_at': session_data.get('completed_at', {}).isoformat() if session_data.get('completed_at') else None,
                'key_generated_by': session_data.get('key_generated_by'),
                'last_accessed': session_data.get('last_accessed', {}).isoformat() if session_data.get('last_accessed') else None
            }
    return jsonify(active_sessions)

@app.route('/quantum/status')
def quantum_status():
    """Detailed quantum security status"""
    active_sessions = {}
    pending_sessions = {}
    
    for session_id, session_data in quantum_sessions.items():
        if session_data['key_ready']:
            active_sessions[session_id] = session_data
        else:
            pending_sessions[session_id] = session_data
    
    return jsonify({
        'total_sessions': len(quantum_sessions),
        'active_quantum_channels': len(active_sessions),
        'pending_sessions': len(pending_sessions),
        'active_sessions': active_sessions,
        'pending_sessions_list': pending_sessions
    })

@app.route('/quantum/clear_session/<session_id>', methods=['DELETE'])
def clear_quantum_session(session_id):
    """Clear a quantum session (for testing)"""
    try:
        if session_id in quantum_sessions:
            del quantum_sessions[session_id]
            print(f"🧹 Cleared quantum session: {session_id}")
            return jsonify({'status': 'success', 'message': 'Session cleared'})
        else:
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404
    except Exception as e:
        print(f"❌ Clear quantum session error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/quantum/cleanup', methods=['POST'])
def cleanup_quantum_sessions():
    """Clean up old quantum sessions (maintenance)"""
    try:
        current_time = datetime.now()
        sessions_to_remove = []
        
        for session_id, session_data in quantum_sessions.items():
            # Remove sessions older than 24 hours
            time_diff = (current_time - session_data['created_at']).total_seconds()
            if time_diff > 86400:  # 24 hours
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            del quantum_sessions[session_id]
            print(f"🧹 Cleaned up old session: {session_id}")
        
        return jsonify({
            'status': 'success', 
            'message': f'Cleaned up {len(sessions_to_remove)} old sessions',
            'sessions_removed': sessions_to_remove
        })
    except Exception as e:
        print(f"❌ Cleanup error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

# MONITORING ROUTES - SIMPLIFIED SINGLE CONTAINER
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            response = jsonify({'status': 'success'})
            response.set_cookie('admin_auth', 'true', max_age=3600)
            return response
        else:
            return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    
    return render_template('admin_login.html')

@app.route('/admin/monitoring')
def admin_monitoring():
    """Main monitoring dashboard"""
    auth_cookie = request.cookies.get('admin_auth')
    if auth_cookie != 'true':
        return render_template('admin_login.html')
    
    return render_template('monitoring.html')

@app.route('/api/monitoring/messages')
def get_monitoring_messages():
    """API endpoint for all monitoring messages"""
    auth_cookie = request.cookies.get('admin_auth')
    if auth_cookie != 'true':
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Get filter parameters
    message_type = request.args.get('type', 'all')
    quantum_only = request.args.get('quantum_only', 'false') == 'true'
    session_id = request.args.get('session_id')
    user_filter = request.args.get('user')
    
    filtered_messages = monitoring_messages.copy()
    
    # Apply filters
    if message_type != 'all':
        filtered_messages = [msg for msg in filtered_messages if msg['message_type'] == message_type]
    
    if quantum_only:
        filtered_messages = [msg for msg in filtered_messages if msg['quantum_encrypted']]
    
    if session_id:
        filtered_messages = [msg for msg in filtered_messages if msg['session_id'] == session_id]
    
    if user_filter:
        filtered_messages = [msg for msg in filtered_messages 
                           if user_filter in msg['from_user'] or user_filter in msg['to_user']]
    
    return jsonify({
        'messages': filtered_messages,
        'total_messages': len(monitoring_messages),
        'filtered_count': len(filtered_messages),
        'quantum_messages': len([msg for msg in monitoring_messages if msg['quantum_encrypted']]),
        'normal_messages': len([msg for msg in monitoring_messages if not msg['quantum_encrypted']])
    })

@app.route('/api/monitoring/stats')
def get_monitoring_stats():
    """API endpoint for monitoring statistics"""
    auth_cookie = request.cookies.get('admin_auth')
    if auth_cookie != 'true':
        return jsonify({'error': 'Unauthorized'}), 401
    
    current_time = datetime.now()
    online_users = [u for u in users.values() if u.get('online', False)]
    
    # Calculate messages in last hour
    one_hour_ago = current_time.timestamp() - 3600
    recent_messages = [msg for msg in monitoring_messages 
                      if datetime.strptime(msg['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp() > one_hour_ago]
    
    stats = {
        'total_users': len(users),
        'online_users': len(online_users),
        'total_messages': len(monitoring_messages),
        'recent_messages_1h': len(recent_messages),
        'quantum_sessions': len(quantum_sessions),
        'active_quantum_channels': len([s for s in quantum_sessions.values() if s.get('key_ready', False)]),
        'quantum_messages': len([msg for msg in monitoring_messages if msg['quantum_encrypted']]),
        'normal_messages': len([msg for msg in monitoring_messages if not msg['quantum_encrypted']])
    }
    
    return jsonify(stats)

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    response = jsonify({'status': 'success'})
    response.set_cookie('admin_auth', '', expires=0)
    return response

if __name__ == '__main__':
    print("🚀 Starting QUANTUM SECURE Talk'n'Go Central Server on port 5000...")
    print("🔐 Quantum Security: OPTIMIZED")
    print("📊 Monitoring Dashboard: http://localhost:5000/admin/login")
    print("👤 Admin Username: admin")
    print("🔑 Admin Password: quantumsecure123")
    print("🌐 Access server status: http://localhost:5000/")
    print("📊 Check quantum status: http://localhost:5000/quantum/status")
    print("⏳ Waiting for users to register...")
    app.run(host='0.0.0.0', port=5000, debug=False)
