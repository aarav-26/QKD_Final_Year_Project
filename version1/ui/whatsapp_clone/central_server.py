from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime
import os
import base64
import uuid

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

@app.route('/')
def home():
    return jsonify({
        'message': 'WhatsApp Clone Central Server',
        'status': 'running',
        'users_count': len(users),
        'online_users': len([u for u in users.values() if u['online']])
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
            'port': port
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
        message_type = data.get('type', 'text')  # text, image, file
        file_data = data.get('file_data')
        file_name = data.get('file_name')
        file_size = data.get('file_size')
        
        # Validate users exist
        if from_port not in users:
            return jsonify({'status': 'error', 'message': 'Sender not found'}), 404
        if to_port not in users:
            return jsonify({'status': 'error', 'message': 'Recipient not found'}), 404
        
        # Create consistent conversation key
        key = f"{min(from_port, to_port)}_{max(from_port, to_port)}"
        
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
            'file_path': file_path
        }
        
        messages[key].append(message_data)
        
        from_user = users[from_port]['username']
        to_user = users[to_port]['username']
        
        if message_type == 'text':
            print(f"💬 Message sent: {from_user}({from_port}) → {to_user}({to_port}): {message_text}")
        elif message_type == 'image':
            print(f"🖼️  Image sent: {from_user}({from_port}) → {to_user}({to_port}): {file_name}")
        elif message_type == 'file':
            print(f"📎 File sent: {from_user}({from_port}) → {to_user}({to_port}): {file_name}")
        
        print(f"📁 Conversation: {key}, Total messages: {len(messages[key])}")
        
        return jsonify({'status': 'sent', 'message_id': message_id})
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
        key = f"{min(from_port, to_port)}_{max(from_port, to_port)}"
        
        if key in messages:
            conversation_messages = messages[key]
            print(f"📩 Returning {len(conversation_messages)} messages for {from_port}↔{to_port}")
            return jsonify(conversation_messages)
        else:
            print(f"📭 No messages found for conversation {key}")
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
    return jsonify({
        'server': 'running',
        'total_users': len(users),
        'online_users': len(online_users),
        'total_conversations': len(messages),
        'users': [{'port': u['port'], 'username': u['username'], 'online': u['online']} for u in users.values()]
    })

if __name__ == '__main__':
    print("🚀 Starting WhatsApp Clone Central Server on port 5000...")
    print("🌐 Access server status: http://localhost:5000/")
    print("📊 Check server status: http://localhost:5000/status")
    print("⏳ Waiting for users to register...")
    app.run(host='0.0.0.0', port=5000, debug=False)
