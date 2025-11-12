from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Central storage for all users and messages
users = {}  # {port: {username, server_url, online, last_seen, port}}
messages = {}  # {conversation_key: [message1, message2, ...]}

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
    # Update online status based on last seen
    current_time = datetime.now()
    for port, user in users.items():
        if (current_time - user['last_seen']).seconds > 30:
            user['online'] = False
    
    print(f"📊 Central server returning {len(users)} users: {list(users.keys())}")
    return jsonify(users)

@app.route('/send_message', methods=['POST'])
def send_message():
    try:
        data = request.json
        from_port = str(data['from_port'])
        to_port = str(data['to_port'])
        message_text = data['message']
        
        # Validate users exist
        if from_port not in users:
            return jsonify({'status': 'error', 'message': 'Sender not found'}), 404
        if to_port not in users:
            return jsonify({'status': 'error', 'message': 'Recipient not found'}), 404
        
        # Create consistent conversation key
        key = f"{min(from_port, to_port)}_{max(from_port, to_port)}"
        
        if key not in messages:
            messages[key] = []
        
        message_data = {
            'from_port': from_port,
            'to_port': to_port,
            'message': message_text,
            'timestamp': datetime.now().strftime('%H:%M'),
            'date': datetime.now().strftime('%Y-%m-%d'),
            'id': len(messages[key]) + 1
        }
        
        messages[key].append(message_data)
        
        from_user = users[from_port]['username']
        to_user = users[to_port]['username']
        
        print(f"💬 Message sent: {from_user}({from_port}) → {to_user}({to_port}): {message_text}")
        print(f"📁 Conversation: {key}, Total messages: {len(messages[key])}")
        
        return jsonify({'status': 'sent', 'message_id': message_data['id']})
    except Exception as e:
        print(f"❌ Send message error: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/get_messages/<from_port>/<to_port>')
def get_messages(from_port, to_port):
    try:
        # Validate users exist
        if from_port not in users:
            print(f"❌ From user {from_port} not found")
            return jsonify([])
        if to_port not in users:
            print(f"❌ To user {to_port} not found")
            return jsonify([])
            
        key = f"{min(from_port, to_port)}_{max(from_port, to_port)}"
        
        if key in messages:
            conversation_messages = messages[key]
            # Return all messages in this conversation
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

@app.route('/debug')
def debug():
    return jsonify({
        'users': users,
        'messages': {k: len(v) for k, v in messages.items()},
        'conversations': list(messages.keys())
    })

if __name__ == '__main__':
    print("🚀 Starting WhatsApp Clone Central Server on port 5000...")
    print("🌐 Access server status: http://localhost:5000/")
    print("📊 Check server status: http://localhost:5000/status")
    print("🐛 Debug info: http://localhost:5000/debug")
    print("⏳ Waiting for users to register...")
    app.run(host='0.0.0.0', port=5000, debug=False)
