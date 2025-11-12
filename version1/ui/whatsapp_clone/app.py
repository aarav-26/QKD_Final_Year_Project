from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import threading
import requests
import time
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'whatsapp_clone_secret_key'

# In-memory storage for users and messages
users = {}
messages = {}
active_connections = {}

class User:
    def __init__(self, port, username=None):
        self.port = port
        self.username = username or f"User_{port}"
        self.friends = set()
        self.online = True
    
    def add_friend(self, friend_port):
        self.friends.add(friend_port)
        if friend_port not in messages:
            messages[friend_port] = {}
        if self.port not in messages[friend_port]:
            messages[friend_port][self.port] = []

@app.route('/')
def index():
    if 'user_port' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        port = request.form.get('port')
        username = request.form.get('username')
        
        if port:
            session['user_port'] = int(port)
            session['username'] = username or f"User_{port}"
            
            # Register user
            if int(port) not in users:
                users[int(port)] = User(int(port), session['username'])
            
            return redirect(url_for('chat'))
    
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'user_port' not in session:
        return redirect(url_for('login'))
    
    user_port = session['user_port']
    if user_port not in users:
        users[user_port] = User(user_port, session['username'])
    
    return render_template('chat.html', 
                         user_port=user_port, 
                         username=session['username'])

@app.route('/get_users')
def get_users():
    if 'user_port' not in session:
        return jsonify([])
    
    user_port = session['user_port']
    all_users = []
    
    for port, user in users.items():
        if port != user_port:
            all_users.append({
                'port': port,
                'username': user.username,
                'online': user.online
            })
    
    return jsonify(all_users)

@app.route('/get_friends')
def get_friends():
    if 'user_port' not in session:
        return jsonify([])
    
    user_port = session['user_port']
    if user_port not in users:
        return jsonify([])
    
    friends_list = []
    for friend_port in users[user_port].friends:
        if friend_port in users:
            friends_list.append({
                'port': friend_port,
                'username': users[friend_port].username,
                'online': users[friend_port].online
            })
    
    return jsonify(friends_list)

@app.route('/add_friend', methods=['POST'])
def add_friend():
    if 'user_port' not in session:
        return jsonify({'success': False})
    
    user_port = session['user_port']
    friend_port = int(request.json.get('port'))
    
    if user_port not in users:
        users[user_port] = User(user_port, session['username'])
    
    if friend_port not in users:
        users[friend_port] = User(friend_port, f"User_{friend_port}")
    
    users[user_port].add_friend(friend_port)
    users[friend_port].add_friend(user_port)
    
    return jsonify({'success': True})

@app.route('/get_messages/<int:friend_port>')
def get_messages(friend_port):
    if 'user_port' not in session:
        return jsonify([])
    
    user_port = session['user_port']
    
    # Initialize message storage if needed
    if user_port not in messages:
        messages[user_port] = {}
    if friend_port not in messages[user_port]:
        messages[user_port][friend_port] = []
    
    return jsonify(messages[user_port][friend_port])

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_port' not in session:
        return jsonify({'success': False})
    
    user_port = session['user_port']
    friend_port = int(request.json.get('friend_port'))
    message_text = request.json.get('message')
    
    if user_port not in messages:
        messages[user_port] = {}
    if friend_port not in messages[user_port]:
        messages[user_port][friend_port] = []
    
    message = {
        'sender': user_port,
        'receiver': friend_port,
        'text': message_text,
        'timestamp': datetime.now().strftime('%H:%M'),
        'date': datetime.now().strftime('%Y-%m-%d')
    }
    
    # Store message for sender
    messages[user_port][friend_port].append(message)
    
    # Also store for receiver
    if friend_port not in messages:
        messages[friend_port] = {}
    if user_port not in messages[friend_port]:
        messages[friend_port][user_port] = []
    
    messages[friend_port][user_port].append(message)
    
    return jsonify({'success': True})

@app.route('/logout')
def logout():
    user_port = session.get('user_port')
    if user_port and user_port in users:
        users[user_port].online = False
    session.clear()
    return redirect(url_for('login'))

def run_server(port):
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: python app.py <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    print(f"Starting WhatsApp Clone on port {port}")
    run_server(port)
