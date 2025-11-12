from flask import Flask, render_template, request
from flask_socketio import SocketIO, send, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Keep track of messages per user
messages = {"person1": []}

@app.route('/')
def index():
    users = list(messages.keys())
    return render_template('chat.html', users=users, current_user='person2', messages=messages)

@socketio.on('send_message')
def handle_message(data):
    receiver = data['to']
    msg = data['msg']
    # Save message for both sender and receiver
    if receiver not in messages:
        messages[receiver] = []
    messages[receiver].append(f"person2: {msg}")
    emit('receive_message', {'from': 'person2', 'msg': msg}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5002, debug=True)
