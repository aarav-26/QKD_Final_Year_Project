const currentUserPort = parseInt("{{ user_port }}");
const currentUsername = "{{ username }}";
let selectedUserPort = null;
let selectedUsername = null;
let messageInterval = null;

// Load all users from central server
async function loadUsers() {
    try {
        const response = await fetch('/api/users');
        const users = await response.json();
        
        const usersList = document.getElementById('usersList');
        const friendsList = document.getElementById('friendsList');
        
        // Update users list (all users)
        usersList.innerHTML = '';
        
        if (Object.keys(users).length === 0) {
            usersList.innerHTML = '<div class="no-users">No other users found</div>';
            friendsList.innerHTML = '<div class="no-users">No online users</div>';
            return;
        }
        
        Object.entries(users).forEach(([port, user]) => {
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            userItem.onclick = () => selectUser(port, user.username);
            userItem.innerHTML = `
                <div class="user-info-small">
                    <div class="user-name">${user.username}</div>
                    <div class="user-port">Port: ${port}</div>
                </div>
                <span class="user-status ${user.online ? 'status-online' : 'status-offline'}">
                    ${user.online ? 'Online' : 'Offline'}
                </span>
            `;
            usersList.appendChild(userItem);
        });
        
        // Update friends list (online users only)
        friendsList.innerHTML = '';
        const onlineUsers = Object.entries(users).filter(([port, user]) => user.online);
        
        if (onlineUsers.length === 0) {
            friendsList.innerHTML = '<div class="no-users">No online users</div>';
            return;
        }
        
        onlineUsers.forEach(([port, user]) => {
            const friendItem = document.createElement('div');
            friendItem.className = 'friend-item';
            friendItem.onclick = () => selectUser(port, user.username);
            friendItem.innerHTML = `
                <div class="user-info-small">
                    <div class="user-name">${user.username}</div>
                    <div class="user-port">Port: ${port}</div>
                </div>
                <span class="user-status status-online">Online</span>
            `;
            friendsList.appendChild(friendItem);
        });
        
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

// Select user for chatting
async function selectUser(port, username) {
    console.log("Selecting user:", username, "Port:", port);
    
    selectedUserPort = port;
    selectedUsername = username;
    
    // Update UI
    document.querySelector('.no-chat-selected').style.display = 'none';
    document.querySelector('.active-chat-header').style.display = 'block';
    document.getElementById('activeChatUser').textContent = username;
    document.getElementById('activeChatStatus').textContent = 'Online';
    document.getElementById('messages').style.display = 'flex';
    document.getElementById('messageInput').style.display = 'block';
    document.querySelector('.no-chat-message').style.display = 'none';
    
    // Clear previous interval
    if (messageInterval) {
        clearInterval(messageInterval);
    }
    
    // Load messages and start polling
    await loadMessages();
    messageInterval = setInterval(loadMessages, 2000);
}

// Load messages for selected user
async function loadMessages() {
    if (!selectedUserPort) return;
    
    try {
        const response = await fetch(`/api/messages/${selectedUserPort}`);
        const messages = await response.json();
        const messagesContainer = document.getElementById('messages');
        
        messagesContainer.innerHTML = '';
        
        if (messages.length === 0) {
            messagesContainer.innerHTML = '<div class="no-messages">No messages yet. Start the conversation!</div>';
            return;
        }
        
        // Sort messages by timestamp
        messages.sort((a, b) => {
            const timeA = new Date(`${a.date} ${a.timestamp}`);
            const timeB = new Date(`${b.date} ${b.timestamp}`);
            return timeA - timeB;
        });
        
        messages.forEach(msg => {
            const messageDiv = document.createElement('div');
            const isSent = parseInt(msg.from_port) === currentUserPort;
            messageDiv.className = `message ${isSent ? 'message-sent' : 'message-received'}`;
            
            const senderName = isSent ? 'You' : msg.from_port;
            
            messageDiv.innerHTML = `
                ${!isSent ? `<div class="message-sender">${senderName}</div>` : ''}
                <div class="message-text">${msg.message}</div>
                <div class="message-time">${msg.timestamp}</div>
            `;
            
            messagesContainer.appendChild(messageDiv);
        });
        
        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    } catch (error) {
        console.error('Error loading messages:', error);
    }
}

// Send message
async function sendMessage() {
    if (!selectedUserPort) {
        alert('Please select a user first!');
        return;
    }
    
    const messageText = document.getElementById('messageText');
    const text = messageText.value.trim();
    
    if (!text) return;
    
    try {
        const response = await fetch('/api/send_message', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                to_port: selectedUserPort,
                message: text
            })
        });
        
        const result = await response.json();
        if (result.status === 'sent') {
            messageText.value = '';
            await loadMessages(); // Reload messages to show the new one
        } else {
            alert('Failed to send message: ' + (result.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error sending message:', error);
        alert('Error sending message');
    }
}

// Handle Enter key press
function handleKeyPress(event) {
    if (event.key === 'Enter') {
        sendMessage();
    }
}

// Search users
function searchUsers() {
    const searchTerm = document.getElementById('searchUsers').value.toLowerCase();
    const userItems = document.querySelectorAll('.user-item');
    
    userItems.forEach(item => {
        const userName = item.querySelector('.user-name').textContent.toLowerCase();
        if (userName.includes(searchTerm)) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
}

// Send heartbeat
async function sendHeartbeat() {
    try {
        await fetch('/api/heartbeat');
    } catch (error) {
        console.log('Heartbeat failed');
    }
}
