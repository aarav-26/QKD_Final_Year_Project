// Global variables
const currentUserPort = parseInt("{{ user_port }}");
const currentUsername = "{{ username }}";
let selectedUserPort = null;
let selectedUsername = null;
let messageInterval = null;
let quantumEncryptionEnabled = false;
let quantumSecurityEstablished = false;

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
            
            // Add quantum security indicator
            const quantumIndicator = user.quantum_secure ? ' <span style="color: #25D366; font-size: 12px;">🔒</span>' : '';
            
            userItem.innerHTML = `
                <div class="user-info-small">
                    <div class="user-name">${user.username}${quantumIndicator}</div>
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
            
            // Add quantum security indicator
            const quantumIndicator = user.quantum_secure ? ' <span style="color: #25D366; font-size: 12px;">🔒</span>' : '';
            
            friendItem.innerHTML = `
                <div class="user-info-small">
                    <div class="user-name">${user.username}${quantumIndicator}</div>
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

// QUANTUM SECURITY FUNCTIONS
async function enableQuantumSecurity() {
    if (!selectedUserPort) {
        showNotification("Please select a user first");
        return;
    }
    
    showNotification("🔐 Starting quantum key exchange...");
    
    try {
        const response = await fetch('/api/enable_quantum', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                target_port: selectedUserPort
            })
        });
        
        const result = await response.json();
        if (result.status === 'success') {
            quantumSecurityEstablished = true;
            updateQuantumUI(true);
            showNotification("✅ Quantum secure channel established!");
            
            // Enable encryption by default
            quantumEncryptionEnabled = true;
            updateEncryptionToggle();
            
        } else {
            showNotification("❌ Quantum security setup failed");
        }
    } catch (error) {
        console.error('Quantum security error:', error);
        showNotification("❌ Quantum security error");
    }
}

async function checkQuantumStatus() {
    if (!selectedUserPort) return;
    
    try {
        const response = await fetch(`/api/quantum_status?target_port=${selectedUserPort}`);
        const status = await response.json();
        
        quantumSecurityEstablished = status.secure_channel || false;
        updateQuantumUI(quantumSecurityEstablished);
        
    } catch (error) {
        console.error('Quantum status check error:', error);
    }
}

function toggleQuantumEncryption() {
    if (!selectedUserPort) {
        showNotification("Please select a user first");
        return;
    }
    
    if (!quantumSecurityEstablished) {
        enableQuantumSecurity();
        return;
    }
    
    quantumEncryptionEnabled = !quantumEncryptionEnabled;
    updateEncryptionToggle();
    
    if (quantumEncryptionEnabled) {
        showNotification("🔒 Quantum encryption enabled for this chat");
    } else {
        showNotification("🔓 Quantum encryption disabled for this chat");
    }
}

function updateQuantumUI(isSecure) {
    const enableBtn = document.getElementById('enableQuantumBtn');
    const quantumStatus = document.getElementById('quantumStatus');
    const quantumControls = document.getElementById('quantumControls');
    
    quantumSecurityEstablished = isSecure;
    
    if (isSecure) {
        if (enableBtn) enableBtn.style.display = 'none';
        if (quantumStatus) quantumStatus.style.display = 'inline';
        if (quantumControls) quantumControls.style.display = 'block';
        quantumEncryptionEnabled = true;
        updateEncryptionToggle();
    } else {
        if (enableBtn) enableBtn.style.display = 'inline';
        if (quantumStatus) quantumStatus.style.display = 'none';
        if (quantumControls) quantumControls.style.display = 'block';
        quantumEncryptionEnabled = false;
        updateEncryptionToggle();
    }
}

function updateEncryptionToggle() {
    const quantumToggle = document.getElementById('quantumToggle');
    const encryptionStatus = document.getElementById('encryptionStatus');
    
    if (quantumEncryptionEnabled && quantumSecurityEstablished) {
        if (quantumToggle) {
            quantumToggle.style.background = '#25D366';
            quantumToggle.innerHTML = '🔒';
            quantumToggle.title = 'Quantum Encryption: ON';
        }
        if (encryptionStatus) encryptionStatus.style.display = 'block';
    } else {
        if (quantumToggle) {
            quantumToggle.style.background = '#666';
            quantumToggle.innerHTML = '🔓';
            quantumToggle.title = 'Quantum Encryption: OFF';
        }
        if (encryptionStatus) encryptionStatus.style.display = 'none';
    }
}

function showNotification(message) {
    // Create notification if it doesn't exist
    let notification = document.getElementById('quantumNotification');
    if (!notification) {
        notification = document.createElement('div');
        notification.id = 'quantumNotification';
        notification.className = 'notification-banner';
        notification.innerHTML = `
            <span id="quantumNotificationText"></span>
            <button class="notification-close" onclick="hideNotification()">×</button>
        `;
        document.body.appendChild(notification);
    }
    
    const notificationText = document.getElementById('quantumNotificationText');
    notificationText.textContent = message;
    notification.style.display = 'flex';
    
    // Auto-hide after 5 seconds
    setTimeout(hideNotification, 5000);
}

function hideNotification() {
    const notification = document.getElementById('quantumNotification');
    if (notification) {
        notification.style.display = 'none';
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
    
    // Show quantum controls if they exist
    const quantumControls = document.getElementById('quantumControls');
    if (quantumControls) {
        quantumControls.style.display = 'block';
    }
    
    // Check quantum security status
    await checkQuantumStatus();
    
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
            messageDiv.className = `message ${isSent ? 'message-sent' : 'message-received'} ${msg.type}-message`;
            
            const senderName = isSent ? 'You' : msg.from_port;
            
            // Add quantum encryption indicator
            const quantumIndicator = msg.quantum_encrypted ? ' <span style="color: #25D366; font-size: 10px;">🔒</span>' : '';
            
            let messageContent = '';
            
            if (msg.type === 'text') {
                messageContent = `
                    ${!isSent ? `<div class="message-sender">${senderName}</div>` : ''}
                    <div class="message-text">${msg.message}${quantumIndicator}</div>
                    <div class="message-time">${msg.timestamp}</div>
                `;
            } else if (msg.type === 'encrypted_text') {
                // Handle encrypted messages - show decrypted content if available
                const displayText = msg.display_message || msg.message;
                messageContent = `
                    ${!isSent ? `<div class="message-sender">${senderName}</div>` : ''}
                    <div class="message-text">${displayText}${quantumIndicator}</div>
                    <div class="message-time">${msg.timestamp}</div>
                `;
            } else if (msg.type === 'image') {
                const imageUrl = `/file/image/${msg.file_path}`;
                messageContent = `
                    ${!isSent ? `<div class="message-sender">${senderName}</div>` : ''}
                    <div class="file-message">
                        <div class="file-info">
                            <span class="file-icon">🖼️</span>
                            <span class="file-name">Image${quantumIndicator}</span>
                        </div>
                        <img src="${imageUrl}" alt="Shared image" class="message-image" onclick="openImage('${imageUrl}')">
                        <div class="message-time">${msg.timestamp}</div>
                    </div>
                `;
            } else if (msg.type === 'file') {
                const fileUrl = `/file/file/${msg.file_path}`;
                messageContent = `
                    ${!isSent ? `<div class="message-sender">${senderName}</div>` : ''}
                    <div class="file-message">
                        <div class="file-info">
                            <span class="file-icon">📎</span>
                            <div class="file-details">
                                <div class="file-name">${msg.message}${quantumIndicator}</div>
                                <div class="file-size">${formatFileSize(msg.file_size)}</div>
                            </div>
                        </div>
                        <a href="${fileUrl}" download="${msg.message}" class="download-btn">Download</a>
                        <div class="message-time">${msg.timestamp}</div>
                    </div>
                `;
            }
            
            messageDiv.innerHTML = messageContent;
            messagesContainer.appendChild(messageDiv);
        });
        
        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    } catch (error) {
        console.error('Error loading messages:', error);
    }
}

// Send message with quantum encryption support
async function sendMessage() {
    if (!selectedUserPort) {
        alert('Please select a user first!');
        return;
    }
    
    const messageText = document.getElementById('messageText');
    const text = messageText.value.trim();
    
    if (!text) return;
    
    try {
        const useQuantum = quantumEncryptionEnabled && quantumSecurityEstablished;
        
        const response = await fetch('/api/send_message', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                to_port: selectedUserPort,
                message: text,
                type: 'text',
                use_quantum: useQuantum
            })
        });
        
        const result = await response.json();
        if (result.status === 'sent') {
            messageText.value = '';
            await loadMessages(); // Reload messages to show the new one
            
            if (useQuantum) {
                showNotification("🔒 Message sent with quantum encryption");
            }
        } else {
            alert('Failed to send message: ' + (result.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error sending message:', error);
        alert('Error sending message');
    }
}

// Enhanced file message sending with quantum support
async function sendFileMessage(fileName, fileData, fileType, fileSize) {
    if (!selectedUserPort) {
        alert('Please select a user first!');
        return;
    }

    try {
        const useQuantum = quantumEncryptionEnabled && quantumSecurityEstablished;
        
        const response = await fetch('/api/send_message', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                to_port: selectedUserPort,
                message: fileName,
                type: fileType,
                file_data: fileData,
                file_name: fileName,
                file_size: fileSize,
                use_quantum: useQuantum
            })
        });
        
        const result = await response.json();
        if (result.status === 'sent') {
            await loadMessages();
            
            if (useQuantum) {
                showNotification("🔒 File sent with quantum encryption");
            }
        } else {
            alert('Failed to send file: ' + (result.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error sending file:', error);
        alert('Error sending file');
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

// In script.js - show who is generating keys
async function enableQuantumSecurity() {
    showNotification("🔐 Starting quantum key exchange...");
    
    try {
        const response = await fetch('/api/enable_quantum', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target_port: selectedUserPort})
        });
        
        const result = await response.json();
        if (result.status === 'success') {
            if (result.role === 'initiator') {
                showNotification("🔑 Generating quantum keys...");
            } else {
                showNotification("⏳ Waiting for quantum keys...");
            }
            
            // Poll for completion
            await waitForQuantumCompletion();
        }
    } catch (error) {
        showNotification("❌ Quantum security setup failed");
    }
}

async function waitForQuantumCompletion() {
    let attempts = 0;
    const maxAttempts = 30; // 30 seconds timeout
    
    while (attempts < maxAttempts) {
        const status = await checkQuantumStatus();
        if (status.secure_channel) {
            showNotification("✅ Quantum secure channel established!");
            updateQuantumUI(true);
            return;
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
        attempts++;
    }
    
    showNotification("❌ Quantum setup timeout");
}

// Send heartbeat
async function sendHeartbeat() {
    try {
        await fetch('/api/heartbeat');
    } catch (error) {
        console.log('Heartbeat failed');
    }
}

// File size formatting
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Open image in full screen
function openImage(imageUrl) {
    window.open(imageUrl, '_blank');
}

// Initialize quantum features when DOM loads
document.addEventListener('DOMContentLoaded', function() {
    // Add quantum toggle button if it doesn't exist in HTML
    const fileButtons = document.querySelector('.file-buttons');
    if (fileButtons && !document.getElementById('quantumToggle')) {
        const quantumToggle = document.createElement('button');
        quantumToggle.type = 'button';
        quantumToggle.id = 'quantumToggle';
        quantumToggle.className = 'file-btn';
        quantumToggle.title = 'Toggle Quantum Encryption';
        quantumToggle.innerHTML = '🔓';
        quantumToggle.onclick = toggleQuantumEncryption;
        quantumToggle.style.background = '#666';
        fileButtons.appendChild(quantumToggle);
    }
    
    // Add encryption status if it doesn't exist
    const messageInput = document.getElementById('messageInput');
    if (messageInput && !document.getElementById('encryptionStatus')) {
        const encryptionStatus = document.createElement('div');
        encryptionStatus.id = 'encryptionStatus';
        encryptionStatus.style.cssText = 'color: #25D366; font-size: 12px; margin-top: 5px; display: none;';
        encryptionStatus.textContent = '🔒 Messages are quantum encrypted';
        messageInput.appendChild(encryptionStatus);
    }
    
    // Start heartbeat
    setInterval(sendHeartbeat, 10000);
});

// Make functions globally available
window.enableQuantumSecurity = enableQuantumSecurity;
window.toggleQuantumEncryption = toggleQuantumEncryption;
window.hideNotification = hideNotification;
window.openImage = openImage;
