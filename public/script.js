document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    console.log('Login form found:', loginForm);
    const registerForm = document.getElementById('registerForm');
    console.log('Register form found:', registerForm);
    const messageDisplay = document.getElementById('message');
    const chatWindow = document.getElementById('chatWindow');
    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('m');
    const welcomeMessage = document.getElementById('welcomeMessage');
    const logoutButton = document.getElementById('logoutButton');

    // --- Authentication Logic (for login.html and register.html) ---
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            console.log('Login form submitted'); // Debug log
            const username = loginForm.username.value;
            const password = loginForm.password.value;
            console.log('Sending login request: ', { username, password });
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                

                console.log('Login response:', response.status, await response.text())
                if (response.ok)
                    window.location.href = '/'; // Redirect to main chat page on success
                else {
                    const errorText = await response.text();
                    messageDisplay.textContent = errorText || 'Login failed.';
                }
            } catch (error) {
                console.error('Login error:', error);
                messageDisplay.textContent = 'An error occurred during login.';
            }
        });
    }

    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = registerForm.username.value;
            const password = registerForm.password.value;

            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });

                if (response.ok) {
                    messageDisplay.classList.remove('error');
                    messageDisplay.classList.add('success');
                    window.location.href = '/'; // Redirect to main chat page on success
                } else {
                    const errorText = await response.text();
                    messageDisplay.textContent = errorText || 'Registration failed.';
                    messageDisplay.classList.remove('success');
                    messageDisplay.classList.add('error');
                }
            } catch (error) {
                console.error('Registration error:', error);
                messageDisplay.textContent = 'An error occurred during registration.';
                messageDisplay.classList.remove('success');
                messageDisplay.classList.add('error');
            }
        });
    }

    // --- Chat Logic (for index.html) ---

    // Only run Socket.IO and chat specific logic if we are on the index.html page
    if (chatWindow && messageForm) {
        let socket; // Declare socket variable in a scope accessible by chat functions

        async function checkAuthAndConnectSocket() {
            try {
                const response = await fetch('/check-auth');
                const data = await response.json();

                if (data.authenticated) {
                    welcomeMessage.textContent = `Welcome, ${data.username} to TokyoChat!`;
                    // Initialize Socket.IO connection AFTER successful authentication check
                    socket = io(); // Connect to the Socket.IO server

                    socket.on('chat message', (msg) => {
                        const item = document.createElement('div');
                        item.textContent = `${msg.username}: ${msg.message}`;
                        chatWindow.appendChild(item);
                        chatWindow.scrollTop = chatWindow.scrollHeight; // Scroll to bottom
                    });

                    messageForm.addEventListener('submit', (e) => {
                        e.preventDefault();
                        if (messageInput.value) {
                            socket.emit('chat message', { message: messageInput.value });
                            messageInput.value = '';
                        }
                    });

                } else
                    // Not authenticated, redirect to login
                    window.location.href = '/login.html';

            } catch (error) {
                console.error('Authentication check failed:', error);
                window.location.href = '/login.html'; // Redirect on auth check error
            }
        }

        checkAuthAndConnectSocket(); // Run auth check when index.html loads

        if (logoutButton) {
            logoutButton.addEventListener('click', async () => {
                try {
                    const response = await fetch('/logout', { method: 'POST' });
                    if (response.ok) {
                        // Disconnect socket if it's open
                        if (socket)
                            socket.disconnect();
                        
                        window.location.href = '/login.html'; // Redirect to login after logout
                    } else
                        alert('Logout failed. Please try again.');
                    
                } catch (error) {
                    console.error('Logout error:', error);
                    alert('An error occurred during logout.');
                }
            });
        }
    }
});