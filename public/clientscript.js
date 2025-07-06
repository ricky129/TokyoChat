document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    console.log('loginForm:', loginForm);
    const registerForm = document.getElementById('registerForm');
    console.log('registerForm:', registerForm);
    const welcomeMessage = document.getElementById('welcomeMessage');
    console.log('welcomeMessage:', welcomeMessage);
    const logoutButton = document.getElementById('logoutButton');
    console.log('logoutButton:', logoutButton);
    const contactsList = document.getElementById('contactsList');
    console.log('contactsList:', contactsList);
    const addContactForm = document.getElementById('addContactForm');
    console.log('addContactForm:', addContactForm);
    const addContactUsernameinput = document.getElementById('addContactUsername');
    console.log('addContactUsernameinput:', addContactUsernameinput);
    const addContactAliasinput = document.getElementById('addContactAlias');
    console.log('addContactAliasinput:', addContactAliasinput);
    const contactMessageDisplay = document.getElementById('contactMessage');
    console.log('contactMessageDisplay:', contactMessageDisplay);
    const form = document.getElementById('form');
    console.log('form:', form);
    const input = document.getElementById('input');
    console.log('input:', input);
    const messages = document.getElementById('messages');
    console.log('messages:', messages);
    const socketIdDisplay = document.getElementById('socketIdDisplay');
    console.log('socketIdDisplay:', socketIdDisplay);
    const messageDisplay = document.getElementById('message');
    console.log('messageDisplay:', messageDisplay);

    let contactsCache = [];

    // --- Authentication Logic (for login.html and register.html) ---
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = loginForm.username.value;
            const password = loginForm.password.value;
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                if (response.ok) {
                    window.localStorage.setItem('tokyochat-user', username);
                    window.location.href = '/';
                }
                else {
                    const errorText = await response.text();
                    messageDisplay.textContent = errorText || 'Login failed.';
                    messageDisplay.classList.add('error');
                    console.log('messageDisplay.textContent (login error):', messageDisplay.textContent);
                }
            } catch (error) {
                console.error('Login error:', error);
                messageDisplay.textContent = 'An error occurred during login.';
                console.log('messageDisplay.textContent (login catch):', messageDisplay.textContent);
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
                const responseText = await response.text();
                if (response.ok) {
                    window.localStorage.setItem('tokyochat-user', username);
                    messageDisplay.classList.remove('error');
                    messageDisplay.classList.add('success');
                    window.location.href = '/';
                } else {
                    messageDisplay.textContent = responseText || 'Registration failed.';
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

    if (messages && form) {
        let socket;

        async function checkAuthAndConnectSocket() {
            try {
                const response = await fetch('/check-auth');
                const data = await response.json();
                if (data.authenticated) {
                    welcomeMessage.textContent = `Welcome ${data.username} to TokyoChat!`;

                    socket = io();

                    socket.on('connect', () => {
                        console.log('Connected to server! Your ID:', socket.id);
                        socketIdDisplay.textContent = socket.id;
                    });

                    socket.on('session-changed', () => {
                        window.location.href = '/login.html';
                    });

                    // Message received Route
                    socket.on('chat message', (data) => {
                        const item = document.createElement('li');
                        let displayName = data.username;
                        const contact = contactsCache.find(c => c.contactUserID == data.id);
                        console.log('Contact found:', contact);
                        if (contact)
                            displayName = contact.alias || contact.contactUsername;

                        const senderSpan = document.createElement('span');
                        senderSpan.classList.add('message-sender');
                        senderSpan.textContent = `[${displayName}]`;

                        const messageSpan = document.createElement('span');
                        messageSpan.classList.add('message-text');
                        messageSpan.textContent = data.message;

                        item.appendChild(senderSpan);
                        item.appendChild(messageSpan);
                        messages.appendChild(item);
                    });

                    form.addEventListener('submit', (e) => {
                        e.preventDefault();
                        if (input.value) {
                            socket.emit('chat message', { message: input.value });
                            input.value = '';
                        }
                    });

                    loadContacts();
                } else
                    window.location.href = '/login.html';
            } catch (error) {
                console.error('Authentication check failed:', error);
                window.location.href = '/login.html'; // Redirect on auth check error
            }
        }

        async function loadContacts() {
            try {
                const response = await fetch('/contacts');
                if (response.ok) {
                    const contacts = await response.json();
                    contactsCache = contacts;
                    if (contactsList)
                        contactsList.innerHTML = '';

                    if (contacts.length === 0) {
                        if (contactsList) {
                            const item = document.createElement('li');
                            item.textContent = 'No contacts yet. Add some!';
                            contactsList.appendChild(item);
                        }
                    } else
                        if (contactsList) {
                            contacts.forEach(element => {
                                const item = document.createElement('li');
                                const displayName = element.alias ? `${element.alias} (${element.contactUsername})` : element.contactUsername;
                                item.textContent = displayName;
                                contactsList.appendChild(item);
                            });
                        }
                    
                } else {
                    if (contactMessageDisplay) {
                        contactMessageDisplay.textContent = 'Failed to load contacts.';
                        contactMessageDisplay.classList.add('error');
                    }
                }
            } catch (err) {
                if (contactMessageDisplay) {
                    contactMessageDisplay.textContent = 'An error occurred while loading contacts.';
                    contactMessageDisplay.classList.add('error');
                }
            }
        }

        if (addContactForm) {
            addContactForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const contactUsername = addContactUsernameinput.value.trim();
                const alias = addContactAliasinput.value.trim();
                contactMessageDisplay.textContent = '';
                contactMessageDisplay.classList.remove('error', 'success');

                if (!contactUsername) {
                    contactMessageDisplay.textContent = 'Please enter a username to add.';
                    contactMessageDisplay.classList.add('error');
                    return;
                }

                try {
                    const token = window.localStorage.getItem('tokyochat-token');
                    if (!token) {
                        contactMessageDisplay.textContent = 'Please log in again';
                        contactMessageDisplay.classList.add('error');
                        window.location.href = '/login.html';
                        return;
                    }
                    const response = await fetch('/contacts/add', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization':`Bearer ${token}`
                        },
                        body: JSON.stringify({ contactUsername, alias })
                    });
                    if (response.ok) {
                        const result = await response.json();
                        contactMessageDisplay.textContent = result.message || 'Contact added!';
                        contactMessageDisplay.classList.add('success');
                        addContactUsernameinput.value = '';
                        addContactAliasinput.value = '';
                        loadContacts();
                    } else {
                        const errorText = await response.text();
                        contactMessageDisplay.textContent = errorText || 'Failed to add contact.';
                        contactMessageDisplay.classList.add('error');
                    }
                } catch (error) {
                    contactMessageDisplay.textContent = 'An error occurred while adding contact.';
                    contactMessageDisplay.classList.add('error');
                }
            });
        }

        if (logoutButton) {
            logoutButton.addEventListener('click', async () => {
                try {
                    const response = await fetch('/logout', { method: 'POST' });
                    if (response.ok) {
                        if (socket)
                            socket.disconnect();

                        window.location.href = '/login.html';
                        userPassword = null;
                        window.localStorage.removeItem('tokyochat-user');
                    } else
                        alert('Logout failed. Please try again.');

                } catch (error) {
                    alert('An error occurred during logout.');
                }
            });
        }

        checkAuthAndConnectSocket();
    }
});