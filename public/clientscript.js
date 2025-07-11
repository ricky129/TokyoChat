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
    let userPassword = null;
    console.log('contactsCache (init):', contactsCache);
    console.log('userPassword (init):', userPassword);

    // --- Authentication Logic (for login.html and register.html) ---
    if (loginForm) {
        console.log("Inside login form.");
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = loginForm.username.value;
            const password = loginForm.password.value;
            console.log('loginForm.username:', username);
            console.log('loginForm.password:', password);
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                console.log('Login response:', response.status, await response.text());
                if (response.ok) {
                    userPassword = password;
                    console.log('userPassword (set after login):', userPassword);
                    window.localStorage.setItem('tokyochat-user', username);
                    window.location.href = '/';
                }
                else {
                    const errorText = await response.text();
                    messageDisplay.textContent = errorText || 'Login failed.';
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
            console.log('registerForm.username:', username);
            console.log('registerForm.password:', password);

            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                const responseText = await response.text();
                console.log('Register response:', response.status, responseText);
                if (response.ok) {
                    userPassword = password; // <-- Save password for session
                    console.log('userPassword (set after register):', userPassword);
                    window.localStorage.setItem('tokyochat-user', username);
                    messageDisplay.classList.remove('error');
                    messageDisplay.classList.add('success');
                    window.location.href = '/'; // Redirect to main chat page on success
                } else {
                    messageDisplay.textContent = responseText || 'Registration failed.';
                    messageDisplay.classList.remove('success');
                    messageDisplay.classList.add('error');
                    console.log('messageDisplay.textContent (register error):', messageDisplay.textContent);
                }
            } catch (error) {
                console.error('Registration error:', error);
                messageDisplay.textContent = 'An error occurred during registration.';
                messageDisplay.classList.remove('success');
                messageDisplay.classList.add('error');
                console.log('messageDisplay.textContent (register catch):', messageDisplay.textContent);
            }
        });
    }

    if (messages && form) {
        let socket;
        console.log('messages:', messages);
        console.log('form:', form);
        console.log('messages && form userPassword:', userPassword);

        // Try to recover password from previous session
        if (!userPassword) {
            // Optionally, you could ask the user for their password if not present; for now, it's session-only
        }

        async function checkAuthAndConnectSocket() {
            try {
                const response = await fetch('/check-auth');
                const data = await response.json();
                console.log('Check-auth response:', data);
                if (data.authenticated) {
                    welcomeMessage.textContent = `Welcome ${data.username} to TokyoChat!`;
                    console.log('welcomeMessage.textContent:', welcomeMessage.textContent);

                    socket = io();
                    console.log('socket (after io()):', socket);

                    socket.on('connect', () => {
                        console.log('Connected to server! Your ID:', socket.id);
                        socketIdDisplay.textContent = socket.id;
                        console.log('socketIdDisplay.textContent:', socketIdDisplay.textContent);
                    });

                    socket.on('session-changed', () => {
                        window.location.href = '/login.html';
                    });

                    // Message received Route
                    socket.on('chat message', (data) => {
                        console.log('Received chat message:', data);
                        const item = document.createElement('li');

                        console.table(contactsCache);

                        let displayName = data.username;
                        const contact = contactsCache.find(c => c.contactUserID == data.id);
                        console.log('Contact found:', contact);
                        if (contact)
                            displayName = contact.alias || contact.contactUsername;
                        console.log('displayName (chat message):', displayName);

                        const senderSpan = document.createElement('span');
                        senderSpan.classList.add('message-sender');
                        senderSpan.textContent = `[${displayName}]`;

                        const messageSpan = document.createElement('span');
                        messageSpan.classList.add('message-text');
                        messageSpan.textContent = data.message;

                        item.appendChild(senderSpan);
                        item.appendChild(messageSpan);
                        messages.appendChild(item);
                        console.log('messages (after append):', messages);
                    });

                    form.addEventListener('submit', (e) => {
                        e.preventDefault();
                        console.log('input.value (before send):', input.value);
                        if (input.value) {
                            socket.emit('chat message', { message: input.value });
                            input.value = '';
                            console.log('input.value (after send):', input.value);
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
                console.log('loadContacts response:', response);
                if (response.ok) {
                    const contacts = await response.json();
                    console.log('contacts (from /contacts):', contacts);
                    contactsCache = contacts;
                    console.log('contactsCache (after load):', contactsCache);
                    if (contactsList)
                        contactsList.innerHTML = '';

                    if (contacts.length === 0) {
                        if (contactsList) {
                            const item = document.createElement('li');
                            item.textContent = 'No contacts yet. Add some!';
                            contactsList.appendChild(item);
                            console.log('contactsList (empty):', contactsList);
                        }
                    } else {
                        if (contactsList) {
                            contacts.forEach(element => {
                                const item = document.createElement('li');
                                const displayName = element.alias ? `${element.alias} (${element.contactUsername})` : element.contactUsername;
                                console.log('element:', element);
                                console.log('displayName (contact):', displayName);
                                item.textContent = displayName;
                                contactsList.appendChild(item);
                                console.log('contactsList (after append):', contactsList);
                            });
                        }
                    }
                } else {
                    if (contactMessageDisplay) {
                        contactMessageDisplay.textContent = 'Failed to load contacts.';
                        contactMessageDisplay.classList.add('error');
                        console.log('contactMessageDisplay.textContent (load fail):', contactMessageDisplay.textContent);
                    }
                }
            } catch (err) {
                console.error('Error loading contacts:', err);
                if (contactMessageDisplay) {
                    contactMessageDisplay.textContent = 'An error occurred while loading contacts.';
                    contactMessageDisplay.classList.add('error');
                    console.log('contactMessageDisplay.textContent (load catch):', contactMessageDisplay.textContent);
                }
            }
        }

        if (addContactForm) {
            addContactForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const contactUsername = addContactUsernameinput.value.trim();
                const alias = addContactAliasinput.value.trim();
                console.log('addContactUsernameinput.value:', contactUsername);
                console.log('addContactAliasinput.value:', alias);
                contactMessageDisplay.textContent = '';
                contactMessageDisplay.classList.remove('error', 'success');

                if (!contactUsername) {
                    contactMessageDisplay.textContent = 'Please enter a username to add.';
                    contactMessageDisplay.classList.add('error');
                    console.log('contactMessageDisplay.textContent (add empty):', contactMessageDisplay.textContent);
                    return;
                }

                try {
                    // --- SEND PASSWORD IN HEADER FOR ENCRYPTED CONTACTS ---
                    let headers = {
                        'Content-Type': 'application/json'
                    };
                    if (userPassword) {
                        headers['x-user-password'] = userPassword;
                    }
                    console.log('addContact headers:', headers);
                    const response = await fetch('/contacts/add', {
                        method: 'POST',
                        headers,
                        body: JSON.stringify({ contactUsername, alias })
                    });
                    console.log('addContact response:', response);
                    if (response.ok) {
                        const result = await response.json();
                        contactMessageDisplay.textContent = result.message || 'Contact added!';
                        contactMessageDisplay.classList.add('success');
                        addContactUsernameinput.value = '';
                        addContactAliasinput.value = '';
                        console.log('contactMessageDisplay.textContent (add success):', contactMessageDisplay.textContent);
                        loadContacts();
                    } else {
                        const errorText = await response.text();
                        contactMessageDisplay.textContent = errorText || 'Failed to add contact.';
                        contactMessageDisplay.classList.add('error');
                        console.log('contactMessageDisplay.textContent (add fail):', contactMessageDisplay.textContent);
                    }
                } catch (error) {
                    console.error('Error adding contact:', error);
                    contactMessageDisplay.textContent = 'An error occurred while adding contact.';
                    contactMessageDisplay.classList.add('error');
                    console.log('contactMessageDisplay.textContent (add catch):', contactMessageDisplay.textContent);
                }
            });
        }

        if (logoutButton) {
            logoutButton.addEventListener('click', async () => {
                try {
                    const response = await fetch('/logout', { method: 'POST' });
                    console.log('logout response:', response);
                    if (response.ok) {
                        if (socket)
                            socket.disconnect();

                        window.location.href = '/login.html';
                        userPassword = null;
                        window.localStorage.removeItem('tokyochat-user');
                        console.log('userPassword (after logout):', userPassword);
                    } else
                        alert('Logout failed. Please try again.');

                } catch (error) {
                    console.error('Logout error:', error);
                    alert('An error occurred during logout.');
                }
            });
        }

        checkAuthAndConnectSocket();
    }
});