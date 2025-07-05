const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { dbPromise } = require('./database');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto'); // <-- ADD THIS LINE!

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const CLI_PORT = process.argv[2] ? parseInt(process.argv[2], 10) : null;
const PORT = CLI_PORT || process.env.PORT || 3000;

if (CLI_PORT && (isNaN(PORT) || PORT <= 0 || PORT > 65535))
    console.error(`Error: Invalid port specified from the command line: ${process.argv[2]}. Using default port 3000`);

const SESSION_SECRET = 'ilmiodolcepreferitoeiltiramisu';

const sessionMiddleware = session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 86400000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
    }
});

function isAuthenticated(req, res, next) {
    if (req.session.userId)
        next();
    else
        res.status(401).redirect('/login.html');
}

// --- ENCRYPTION HELPERS ---

async function deriveKey(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, 100000, 32, 'sha512', (err, derivedKey) => {
            if (err)
                reject(err);
            resolve(derivedKey);
        });
    });
}

async function encrypt(text, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

async function decrypt(encryptedText, key, iv) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// -----------------------------------

async function startApp() {
    let db;
    const userSockets = {};

    console.log('Initializing database...');
    try {
        db = await dbPromise;
        console.log('Database initialized successfully, db:', !!db);

        // Body parsers
        app.use(express.urlencoded({ extended: true }));
        app.use(express.json());

        // Session middleware
        app.use(sessionMiddleware);

        // Middleware to check db is ready (should always be true here)
        app.use((req, res, next) => {
            if (!db) {
                console.error('Database not initialized yet for request:', req.url);
                return res.status(503).send('Server is starting, please try again in a moment.');
            }
            next();
        });

        // Static files
        app.use(express.static('public'));

        // --- REGISTRATION ROUTE (with encryption) ---
        app.post('/register', async (req, res) => {
            const { username, password } = req.body;

            if (!username || !password)
                return res.status(400).send('Username and password are required.');

            try {
                const existingUser = await db.get(`SELECT id FROM users WHERE username = ?`, [username]);
                if (existingUser)
                    return res.status(409).send('Username already taken.');

                const hash = await bcrypt.hash(password, 10);
                const result = await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash]);

                // ENCRYPT EMPTY CONTACTS FOR NEW USER
                const userId = result.lastID;
                const contacts = [];
                const salt = crypto.randomBytes(16); // Buffer, not hex string
                const iv = crypto.randomBytes(16).toString('hex');
                const key = await deriveKey(password, salt);
                req.session.derivedKey = key;
                const encrypted_contacts = await encrypt(JSON.stringify(contacts), key, Buffer.from(iv, 'hex'));

                await db.run(`INSERT INTO contacts (user_id, encrypted_contacts, iv, salt) VALUES (?, ?, ?, ?)`, [userId, encrypted_contacts, iv, salt.toString('hex')]);

                const oldUserId = req.session.userId;
                if (oldUserId && userSockets[oldUserId]) {
                    userSockets[userId].forEach(socketId => {
                        io.to(socketId).emit('session-changed');
                    });
                    delete userSockets[userId];
                }

                req.session.userId = userId;
                req.session.username = username;
                // Do not store sensitive key in session

                console.log(`User ${username} registered with ID: ${userId}`);
                res.status(200).send('Registration successful!');

            } catch (dbErr) {
                if (dbErr.code === 'SQLITE_CONSTRAINT' || dbErr.code === 'SQLITE_CONSTRAINT_UNIQUE')
                    return res.status(409).send('Username already taken.');
                console.error('Error inserting user or contacts:', dbErr);
                return res.status(500).send('Error registering user.');
            }
        });

        // --- LOGIN ROUTE (with contacts decryption) ---
        app.post('/login', async (req, res) => {
            const { username, password } = req.body;

            if (!username || !password)
                return res.status(400).send('Username and password are required');

            try {
                const user = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
                if (!user)
                    return res.status(401).send('Invalid username');

                const result = await bcrypt.compare(password, user.password);
                if (!result)
                    return res.status(401).send('Invalid password');

                // Fetch encrypted contacts
                const contactRecord = await db.get(`SELECT encrypted_contacts, iv, salt FROM contacts WHERE user_id = ?`, [user.id]);
                let contacts = [];
                if (contactRecord) {
                    const key = await deriveKey(password, Buffer.from(contactRecord.salt, 'hex'));
                    req.session.derivedKey = key;
                    try {
                        const decrypted = await decrypt(contactRecord.encrypted_contacts, key, Buffer.from(contactRecord.iv, 'hex'));
                        contacts = JSON.parse(decrypted);
                    } catch (e) {
                        // If decryption fails, fallback to empty
                        console.error('Failed to decrypt contacts for user', username, e);
                        contacts = [];
                    }
                }

                const oldUserId = req.session.userId;
                if (oldUserId && userSockets[oldUserId]) {
                    userSockets[oldUserId].forEach(socketId => {
                        io.to(socketId).emit('session-changed');
                    });
                    delete userSockets[oldUserId];
                }
                req.session.userId = user.id;
                req.session.username = user.username;
                req.session.contacts = contacts;
                // Do not store sensitive key in session

                console.log(`User ${user.username} logged in`);
                res.status(200).send('Login successful');
            } catch (err) {
                console.error('Database error: ', err);
                return res.status(500).send('Server error during login');
            }
        });

        // --- LOGOUT ROUTE ---
        app.post('/logout', (req, res) => {
            const userId = req.session.userId;
            if (userId && userSockets[userId]) {
                userSockets[userId].forEach(socketId => {
                    io.to(socketId).emit('session-changed');
                });
                delete userSockets[userId];
            }

            req.session.destroy(err => {
                if (err) {
                    console.error('Error destroying session: ', err);
                    return res.status(500).send('Error logging out.');
                }
                res.clearCookie('connect.sid');
                res.status(200).send('Logged out successfully.');
            });
        });

        // --- CHECK AUTH STATUS ---
        app.get('/check-auth', (req, res) => {
            if (req.session.userId)
                res.status(200).json({
                    authenticated: true,
                    username: req.session.username
                });
            else
                res.status(200).json({
                    authenticated: false
                });
        });

        // --- MAIN CHAT PROTECTION ---
        app.get('/', isAuthenticated, (req, res) => {
            res.sendFile(__dirname + '/index.html');
        });

        app.get('/index.html', isAuthenticated, (req, res) => {
            res.sendFile(__dirname + '/index.html');
        });

        // --- CONTACTS FETCHING ROUTE (with decryption) ---
        app.get('/contacts', isAuthenticated, async (req, res) => {
            try {
                const user = await db.get(`SELECT * FROM users WHERE id = ?`, [req.session.userId]);
                if (!user) return res.status(401).send('User not found');

                const contactRecord = await db.get(`SELECT * FROM contacts WHERE user_id = ?`, [req.session.userId]);
                if (!contactRecord)
                    return res.status(500).send("The user's contacts data couldn't be found.");

                // Ensure the key is a Buffer
                let contacts = [];
                try {
                    if (!req.session.derivedKey)
                        return res.status(401).send('Session key missing. Please log in again.');

                    // Convert derivedKey to Buffer if it's an object
                    let key = req.session.derivedKey;
                    if (!(key instanceof Buffer)) {
                        if (key && key.type === 'Buffer' && Array.isArray(key.data)) {
                            key = Buffer.from(key.data);
                        } else
                            throw new Error('Invalid key format in session');
                    }
                    const decrypted = await decrypt(contactRecord.encrypted_contacts, key, Buffer.from(contactRecord.iv, 'hex'));
                    console.log('Decrypted contacts:', decrypted);
                    contacts = JSON.parse(decrypted);
                } catch (e) {
                    console.error('Failed to decrypt contacts', e);
                    return res.status(500).send('Failed to decrypt contacts. Please ensure your login credentials are correct.');
                }

                // Map contactUserID to username
                const contactUserIDs = contacts.map(c => c.contactUserID);
                let contactUsernamesMap = {};
                if (contactUserIDs.length > 0) {
                    const placeholders = contactUserIDs.map(() => '?').join(',');
                    const users = await db.all(`SELECT id, username FROM users WHERE id IN (${placeholders})`, contactUserIDs);
                    users.forEach(u => { contactUsernamesMap[u.id] = u.username; });
                }
                const contactsWithUsernames = contacts.map(c => ({
                    contactUserID: c.contactUserID,
                    contactUsername: contactUsernamesMap[c.contactUserID] || 'Unknown User',
                    alias: c.alias
                }));

                res.json(contactsWithUsernames);
            } catch (err) {
                console.error('Error fetching contacts:', err);
                res.status(500).send('Error fetching contacts.');
            }
        });

        // --- CONTACT ADDING ROUTE (with encryption) ---
        app.post('/contacts/add', isAuthenticated, async (req, res) => {
            const { contactUsername, alias } = req.body;

            const user = await db.get(`SELECT * FROM users WHERE username = ?`, [contactUsername]);
            if (!user)
                return res.status(404).send('User not found.');

            const contactRecord = await db.get(`SELECT * FROM contacts WHERE user_id = ?`, [req.session.userId]);
            if (!contactRecord)
                return res.status(500).send("The user's contacts data couldn't be found.");

            if (!contactUsername)
                return res.status(400).send('Contact Username is required.');

            // Convert derivedKey to Buffer if it's an object
            let key = req.session.derivedKey;
            if (!(key instanceof Buffer)) {
                if (key && key.type === 'Buffer' && Array.isArray(key.data))
                    key = Buffer.from(key.data);
                else
                    throw new Error('Invalid key format in session');
            }

            try {
                if (!req.session.derivedKey)
                    return res.status(401).send('Session key missing. Please log in again.');

                try {

                    const decrypted = await decrypt(contactRecord.encrypted_contacts, key, Buffer.from(contactRecord.iv, 'hex'));
                    console.log('Decrypted contacts:', decrypted);
                    contacts = JSON.parse(decrypted);
                } catch (e) {
                    console.error('Failed to decrypt contacts for add', e);
                    return res.status(401).send('Invalid password for decryption.');
                }

                // Check if contact already exists to prevent duplicates
                const contactExists = contacts.some(c => c.contactUserID === user.id);
                if (contactExists)
                    return res.status(500).send('Contact already in your list');

                // Add the new contact
                const newContact = {
                    contactUserID: user.id,
                    alias: alias || contactUsername
                }
                contacts.push(newContact);

                // Encrypt updated contacts
                const encrypted_contacts = await encrypt(JSON.stringify(contacts), key, Buffer.from(contactRecord.iv, 'hex'));

                await db.run(`UPDATE contacts SET encrypted_contacts = ? WHERE user_id = ?`, [encrypted_contacts, req.session.userId]);
                console.log('Contacts updated for user:', req.session.userId);

                res.status(200).json({
                    message: 'Contact added successfully.',
                    newContact: newContact
                });
            } catch (err) {
                console.error('Error adding contact:', err);
                res.status(500).send('Error adding contact.');
            }
        });

        // --- SOCKET.IO INTEGRATION ---
        const wrap = middleware => (socket, next) => middleware(socket.request, {}, next);
        io.use(wrap(sessionMiddleware));

        io.use((socket, next) => {
            if (socket.request.session && socket.request.session.userId) {
                socket.request.username = socket.request.session.username;
                next();
            } else
                next(new Error('Authentication error: Not logged in.'));
        });

        io.on('connection', (socket) => {
            const userId = socket.request.session.userId;
            if (userId) {
                if (!userSockets[userId]) userSockets[userId] = [];
                userSockets[userId].push(socket.id);
            }

            socket.on('chat message', (data) => {
                const userId = socket.request.session.userId;
                const senderUsername = socket.request.username;

                if (!userId) {
                    console.warn(`Attempted to send message without a valid userId: ${socket.id}`);
                    return;
                }

                const messageData = {
                    id: userId,
                    username: senderUsername,
                    message: data.message
                };

                console.log(`Message from ${messageData.username} (${messageData.id}): ${messageData.message}`);
                io.emit('chat message', messageData);
            });

            socket.on('disconnect', () => {
                const userId = socket.request.session.userId;
                if (userId && userSockets[userId]) {
                    userSockets[userId] = userSockets[userId].filter(id => id !== socket.id);
                    if (userSockets[userId].length === 0) delete userSockets[userId];
                }
                console.log(`User disconnected: ${socket.id} (Username: ${socket.request.username || 'N/A'})`);
            });
        });

        // --- START SERVER ---
        server.listen(PORT, () => {
            console.log(`Server listening on port ${PORT}`);
            console.log(`Default login user: testuser / password`);
            console.log(`Access login page at http://localhost:${PORT}/login.html`);
        });

    } catch (err) {
        console.error('Failed to initialize app: ', err);
        process.exit(1);
    }
}

startApp().catch(err => {
    console.error('Error starting app:', err);
    process.exit(1);
});