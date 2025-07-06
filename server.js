const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const dbPromise = require('./database');
const session = require('express-session');
const bcrypt = require('bcryptjs');
<<<<<<< Updated upstream
const { start } = require('repl');
=======
const crypto = require('crypto');
>>>>>>> Stashed changes

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const CLI_PORT = process.argv[2] ? parseInt(process.argv[2], 10) : null;
const PORT = CLI_PORT || process.env.PORT || 3000;

if (CLI_PORT && (isNaN(PORT) || PORT <= 0 || PORT > 65535)) {
    console.error(`Error: Invalid port specified from the command line: ${process.argv[2]}. Using default port 3000`);
}

const SESSION_SECRET = 'ilmiodolcepreferitoeiltiramisu';

const redisClient = redis.createClient({
    url: 'redis://localhost:6379'
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));
redisClient.connect().catch(console.error);

const sessionMiddleware = session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 86400000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
    }
});

function isAuthenticated(req, res, next) {
    if (req.session.userId)
        next();
    else
        res.status(401).redirect('/login.html');
}

<<<<<<< Updated upstream
let db;
=======
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
>>>>>>> Stashed changes

async function startApp() {
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

        // Registration Route
        app.post('/register', (req, res) => {
            console.log('Register body:', req.body);
            const { username, password } = req.body;
            if (!username || !password)
                return res.status(400).send('Username and password are required.');

            bcrypt.hash(password, 10, async (err, hash) => {

<<<<<<< Updated upstream
                if (err) {
                    console.error('Error hashing password:', err);
                    return res.status(500).send('Error registering user.');
                }

                try {
                    const result = await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`,
                        [username, hash]
                    );
=======
                const hash = await bcrypt.hash(password, 10);
                const encryptionkey = crypto.randomBytes(32);
                const result = await db.run(`INSERT INTO users (username, password, encryption_key) VALUES (?, ?, ?)`,
                    [username, hash, encryptionkey]);

                // ENCRYPT EMPTY CONTACTS FOR NEW USER
                const userId = result.lastID;
                const contacts = [];
                const salt = crypto.randomBytes(16);
                const iv = crypto.randomBytes(16).toString('hex');
                const encrypted_contacts = await encrypt(JSON.stringify(contacts), encryptionkey, Buffer.from(iv, 'hex'));

                await db.run(`INSERT INTO contacts (user_id, encrypted_contacts, iv, salt) VALUES (?, ?, ?, ?)`,
                    [userId, encrypted_contacts, iv, salt.toString('hex')]);

                const oldUserId = req.session.userId;
                if (oldUserId && userSockets[oldUserId]) {
                    userSockets[oldUserId].forEach(socketId => {
                        io.to(socketId).emit('session-changed');
                    });
                    delete userSockets[oldUserId];
                }

                const token = jwt.sign({ userId }, TOKEN_SECRET, { expiresIn: '1d' });
                await db.run(
                    `INSERT INTO tokens (token, user_id, encryption_key, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
                    [token, userId, encryptionkey, Date.now(), Date.now() + 86400000]
                );

                req.session.userId = userId;
                req.session.username = username;
>>>>>>> Stashed changes

                    console.log(`User ${username} registered with ID: ${result.lastID}`);
                    req.session.userId = result.lastID;
                    req.session.username = username;
                    res.status(200).send('Registration successful!');

                } catch (dbErr) {
                    if (dbErr.code === 'SQLITE_CONSTRAINT')
                        return res.status(409).send('Username already taken.');
                    console.error('Error inserting user:', dbErr);
                    return res.status().send('Error registering user.');
                }
            });
        });

        // Login Route
        app.post('/login', async (req, res) => {
            console.log('Login body:', req.body);
            const { username, password } = req.body;
            console.log('Login request received: ', { username });

            if (!username || !password)
                return res.status(400).send('Username and password are required');

            try {
                const user = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
                console.log('Database query executed:', 'user:', user);

                if (!user)
                    return res.status(401).send('Invalid username or password');

                const result = bcrypt.compare(password, user.password);
                console.log('Password comparison executed, result:', result);

<<<<<<< Updated upstream
                if (result) {
                    req.session.userId = user.id;
                    req.session.username = user.username;
                    console.log(`User ${user.username} logged in`);
                    res.status(200).send('Login successful');
                } else
                    res.status(401).send('Invalid username or password');
=======
                // Fetch encrypted contacts
                const contactRecord = await db.get(`SELECT encrypted_contacts, iv, salt FROM contacts WHERE user_id = ?`, [user.id]);
                let contacts = [];
                if (contactRecord) {
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

                console.log(`User ${user.username} logged in`);
                res.status(200).send('Login successful');
>>>>>>> Stashed changes
            } catch (err) {
                console.error('Database error: ', err);
                return res.status(500).send('Server error during login');
            }
        });

        // Logout Route
        app.post('/logout', (req, res) => {
            req.session.destroy(err => {
                if (err) {
                    console.error('Error destroying session: ', err);
                    return res.status(500).send('Error logging out.');
                }
                res.clearCookie('connect.sid');
                res.status(200).send('Logged out successfully.');
            });
        });

        // Check Auth Status
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

        // Protect the main chat page
        app.get('/', isAuthenticated, (req, res) => {
            res.sendFile(__dirname + '/index.html');
        });

        app.get('/index.html', isAuthenticated, (req, res) => {
            res.sendFile(__dirname + '/index.html');
        });

<<<<<<< Updated upstream
        // Socket.IO integration
=======
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
                    const key = Buffer.from(user.encryption_key);
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

            if (!contactUsername)
                return res.status(400).send('Contact Username is required.');

            try {
                const user = await db.get(`SELECT * FROM users WHERE username = ?`, [contactUsername]);
                if (!user)
                    return res.status(404).send('User not found.');

                const contactRecord = await db.get(`SELECT * FROM contacts WHERE user_id = ?`, [req.session.userId]);
                if (!contactRecord)
                    return res.status(500).send("The user's contacts data couldn't be found.");

                let contacts = [];

                try {
                    const key = Buffer.from (user.encryption_key);
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
>>>>>>> Stashed changes
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
            console.log(`A user connected: ${socket.id} (Username: ${socket.request.username || 'N/A'})`);

            socket.on('chat message', (data) => {
                const senderUsername = socket.request.username || socket.id;
                const messageData = {
                    id: socket.id,
                    username: senderUsername,
                    message: data.message
                };
                console.log(`Message from ${messageData.username} (${messageData.id}): ${messageData.message}`);
                io.emit('chat message', messageData);
            });

            socket.on('disconnect', () => {
                console.log(`User disconnected: ${socket.id} (Username: ${socket.request.username || 'N/A'})`);
            });
        });

        // Start the server only after everything is ready
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
