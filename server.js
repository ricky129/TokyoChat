import 'dotenv/config';
import express, { urlencoded, json, static as expressStatic } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dbPromise from './database.js';
import session from 'express-session';
import { createClient } from 'redis';
import { hash as _hash, compare } from 'bcryptjs';
import { randomBytes } from 'crypto';
import jwt from 'jsonwebtoken';
import { RedisStore } from 'connect-redis';
const { sign } = jwt;

const app = express();
const server = createServer(app);
const io = new Server(server);

const TOKEN_SECRET = process.env.TOKEN_SECRET;
if (!TOKEN_SECRET) {
    console.error('Error: TOKEN_SECRET environment variable is required.');
    process.exit(1);
}
const SESSION_SECRET = 'ilmiodolcepreferitoeiltiramisu';

const CLI_PORT = process.argv[2] ? parseInt(process.argv[2], 10) : null;
if (CLI_PORT && (isNaN(CLI_PORT) || CLI_PORT <= 0 || CLI_PORT > 65535)) {
    console.error(`Error: Invalid port specified from the command line: ${process.argv[2]}. Using default port 3000`);
    CLI_PORT = null;
}
const PORT = CLI_PORT || process.env.PORT || 3000;

const redisClient = createClient({
    url: 'redis://localhost:6379'
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));
redisClient.connect().catch(console.error);

const sessionMiddleware = session({
    store: new RedisStore({ client: redisClient }),
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

async function startApp() {
    let db;
    const userSockets = {};
    try {
        db = await dbPromise;
        console.log('Database initialized successfully, db:', !!db);

        // Body parsers
        app.use(urlencoded({ extended: true }));
        app.use(json());
        app.use(sessionMiddleware);
        app.use((req, res, next) => {
            if (!db) {
                console.error('Database not initialized yet for request:', req.url);
                return res.status(503).send('Server is starting, please try again in a moment.');
            }
            next();
        });
        app.use(expressStatic('public'));

        // Registration Route
        app.post('/register', async (req, res) => {
            console.log('Register body:', req.body);
            const { username, password } = req.body;
            if (!username || !password)
                return res.status(400).send('Username and password are required.');

            try {
                const existingUser = await db.get(`SELECT id FROM users WHERE username = ?`, [username]);
                if (existingUser)
                    return res.status(409).send('Username already taken');

                const hash = await _hash(password, 10);
                const result = await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash]);
                const userId = result.lastID;

                const encryptionKey = randomBytes(32);
                const { encryptedData, iv } = await (await import('./database.js')).encrypt(JSON.stringify([]), encryptionKey);
                await db.run(`INSERT INTO contacts (user_id, encrypted_contacts, iv) VALUES (?, ?, ?)`, [userId, encryptedData, iv]);

                const token = sign({ userId }, TOKEN_SECRET, { expiresIn: '1d' });
                await db.run(
                    `INSERT INTO tokens (token, user_id, encryption_key, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
                    [token, userId, encryptionKey, Date.now(), Date.now() + 86400000]
                );

                const oldUserId = req.session.userId;
                if (oldUserId && userSockets[oldUserId]) {
                    userSockets[oldUserId].forEach(socketId => {
                        io.to(socketId).emit('session-changed');
                    });
                    delete userSockets[oldUserId];
                }

                req.session.userId = userId;
                req.session.username = username;

                console.log(`User ${username} registered with ID: ${result.lastID}`);
                res.status(200).json({ message: 'Registration successful', token });
            } catch (dbErr) {
                console.error('Error inserting user:', dbErr);
                res.status(500).send('Error registering user.');
            }
        });

        // Login Route
        app.post('/login', async (req, res) => {
            console.log('Login body:', req.body);
            const { username, password } = req.body;

            if (!username || !password)
                return res.status(400).send('Username and password are required');

            try {
                const user = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
                if (!user)
                    return res.status(401).send('Invalid username or password');

                const result = await compare(password, user.password);
                if (!result)
                    return res.status(401).send('Invalid username or password');

                let encryptionKey;
                const tokenRecord = await db.get(`SELECT encryption_key FROM tokens 
                            WHERE user_id = ? AND expires_at > ? 
                            ORDER BY created_at DESC LIMIT 1`,
                    [user.id, Date.now()]
                );
                if (tokenRecord)
                    encryptionKey = Buffer.from(tokenRecord.encryption_key);
                else
                    encryptionKey = randomBytes(32);

                const token = sign({ userId: user.id }, TOKEN_SECRET, { expiresIn: '1d' });
                await db.run(`INSERT INTO tokens (token, user_id, encryption_key, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
                    [token, user.id, encryptionKey, Date.now(), Date.now() + 86400000]
                );

                const contactRecord = await db.get(`SELECT encrypted_contacts, iv FROM contacts WHERE user_id = ?`, [user.id]);
                let contacts = [];
                if (contactRecord) {
                    try {
                        if (tokenRecord) {
                            const { decrypt } = await import('./database.js');
                            const decrypted = decrypt(contactRecord.encrypted_contacts, contactRecord.iv, encryptionKey);
                            contacts = JSON.parse(decrypted);
                        } else {
                            console.warn(`No valid token found for user ${user.id}, cannot decrypt contacts`);
                            contacts = [];
                        }
                    } catch (e) {
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
                res.status(200).json({ message: 'Login successful', token });
            } catch (err) {
                console.error('Database error: ', err);
                return res.status(500).send('Server error during login');
            }
        });

        // Logout Route
        app.post('/logout', (req, res) => {

            const userId = req.session.userId;
            if (userId && userSockets[userId]) {
                userSockets[userId].forEach(socketId => {
                    io.to(socketId).emit('session-changed');
                });
                delete userSockets[userId];
            }

            if (userId)
                db.run(`DELETE FROM tokens WHERE user_id = ?`, [userId]);

            req.session.destroy(err => {
                if (err) {
                    console.error('Error destroying session: ', err);
                    return res.status(500).send('Error logging out.');
                }
                res.clearCookie('connect.sid');
                res.status(200).send('Logged out successfully.');
            });
        });

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

        // --- CONTACTS FETCHING ROUTE ---
        app.get('/contacts', async (req, res) => {
            const token = req.headers['authorization']?.replace('Bearer ', '');
            if (!token)
                return res.status(401).send('Token required');

            try {
                const tokenRecord = await db.get(`SELECT * FROM tokens WHERE token = ? AND expires_at > ?`, [token, Date.now()]);
                if (!tokenRecord)
                    return res.status(401).send('Invalid or expired token');

                const user = await db.get(`SELECT * FROM users WHERE id = ?`, [tokenRecord.user_id]);
                if (!user)
                    return res.status(401).send('User not found');

                const contactRecord = await db.get(`SELECT * FROM contacts WHERE user_id = ?`, [tokenRecord.user_id]);
                if (!contactRecord)
                    return res.status(500).send("The user's contacts data couldn't be found.");

                let contacts = [];
                try {
                    const key = Buffer.from(tokenRecord.encryption_key);
                    const decrypted = (await import('./database.js')).decrypt(contactRecord.encrypted_contacts, contactRecord.iv, key);
                    console.log('Decrypted contacts:', decrypted);
                    contacts = JSON.parse(decrypted);
                } catch (e) {
                    console.error('Failed to decrypt contacts', e);
                    return res.status(500).send('Failed to decrypt contacts.')
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

        // --- CONTACT ADDING ROUTE ---
        app.post('/contacts/add', async (req, res) => {
            const { contactUsername, alias } = req.body;
            if (!contactUsername)
                return res.status(400).send('Contact Username is required.');

            const token = req.headers['authorization']?.replace('Bearer ', '');
            if (!token)
                return res.status(401).send('Token required');



            try {
                const tokenRecord = await db.get(`SELECT * FROM tokens WHERE token = ? AND expires_at > ?`, [token, Date.now()]);
                if (!tokenRecord)
                    return res.status(401).send('Invalid or expired token');

                const user = await db.get(`SELECT * FROM users WHERE username = ?`, [contactUsername]);
                if (!user)
                    return res.status(404).send('User not found.');

                const contactRecord = await db.get(`SELECT * FROM contacts WHERE user_id = ?`, [tokenRecord.user_id]);
                if (!contactRecord)
                    return res.status(500).send("The user's contacts data couldn't be found.");

                let contacts = [];

                try {
                    const key = Buffer.from(tokenRecord.encryption_key);
                    const decrypted = await (await import('./database.js')).decrypt(contactRecord.encrypted_contacts, contactRecord.iv, key);
                    console.log('Decrypted contacts:', decrypted);
                    contacts = JSON.parse(decrypted);
                } catch (e) {
                    console.error('Failed to decrypt contacts for add', e);
                    return res.status(500).send('Failed to decrypt contacts.');
                }

                const contactExists = contacts.some(c => c.contactUserID === user.id);
                if (contactExists)
                    return res.status(409).send('Contact already in your list');

                const newContact = {
                    contactUserID: user.id,
                    alias: alias || contactUsername
                }
                contacts.push(newContact);

                const { encryptedData, iv } = await (await import('./database.js')).encrypt(JSON.stringify(contacts), Buffer.from(tokenRecord.encryption_key));
                await db.run(`UPDATE contacts SET encrypted_contacts = ?, iv = ? WHERE user_id = ?`, [encryptedData, iv, tokenRecord.user_id]);
                console.log('Contacts updated for user:', tokenRecord.user_id);

                res.status(200).json({
                    message: 'Contact added successfully.',
                    newContact
                });
            } catch (err) {
                console.error('Error adding contact:', err);
                res.status(500).send('Error adding contact.');
            }
        });

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
                if (!userSockets[userId])
                    userSockets[userId] = [];
                userSockets[userId].push(socket.id);
            }
            console.log(`A user connected: ${socket.id} (Username: ${socket.request.username || 'N/A'})`);

            socket.on('chat message', (data) => {
                const userId = socket.request.session.userId;
                if (!userId) {
                    console.warn(`Attempted to send a message without a valid userId: ${socket.id}`);
                    return;
                }
                const senderUsername = socket.request.username || socket.id;
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
                    if (userSockets[userId].length === 0)
                        delete userSockets[userId];
                }
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
