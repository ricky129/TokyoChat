const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const dbPromise = require('./database');
const session = require('express-session');
const bcrypt = require('bcryptjs');

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

/**
 * Derive a key from password and salt using PBKDF2
 * @param {*} password user password
 * @param {*} salt random string of bits added to a password before it's hashed and stored
 * @returns Derived key from password and salt params
 */
async function deriveKey(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, 100000, 32, 'sha512', (err, derivedKey) => {
            if (err)
                reject(err);
            resolve(derivedKey);
        })
    })
}
/**
 * Encrypt the 'text param using the 'aes-256-cbc' algorithm.
 * @param {*} text The text to encrypt
 * @param {*} key A string of bits that acts as a secret code for scrambling and unscrambling data, with randomness and security enhanced by the salt variable
 * @param {*} iv fixed-size input added to enchance the randomness and security of the encryption using the key
 * @returns encrypted 'text' param using the 'aes-256-cbc' algorithm.
 */
async function encrypt(text, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

/**
 * Decrypt the 'encryptedText' variable using the 'aes-256-cbc' algorithm.
 * @param {*} encryptedText The text to decrypt
 * @param {*} key A string of bits that acts as a secret code for scrambling and unscrambling data, with randomness and security enhanced by the salt variable
 * @param {*} iv fixed-size input added to enchance the randomness and security of the encryption using the key
 * @returns encrypted 'encryptedText' param using the 'aes-256-cbc' algorithm.
 */
async function decrypt(encryptedText, key, iv) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

async function startApp() {
    let db;
    const userSockets = {};

    console.log('Initializing database...');
    try {
        db = await dbPromise;
        console.log('Database initialized successfully, db:', !!db);

        // Body parsers
        app.use(express.urlencoded({
            extended: true
        }));
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
        app.post('/register', async (req, res) => {
            //console.log('Register body:', req.body);
            const { username, password } = req.body;

            if (!username || !password)
                return res.status(400).send('Username and password are required.');

            try {
                const existingUser = await db.get(`SELECT id FROM users WHERE username = ?`, [username]);
                if (existingUser)
                    return res.status(409).send('Username already taken.');

                const hash = await bcrypt.hash(password, 10);

                const result = await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash]);
                await db.run(`INSERT INTO contacts (user_id, contacts_json) VALUES (?, ?)`, [result.lastID, JSON.stringify([])]);

                const userId = req.session.userId;
                const oldUserId = req.session.userId;
                if (oldUserId && userSockets[oldUserId]) {
                    userSockets[userId].forEach(socketId => {
                        io.to(socketId).emit('session-changed');
                    });
                    delete userSockets[userId];
                }

                req.session.userId = result.lastID;
                req.session.username = username;
                /*req.session.decrypted_contacts = [];
                req.session.encryptionKey = derivedKey.toString('hex'); // Store encryption key in session after registration*/
                console.log(`User ${username} registered with ID: ${result.lastID}`);
                res.status(200).send('Registration successful!');

            } catch (dbErr) {
                if (dbErr.code === 'SQLITE_CONSTRAINT' || dbErr.code === 'SQLITE_CONSTRAINT_UNIQUE')
                    return res.status(409).send('Username already taken.');
                console.error('Error inserting user or contacts:', dbErr);
                return res.status(500).send('Error registering user.');
            }
        }
        );

        // Login Route
        app.post('/login', async (req, res) => {
            //console.log('Login body:', req.body);
            const { username, password } = req.body;
            //console.log('Login request received: ', { username });

            if (!username || !password)
                return res.status(400).send('Username and password are required');

            try {
                const user = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
                if (!user)
                    return res.status(401).send('Invalid username');

                const result = await bcrypt.compare(password, user.password);
                if (!result)
                    return res.status(401).send('Invalid password');

                const userId = req.session.userId;
                if (userId && userSockets[userId]) {
                    userSockets[userId].forEach(socketId => {
                        io.to(socketId).emit('session-changed');
                    });
                    delete userSockets[userId];
                }
                req.session.userId = user.id;
                req.session.username = user.username;
                const contactRecord = await db.get(`SELECT contacts_json FROM contacts WHERE user_id = ?`, [user.id]);
                req.session.contacts = contactRecord ? JSON.parse(contactRecord.contacts_json) : [];
                console.log(`User ${user.username} logged in`);
                res.status(200).send('Login successful');
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

        // Contacts fetching Route
        app.get('/contacts', isAuthenticated, async (req, res) => {
            try {
                const contactRecord = await db.get(`SELECT * FROM contacts WHERE user_id = ?`, [req.session.userId]);
                if (!contactRecord)
                    return res.status(500).send("The user's contacts data couldn't be found");

                const contacts = JSON.parse(contactRecord.contacts_json);

                // Map contactUserID to username
                const contactUserIDs = contacts.map(c => c.contactUserID);
                let contactUsernamesMap = {};
                if (contactUserIDs.length > 0) {
                    const placeHolders = contactUserIDs.map(() => '?').join(',');
                    const usersFromDB = await db.all(`SELECT id, username FROM users WHERE id IN (${placeHolders})`, contactUserIDs);
                    usersFromDB.forEach(element => {
                        contactUsernamesMap[element.id] = element.username;
                    });
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

        // Contact adding Route
        app.post('/contacts/add', isAuthenticated, async (req, res) => {
            const { contactUsername, alias } = req.body;
            if (!contactUsername)
                return res.status(400).send('Contact Username is required.');

            try {
                const contactUser = await db.get(`SELECT * FROM users WHERE username = ?`, [contactUsername]);
                if (!contactUser)
                    return res.status(404).send('Contact user not found.');

                const contactRecord = await db.get(`SELECT * FROM contacts WHERE user_id = ?`, [req.session.userId]);
                if (!contactRecord)
                    return res.status(500).send("The user's contacts data couldn't be found");

                const currentContacts = JSON.parse(contactRecord.contacts_json);

                // Check if contact already exists to prevent duplicates
                const contactExists = currentContacts.some(c => c.contactUserID === contactUser.id);
                if (contactExists)
                    return res.status(500).send('Contact already in your list');

                // Add the new contact
                const newContact = {
                    contactUserID: contactUser.id,
                    alias: alias || contactUsername
                }
                currentContacts.push(newContact);

                await db.run(`UPDATE contacts SET contacts_json = ? WHERE user_id = ?`, [JSON.stringify(currentContacts), req.session.userId]);
                console.log('Contacts updated for user:', req.session.userId);

                res.status(200).json({
                    message: 'Contact added successfully.',
                    newContact: newContact
                });
            } catch (err) {
                console.error('Error adding contact:', err);
                res.status(500).send('Error adding contact.');
            }
        })

        // Socket IO integration
        // By calling io.use(wrap(sessionMiddleware));, the code ensures that every new Socket.IO connection will 
        // have access to the session data, just like regular HTTP requests. This is important for features like 
        // authentication and user tracking, allowing you to access session information inside your Socket.IO event handlers.
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

            // Message sent Route
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