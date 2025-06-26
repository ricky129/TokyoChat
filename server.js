const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const dbPromise = require('./database');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { start } = require('repl');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const CLI_PORT = process.argv[2] ? parseInt(process.argv[2], 10) : null;
const PORT = CLI_PORT || process.env.PORT || 3000;

if (CLI_PORT && (isNaN(PORT) || PORT <= 0 || PORT > 65535)) {
    console.error(`Error: Invalid port specified from the command line: ${process.argv[2]}. Using default port 3000`);
}

const SESSION_SECRET = 'ilmiodolcepreferitoeiltiramisu';

const sessionMiddleware = session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
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

let db;

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

                if (err) {
                    console.error('Error hashing password:', err);
                    return res.status(500).send('Error registering user.');
                }

                try {
                    const result = await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`,
                        [username, hash]
                    );

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
        app.post('/login', (req, res) => {
            console.log('Login body:', req.body);
            const { username, password } = req.body;
            console.log('Login request received: ', { username });

            if (!username || !password)
                return res.status(400).send('Username and password are required');

            db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
                console.log('Database query executed, err:', err, 'user:', user);

                if (err) {
                    console.error('Database error: ', err);
                    return res.status(500).send('Server error during login');
                }
                if (!user)
                    return res.status(401).send('Invalid username or password');

                bcrypt.compare(password, user.password, (err, result) => {
                    console.log('Password comparison executed, err:', err, 'result:', result);

                    if (err) {
                        console.error('Error comparing passwords: ', err);
                        return res.status(500).send('Server error during login');
                    }

                    if (result) {
                        req.session.userId = user.id;
                        req.session.username = user.username;
                        console.log(`User ${user.username} logged in`);
                        res.status(200).send('Login successful');
                    } else
                        res.status(401).send('Invalid username or password');

                });

            });
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

        // Socket.IO integration
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
