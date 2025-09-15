const sqlite = require('sqlite');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'default_32_byte_long_key_123456789012'; // 32 bytes
const IV_LENGTH = 16; // AES block size

function encrypt(text, key = ENCRYPTION_KEY) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const salt = crypto.randomBytes(16);
    const derivedKey = crypto.scryptSync(key, salt, 32);
    const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        encryptedData: encrypted,
        iv: iv.toString('hex'),
        salt: salt.toString('hex')
    };
}

function decrypt(encrypted, ivHex, saltHex, key = ENCRYPTION_KEY) {
    const iv = Buffer.from(ivHex, 'hex');
    const salt = Buffer.from(saltHex, 'hex');
    const derivedKey = crypto.scryptSync(key, salt, 32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

async function initializeDB() {
    let db;
    try {
        db = await sqlite.open({
            filename: './TokyoChat.sqlite',
            driver: sqlite3.Database
        });
        console.log("Connected to the SQLite database");

        await db.run(
            `CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )`);
        console.log("Users table checked");

        await db.run(
            `CREATE TABLE IF NOT EXISTS contacts (
                user_id INTEGER PRIMARY KEY,
                encrypted_contacts TEXT NOT NULL,
                iv TEXT NOT NULL,
                salt TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`);
        console.log("Encrypted contacts table checked");

        await db.run(
            `CREATE TABLE IF NOT EXISTS rooms (
                room_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
                )`);
        console.log("Rooms table checked");

        const defualtRooms = ['General', 'Random'];
        for (const roomName of defualtRooms) {
            const room = await db.get(`SELECT room_id FROM rooms WHERE name = ?`, [roomName]);
            if (!room) {
                await db.run('INSERT INTO rooms (name) VALUES (?)', [roomName]);
                console.log(`Default room '${roomName} inserted.`);
            }
        }

        const row = await db.get("SELECT COUNT(*) as count FROM users");
        if (row.count === 0) {
            const defaultUsername = "testuser";
            const defaultPassword = "password";
            console.log(`No users found. Attempting to insert default user '${defaultUsername}'...`);
            const hash = await bcrypt.hash(defaultPassword, 10);
            const result = await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [defaultUsername, hash]);
            console.log(`Default user '${defaultUsername}' inserted with ID: ${result.lastID}`);
        }

        return db;
    } catch (err) {
        console.error("Database initialization failed: ", err.message);
        process.exit(1);
    }
}

// Export encryption functions for use elsewhere
module.exports = {
    dbPromise: initializeDB(),
    encrypt,
    decrypt
};