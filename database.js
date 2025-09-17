const sqlite = require('sqlite');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'default_32_byte_long_key_123456789012'; // 32 bytes
const IV_LENGTH = 16; // AES block size

// Reusable function to derive key
async function deriveKey(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, 100000, 32, 'sha512', (err, derivedKey) => {
            if (err) return reject(err);
            resolve(derivedKey);
        });
    });
}

function encrypt(text, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        encryptedData: encrypted,
        iv: iv.toString('hex')
    };
}

function decrypt(encrypted, ivHex, key) {
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

async function initializeDB() {
    try {
        const db = await sqlite.open({
            filename: './TokyoChat.sqlite',
            driver: sqlite3.Database
        });
        console.log('Connected to the SQLite database');

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

        await db.run(`
            CREATE TABLE IF NOT EXISTS private_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT
            )`);
        console.log('private_chats table checked');

        await db.run(`
            CREATE TABLE IF NOT EXISTS chat_participants (
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (chat_id, user_id),
                FOREIGN KEY (chat_id) REFERENCES private_chats(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`);
        console.log('chat_participants table checked');

        await db.run(`
            CREATE TABLE IF NOT EXISTS private_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                encrypted_message TEXT NOT NULL,
                iv TEXT NOT NULL,
                salt TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (chat_id) REFERENCES private_chats(id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
            )`);
        console.log('private_messages table checked');

        const defaultRooms = ['General', 'Random'];
        for (const roomName of defaultRooms) {
            const room = await db.get(`SELECT room_id FROM rooms WHERE name = ?`, [roomName]);
            if (!room) {
                await db.run('INSERT INTO rooms (name) VALUES (?)', [roomName]);
                console.log(`Default room '${roomName}' inserted.`);
            }
        }

        const row = await db.get("SELECT COUNT(*) as count FROM users");
        if (row.count === 0) {
            const defaultUsername1 = "testuser";
            const defaultPassword = "password";
            const defaultUsername2 = "testuser2";
            console.log(`No users found. Creating default users...`);

            const hash = await bcrypt.hash(defaultPassword, 10);
            
            const result1 = await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [defaultUsername1, hash]);
            const userId1 = result1.lastID;
            
            const result2 = await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [defaultUsername2, hash]);
            const userId2 = result2.lastID;
            console.log(`Default users '${defaultUsername1}' (ID: ${userId1}) and '${defaultUsername2}' (ID: ${userId2}) created.`);

            const contacts1 = [{ contactUserID: userId2, alias: 'user2', contactUsername: defaultUsername2 }];
            const contacts2 = [{ contactUserID: userId1, alias: 'user1', contactUsername: defaultUsername1 }];

            const salt1 = crypto.randomBytes(16);
            const iv1 = crypto.randomBytes(16);
            const key1 = await deriveKey(defaultPassword, salt1);

            const salt2 = crypto.randomBytes(16);
            const iv2 = crypto.randomBytes(16);
            const key2 = await deriveKey(defaultPassword, salt2);

            const encrypted_contacts1 = encrypt(JSON.stringify(contacts1), key1, iv1);
            await db.run(
                `INSERT INTO contacts (user_id, encrypted_contacts, iv, salt) VALUES (?, ?, ?, ?)`,
                [userId1, encrypted_contacts1.encryptedData, encrypted_contacts1.iv, salt1.toString('hex')]
            );

            const encrypted_contacts2 = encrypt(JSON.stringify(contacts2), key2, iv2);
            await db.run(
                `INSERT INTO contacts (user_id, encrypted_contacts, iv, salt) VALUES (?, ?, ?, ?)`,
                [userId2, encrypted_contacts2.encryptedData, encrypted_contacts2.iv, salt2.toString('hex')]
            );
            console.log("Default contacts established for 'testuser' and 'testuser2'.");
        }

        return db;
    } catch (err) {
        console.error("Database initialization failed: ", err.message);
        process.exit(1);
    }
}

module.exports = {
    dbPromise: initializeDB(),
    encrypt,
    decrypt,
    deriveKey
};