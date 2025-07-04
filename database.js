const sqlite = require('sqlite');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcryptjs');

async function initializeDB() {
    let db;
    try {

        db = await sqlite.open({
            filename: './TokyoChat.sqlite',
            driver: sqlite3.Database
        });
        // console.log("Connected to the SQLite database");

        await db.run(
            `CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )`);
        //console.log("Users table checked");

        await db.run(
            `CREATE TABLE IF NOT EXISTS contacts (
                user_id INTEGER PRIMARY KEY,
                contacts_json TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )`);
        //console.log("Encrypted contacts table checked");

        const row = await db.get("SELECT COUNT(*) as count FROM users");
        if (row.count === 0) {
            const defaultUsername = "testuser";
            const defaultPassword = "password";

            //console.log(`No users found. Attempting to insert default user '${defaultUsername}'...`);
            const hash = await bcrypt.hash(defaultPassword, 10);
            const result = await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [defaultUsername, hash]);
            //console.log(`Default user '${defaultUsername}' inserted with ID: ${result.lastID}`);
        }

        return db;
    } catch (err) {
        console.error("Database initialization failed: ", err.message);
        process.exit(1);
    }
}
/** We call initializeDB() immediately, which returns a Promise.
 * This Promise is then exported, and server.js will await it. */
module.exports = initializeDB();