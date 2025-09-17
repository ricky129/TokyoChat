A real-time chat application built with Node.js, Express, Socket.IO, and SQLite. TokyoChat supports public rooms, private messaging, user contacts with encryption, and user authentication. It's designed for seamless, secure communication in a modern, dark-themed interface.

Features

User Authentication: Secure registration and login with bcrypt-hashed passwords.
Public Chat Rooms: Join or create dynamic rooms (e.g., "General", "Random") with real-time messaging.
Private Chats: One-on-one messaging with automatic chat creation between contacts.
Encrypted Contacts: User contacts are stored encrypted in the database using AES-256-CBC with PBKDF2-derived keys.
Contact Management: Add contacts with custom aliases; contacts are decrypted client-side on login.
Real-Time Updates: Powered by Socket.IO for instant message delivery and room joins/leaves.
Responsive UI: Dark-themed, mobile-friendly interface with CSS custom properties.
Default Setup: Pre-configured with test users for quick testing.

Tech Stack

Backend: Node.js, Express.js, Socket.IO, SQLite (with sqlite3 driver)
Security: bcryptjs (password hashing), Node.js crypto module (AES encryption)
Frontend: Vanilla JavaScript, HTML5, CSS3
Database: SQLite (file-based, no external server needed)
Session Management: express-session
