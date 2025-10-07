const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { dbPromise } = require("./database");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { generateKeyPairSync } = require("./database");
const { toNamespacedPath } = require("path");
const { send } = require("process");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const CLI_PORT = process.argv[2] ? parseInt(process.argv[2], 10) : null;
const PORT = CLI_PORT || process.env.PORT || 3000;

if (CLI_PORT && (isNaN(PORT) || PORT <= 0 || PORT > 65535))
  console.error(
    `Error: Invalid port specified from the command line: ${process.argv[2]}. Using default port 3000`,
  );

const SESSION_SECRET = "ilmiodolcepreferitoeiltiramisu";

const sessionMiddleware = session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 86400000,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  },
});

function isAuthenticated(req, res, next) {
  if (req.session.userId)
    next();
  else
    res.status(401).redirect("/login.html");
}

async function deriveKey(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 100000, 32, "sha512", (err, derivedKey) => {
      if (err)
        return reject(err);
      resolve(derivedKey);
    });
  });
}

async function encrypt(text, key, iv) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

async function decrypt(encryptedText, key, iv) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

async function decryptToBuffer(encryptedText, key, iv) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const decryptedBuffer = Buffer.concat([
    decipher.update(encryptedText, "hex"),
    decipher.final(),
  ]);
  return decryptedBuffer;
}

async function startApp() {
  let db;
  const userSockets = {};

  console.log("Initializing database...");
  try {
    db = await dbPromise;
    console.log("Database initialized successfully, db:", !!db);

    // Body parsers
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());

    // Session middleware
    app.use(sessionMiddleware);

    // Middleware to check db is ready (should always be true)
    app.use((req, res, next) => {
      if (!db) {
        console.error("Database not initialized yet for request:", req.url);
        return res
          .status(503)
          .send("Server is starting, please try again in a moment.");
      }
      next();
    });

    // Static files
    app.use(express.static("public"));

    app.post("/register", async (req, res) => {
      const { username, password } = req.body;

      if (!username || !password)
        return res.status(400).send("Username and password are required.");

      try {
        const existingUser = await db.get(
          `SELECT id FROM users WHERE username = ?`,
          [username],
        );
        if (existingUser)
          return res.status(409).send("Username already taken.");

        const hash = await bcrypt.hash(password, 10);
        const result = await db.run(
          `INSERT INTO users (username, password) VALUES (?, ?)`,
          [username, hash],
        );

        const userId = result.lastID;
        const contacts = [];
        const salt = crypto.randomBytes(16);
        const iv = crypto.randomBytes(16).toString("hex");
        const key = await deriveKey(password, salt);
        req.session.derivedKey = key;
        const encrypted_contacts = await encrypt(
          JSON.stringify(contacts),
          key,
          Buffer.from(iv, "hex"),
        );

        await db.run(
          `INSERT INTO contacts (user_id, encrypted_contacts, iv, salt) VALUES (?, ?, ?, ?)`,
          [userId, encrypted_contacts, iv, salt.toString("hex")],
        );

        const { publicKey, privateKey } = generateKeyPairSync("ec", {
          namedCurve: "prime256v1",
          publicKeyEncoding: { type: "spki", format: "der" },
          privateKeyEncoding: { type: "pkcs8", format: "der" },
        });
        const privSalt = crypto.randomBytes(16);
        const privIv = crypto.randomBytes(16);
        const privDerKey = await deriveKey(password, privSalt);
        const encPriv = encrypt(privateKey, privDerKey, privIv);
        await db.run(
          `INSERT INTO user_keys (user_id, public_key, encrypted_private_key, private_iv, private_salt) VALUES (?, ?, ?, ?, ?)`,
          [
            userId,
            publicKey.toString("hex"),
            encPriv.encryptedData,
            encPriv.iv,
            privSalt.toString("hex"),
          ],
        );

        const oldUserId = req.session.userId;
        if (oldUserId && userSockets[oldUserId]) {
          userSockets[userId].forEach((socketId) => {
            io.to(socketId).emit("session-changed");
          });
          delete userSockets[userId];
        }

        req.session.userId = userId;
        req.session.username = username;

        console.log(`User ${username} registered with ID: ${userId}`);
        res.status(200).send("Registration successful!");
      } catch (dbErr) {
        if (dbErr.code === "SQLITE_CONSTRAINT" || dbErr.code === "SQLITE_CONSTRAINT_UNIQUE")
          return res.status(409).send("Username already taken.");
        console.error("Error inserting user or contacts:", dbErr);
        return res.status(500).send("Error registering user.");
      }
    });

    app.post("/login", async (req, res) => {
      const { username, password } = req.body;

      if (!username || !password)
        return res.status(400).send("Username and password are required");

      try {
        const user = await db.get(`SELECT * FROM users WHERE username = ?`, [
          username,
        ]);
        if (!user)
          return res.status(401).send("Invalid username");

        const result = await bcrypt.compare(password, user.password);
        if (!result)
          return res.status(401).send("Invalid password");

        // fetch encrypted contacts
        const contactRecord = await db.get(
          `SELECT encrypted_contacts, iv, salt FROM contacts WHERE user_id = ?`,
          [user.id],
        );
        let contacts = [];
        if (contactRecord) {
          const saltBuffer = Buffer.from(contactRecord.salt, "hex");
          const key = await deriveKey(password, saltBuffer);
          req.session.derivedKey = key;
          try {
            const decrypted = await decrypt(
              contactRecord.encrypted_contacts,
              key,
              Buffer.from(contactRecord.iv, "hex"),
            );
            contacts = JSON.parse(decrypted);
          } catch (e) {
            // if decryption fails, fallback to empty
            console.error("Failed to decrypt contacts for user", username, e);
            contacts = [];
          }
        }

        const oldUserId = req.session.userId;
        if (oldUserId && userSockets[oldUserId]) {
          userSockets[oldUserId].forEach((socketId) => {
            io.to(socketId).emit("session-changed");
          });
          delete userSockets[oldUserId];
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.contacts = contacts;

        const keyRecord = await db.get(
          `SELECT encrypted_private_key, private_iv, private_salt
                    FROM user_keys
                    WHERE user_id = ?`,
          [user.id],
        );
        if (keyRecord) {
          const privSaltBuf = Buffer.from(keyRecord.private_salt, "hex");
          const privKey = await deriveKey(password, privSaltBuf);
          const decryptedPriv = await decryptToBuffer(
            keyRecord.encrypted_private_key,
            privKey,
            Buffer.from(keyRecord.private_iv, "hex"),
          );
          req.session.privateKey = decryptedPriv;
        } else
          console.error("No private key found for user", username);

        console.log(`User ${user.username} logged in`);
        res.status(200).send("Login successful");
      } catch (err) {
        console.error("Database error: ", err);
        return res.status(500).send("Server error during login");
      }
    });

    app.post("/logout", (req, res) => {
      const userId = req.session.userId;
      if (userId && userSockets[userId]) {
        userSockets[userId].forEach((socketId) => {
          io.to(socketId).emit("session-changed");
        });
        delete userSockets[userId];
      }

      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying session: ", err);
          return res.status(500).send("Error logging out.");
        }
        res.clearCookie("connect.sid");
        res.status(200).send("Logged out successfully.");
      });
    });

    app.get("/check-auth", (req, res) => {
      if (req.session.userId)
        res.status(200).json({
          authenticated: true,
          username: req.session.username,
        });
      else
        res.status(200).json({
          authenticated: false,
        });
    });
    app.get("/", isAuthenticated, (req, res) => {
      res.sendFile(__dirname + "/index.html");
    });

    app.get("/index.html", isAuthenticated, (req, res) => {
      res.sendFile(__dirname + "/index.html");
    });

    app.get("/contacts", isAuthenticated, async (req, res) => {
      try {
        const user = await db.get(`SELECT * FROM users WHERE id = ?`, [
          req.session.userId,
        ]);
        if (!user)
          return res.status(401).send("User not found");

        const contactRecord = await db.get(
          `SELECT * FROM contacts WHERE user_id = ?`,
          [req.session.userId],
        );
        if (!contactRecord) {
          console.warn("The user's contacts data couldn't be found.");
          return res.json([]);
        }

        // ensure the key is a Buffer
        let contacts = [];
        try {
          if (!req.session.derivedKey)
            return res
              .status(401)
              .send("Session key missing. Please log in again.");

          // convert derivedKey to Buffer if it's an object
          let key = req.session.derivedKey;
          if (!(key instanceof Buffer)) {
            if (key && key.type === "Buffer" && Array.isArray(key.data))
              key = Buffer.from(key.data);
            else throw new Error("Invalid key format in session");
          }
          const decrypted = await decrypt(
            contactRecord.encrypted_contacts,
            key,
            Buffer.from(contactRecord.iv, "hex"),
          );
          console.log("Decrypted contacts:", decrypted);
          contacts = JSON.parse(decrypted);
        } catch (e) {
          console.error("Failed to decrypt contacts", e);
          return res
            .status(500)
            .send(
              "Failed to decrypt contacts. Please ensure your login credentials are correct.",
            );
        }

        // map contactUserID to username
        const contactUserIDs = contacts.map((c) => c.contactUserID);
        let contactUsernamesMap = {};
        let contactPubKeysMap = {};
        if (contactUserIDs.length > 0) {
          const placeholders = contactUserIDs.map(() => "?").join(",");
          const users = await db.all(
            `
                        SELECT id, username
                        FROM users
                        WHERE id IN (${placeholders})`,
            contactUserIDs,
          );
          users.forEach((u) => {
            contactUsernamesMap[u.id] = u.username;
          });
          const keys = await db.all(
            `SELECT user_id, public_key
                        FROM user_keys
                        WHERE user_id IN (${placeholders})`,
            contactUserIDs,
          );
          keys.forEach((k) => {
            contactPubKeysMap[k.user_id] = k.public_key;
          });
        }
        const contactsWithDetails = contacts.map((c) => ({
          contactUserID: c.contactUserID,
          contactUsername: contactUsernamesMap[c.contactUserID] || null,
          publicKey: contactPubKeysMap[c.contactUserID] || null,
          alias: c.alias || contactUsernamesMap[c.contactUserID] || null,
        }));
        res.json(contactsWithDetails);
      } catch (err) {
        console.error("Error fetching contacts:", err);
        res.status(500).send("Error fetching contacts.");
      }
    });

    app.post("/contacts/add", isAuthenticated, async (req, res) => {
      const { contactUsername, alias } = req.body;

      console.log("contactUsername:", contactUsername);
      const user = await db.get(`SELECT * FROM users WHERE username = ?`, [
        contactUsername,
      ]);
      if (!user)
        return res.status(404).send("User not found.");

      const contactRecord = await db.get(
        `SELECT * FROM contacts WHERE user_id = ?`,
        [req.session.userId],
      );
      if (!contactUsername)
        return res.status(400).send("Contact username is required.");

      // convert derivedKey to Buffer if it's an object
      let key = req.session.derivedKey;
      if (!(key instanceof Buffer)) {
        if (key && key.type === "Buffer" && Array.isArray(key.data))
          key = Buffer.from(key.data);
        else
          throw new Error("Invalid key format in session");
      }

      let contacts = [];
      try {
        if (!req.session.derivedKey)
          return res
            .status(401)
            .send("Session key missing. Please log in again.");
        try {
          const decrypted = await decrypt(
            contactRecord.encrypted_contacts,
            key,
            Buffer.from(contactRecord.iv, "hex"),
          );
          console.log("Decrypted contacts:", decrypted);
          contacts = JSON.parse(decrypted);
        } catch (e) {
          console.error("Failed to decrypt contacts for add", e);
          return res.status(401).send("Invalid password for decryption.");
        }

        const contactExists = contacts.some((c) => c.contactUserID === user.id);
        if (contactExists)
          return res.status(500).send("Contact already in your list.");

        const keyRec = await db.get(
          `SELECT public_key
                    FROM user_keys
                    WHERE user_id = ?`,
          [user.id],
        );
        const newContact = {
          contactUserID: user.id,
          alias: alias || contactUsername,
          contactUsername: contactUsername,
          publicKey: keyRec ? keyRec.public_key : null,
        };
        contacts.push(newContact);

        // encrypt updated contacts
        const encrypted_contacts = await encrypt(
          JSON.stringify(contacts),
          key,
          Buffer.from(contactRecord.iv, "hex"),
        );

        await db.run(
          `UPDATE contacts SET encrypted_contacts = ? WHERE user_id = ?`,
          [encrypted_contacts, req.session.userId],
        );
        console.log("Contacts updated for user:", req.session.userId);

        res.status(200).json({
          message: "Contact added successfully.",
          newContact: newContact,
        });
      } catch (err) {
        console.error("Error adding contact:", err);
        res.status(500).send("Error adding contact.");
      }
    });

    app.get("/rooms", isAuthenticated, async (req, res) => {
      try {
        const rooms = await db.all(`SELECT name FROM rooms`);
        res.json(rooms);
      } catch (err) {
        console.log("Error fetching rooms:", err);
        res.status(500).send("Error fetching rooms");
      }
    });

    app.get("/ownId", isAuthenticated, (req, res) => {
      if (req.session.userId)
        res.json({ id: req.session.userId });
      else
        res.status(401).json({ error: "Not authenticated" });
    });

    app.get("/get-private-key", isAuthenticated, (req, res) => {
      if (!req.session.privateKey)
        return res
          .status(401)
          .json({ error: "Private key not available. Please re-login." });

      let privateKey = req.session.privateKey;
      if (!(privateKey instanceof Buffer) && privateKey.type === "Buffer" && Array.isArray(privateKey.data))
        privateKey = Buffer.from(privateKey.data);

      if (!(privateKey instanceof Buffer))
        return res
          .status(500)
          .json({ error: "Private key is corrupted in the session." });

      res.json({ privateKeyHex: privateKey.toString("hex") });
    });

    // socket.io integration
    const wrap = (middleware) => (socket, next) =>
      middleware(socket.request, {}, next);
    io.use(wrap(sessionMiddleware));

    io.use((socket, next) => {
      if (socket.request.session && socket.request.session.userId) {
        socket.request.username = socket.request.session.username;
        next();
      } else
        next(new Error("Authentication error: Not logged in."));
    });

    io.on("connection", (socket) => {
      const userId = socket.request.session.userId;
      if (userId) {
        if (!userSockets[userId])
          userSockets[userId] = [];
        userSockets[userId].push(socket.id);
      }

      const userRooms = {};

      socket.on("chat message", (data) => {
        const userId = socket.request.session.userId;
        const senderUsername = socket.request.username;

        if (!userId) {
          console.warn(`Attempted to send message without a valid userId: ${socket.id}`,);
          return;
        }

        const messageData = {
          id: userId,
          username: senderUsername,
          message: data.message,
        };

        console.log(
          `Message from ${messageData.username} (${messageData.id}): ${messageData.message}`,
        );
        const currentRoom = userRooms[socket.id] || "general";
        io.to(currentRoom).emit("chat message", messageData);
      });

      socket.on("private chat message", async (data) => {
        const { encrypted, iv, chatId, ownId } = data;
        if (!encrypted || !iv || !chatId)
          return socket.emit("private chat error", "Invalid message data");

        const userId = socket.request.session.userId;
        const senderUsername = socket.request.username;

        if (!userId) {
          console.warn(
            `Attempted to send private message without a valid userId: ${socket.id}`,
          );
          return;
        }

        try {
          await db.run(
            `INSERT INTO private_messages (chat_id, sender_id, encrypted_message, iv, salt) VALUES (?, ?, ?, ?, ?)`,
            [chatId, userId, encrypted, iv, ""],
          );

          const privateRoomName = `private_chat_${chatId}`;
          io.to(privateRoomName).emit("private chat message", {
            id: userId,
            username: senderUsername,
            encrypted,
            iv,
            timestamp: new Date().toISOString(),
          });

          console.log(
            `Private message sent in chat ${chatId} from ${senderUsername}`,
          );
        } catch (err) {
          console.error("Error storing private message:", err);
          socket.emit("private chat error", "Failed to send message");
        }
      });

      socket.on("disconnect", () => {
        const userId = socket.request.session.userId;
        if (userId && userSockets[userId]) {
          userSockets[userId] = userSockets[userId].filter(
            (id) => id !== socket.id,
          );
          if (userSockets[userId].length === 0)
            delete userSockets[userId];
        }
        console.log(
          `User disconnected: ${socket.id} (Username: ${socket.request.username || "N/A"})`,
        );
      });

      socket.on("join room", (room) => {
        const previousRoom = userRooms[socket.id];
        if (previousRoom)
          socket.leave(previousRoom);

        socket.join(room);
        userRooms[socket.id] = room;

        socket.emit("room message", {
          message: `You have joined the ${room} room.`,
        });
        console.log(`${socket.request.username} joined room: ${room}`);
      });

      socket.on("chatToContact", async (contactUsername) => {
        const userId = socket.request.session.userId;

        const contactUser = await db.get(
          `SELECT id FROM users WHERE username = ?`,
          [contactUsername],
        );

        if (!contactUser) {
          console.error(
            `Attempted to chat with non-existent user: ${contactUsername}`,
          );
          return socket.emit("private chat error", "User not found.");
        }

        const contactId = contactUser.id;

        if (!userId || !contactId) {
          console.error("Invalid user or contact ID");
          return socket.emit("private chat error", "User not found.");
        }

        try {
          const contactRecord = await db.get(
            `SELECT * FROM contacts WHERE user_id = ?`,
            [userId],
          );
          if (!contactRecord)
            return socket.emit(
              "private chat error",
              "Could not find your contact data.",
            );

          let key = socket.request.session.derivedKey;
          if (!(key instanceof Buffer))
            if (key && key.type === "Buffer" && Array.isArray(key.data))
              key = Buffer.from(key.data);
            else
              throw new Error("Invalid key format in session");

          const decrypted = await decrypt(
            contactRecord.encrypted_contacts,
            key,
            Buffer.from(contactRecord.iv, "hex"),
          );
          const contacts = JSON.parse(decrypted);
          const targetContact = contacts.find(
            (c) => c.contactUserID === contactId,
          );
          const displayName = targetContact
            ? targetContact.alias
            : contactUsername;

          const existingChat = await db.get(
            `SELECT T1.chat_id
            FROM chat_participants AS T1
            JOIN chat_participants AS T2
            ON T1.chat_id = T2.chat_id
            WHERE T1.user_id = ? AND T2.user_id = ?`,
            [userId, contactId],
          );

          let chatId;

          if (existingChat) {
            chatId = existingChat.chat_id;
            console.log(`Existing chat found with ID: ${chatId}`);
          } else {
            const result = await db.run(
              `INSERT INTO private_chats VALUES (NULL)`,
            );
            chatId = result.lastID;
            console.log(`New private chat created with ID: ${chatId}`);

            await db.run(
              `INSERT INTO chat_participants (chat_id, user_id) VALUES (?, ?), (?, ?)`,
              [chatId, userId, chatId, contactId],
            );
            console.log(`Participants added to chat ${chatId}`);
          }

          const previousRoom = userRooms[socket.id];
          if (previousRoom)
            socket.leave(previousRoom);

          const privateRoomName = `private_chat_${chatId}`;
          socket.join(privateRoomName);
          userRooms[socket.id] = privateRoomName;

          const history = await db.all(
            `SELECT id, sender_id, encrypted_message, iv, timestamp
            FROM private_messages
            WHERE chat_id = ? AND (deleted_by IS NULL OR deleted_by <> ?)
            ORDER BY timestamp ASC`,
            [chatId, userId.toString()],
          );
          socket.emit("private chat history", history);

          socket.emit("joined private chat", privateRoomName);
          socket.emit("room message", {
            message: `You joined your private chat with "${displayName}" room.`,
          });
          console.log(
            `${socket.request.username} joined private chat: ${chatId}`,
          );
        } catch (err) {
          console.error("Error handling chatToContact:", err);
          socket.emit("private chat error", "A server error occurred.");
        }
      });

      socket.on("create room", async (roomName) => {
        if (!roomName || typeof roomName !== "string" || roomName.trim().length === 0)
          return socket.emit("room message", {
            message: `Error: Invalid room name`,
          });
        const trimmedRoomName = roomName.trim();

        try {
          const existingRoom = await db.get(
            `SELECT name FROM rooms WHERE name = ?`,
            [trimmedRoomName],
          );
          if (existingRoom)
            return socket.emit("room message", {
              message: `Room "${trimmedRoomName}" already exists.`,
            });

          await db.run(`INSERT INTO rooms (name) VALUES (?)`, [
            trimmedRoomName,
          ]);
          console.log(`Room "${trimmedRoomName}" created by ${socket.request.username}.`);
          socket.emit("room created", trimmedRoomName);
          const previousRoom = userRooms[socket.id];
          if (previousRoom)
            socket.leave(previousRoom);
          socket.join(trimmedRoomName);
          userRooms[socket.id] = trimmedRoomName;

          socket.emit("room message", {
            message: `You created and joined the "${trimmedRoomName}" room.`,
          });
        } catch (err) {
          console.error("Error saving room to database:", err);
          socket.emit("room message", { message: "A server error occurred." });
        }
      });

      socket.on("delete room", async (roomName) => {
        if (["General", "Random"].includes(roomName))
          return socket.emit("room message", {
            message: "Error: cannot delete default rooms.",
          });

        try {
          await db.run("DELETE FROM rooms WHERE name = ?", [roomName]);

          const socketsInRoom = io.sockets.adapter.rooms.get(roomName);
          if (socketsInRoom) {
            socketsInRoom.forEach((socketId) => {
              const userSocket = io.sockets.sockets.get(socketId);
              if (userSocket) {
                userSocket.leave(roomName);
                userSocket.join("General");
                userSocket.emit("room message", {
                  message: `The room '${roomName}' was deleted. You have been moved to 'General'.`,
                });
              }
            });
          }
          io.emit("room deleted", roomName);
          console.log(`Room "${roomName}" deleted by ${socket.request.username}.`);
        } catch (err) {
          console.error("Error deleting room from database:", err);
          socket.emit("room message", {
            message: "A server error occurred while deleting the room.",
          });
        }
      });

      socket.on("delete private chat", async (chatId, ownId) => {
        try {
          const ownIdStr = ownId.toString();
          const updateResult = await db.run(
            `UPDATE private_messages
             SET deleted_by = ?
             WHERE chat_id = ? AND deleted_by IS NULL`,
            [ownIdStr, chatId],
          );

          // delete messages already marked by the other user
          const deleteResult = await db.run(
            `DELETE FROM private_messages
          	WHERE chat_id = ? AND deleted_by <> ?
            AND deleted_by IS NOT NULL`,
            [chatId, ownIdStr]
          );

          console.log(`Private chat ${chatId} marked/deleted for user ${ownId}.`);
        } catch (err) {
          console.error("Error deleting private chat:", err);
          socket.emit("room message", { message: "A server error occurred while deleting the chat." });
        }
      });
    });

    server.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
      console.log(`Default login user: testuser / password`);
      console.log(`Access login page at http://localhost:${PORT}/login.html`);
    });
  } catch (err) {
    console.error("Failed to initialize app: ", err);
    process.exit(1);
  }
}

startApp().catch((err) => {
  console.error("Error starting app:", err);
  process.exit(1);
});
