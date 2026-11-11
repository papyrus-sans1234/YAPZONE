
const express = require("express");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const { randomUUID } = require("crypto");

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const TERMS_VERSION = "2026-11-11";

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
    console.error("DATABASE_URL and SESSION_SECRET are required.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes("localhost")
        ? false
        : { rejectUnauthorized: false }
});

app.use(express.json({ limit: "20kb" }));

const PgSessionStore = connectPgSimple(session);

const sessionMiddleware = session({
    store: new PgSessionStore({
        pool,
        tableName: "user_sessions",
        createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
});

app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

const io = new Server(server, {
    maxHttpBufferSize: 1e6
});

io.engine.use(sessionMiddleware);

const activeUsers = new Map();
const authAttempts = new Map();

const MAX_MESSAGE_LENGTH = 500;
const MAX_USERNAME_LENGTH = 20;
const MESSAGE_LIMIT = 5;
const MESSAGE_WINDOW = 5000;

function cleanUsername(value) {
    return typeof value === "string" ? value.trim() : "";
}

function validUsername(name) {
    return name.length >= 2 &&
        name.length <= MAX_USERNAME_LENGTH &&
        /^[\p{L}\p{N}_ -]+$/u.test(name);
}

function asyncRoute(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

function authRateLimited(req, res, next) {
    const key = req.ip || req.socket.remoteAddress || "unknown";
    const now = Date.now();

    const recent = (authAttempts.get(key) || [])
        .filter(time => now - time < 10 * 60 * 1000);

    if (recent.length >= 15) {
        return res.status(429).json({
            error: "Too many attempts. Please wait a few minutes."
        });
    }

    recent.push(now);
    authAttempts.set(key, recent);

    next();
}

app.get("/health", (req, res) => {
    res.json({
        status: "online",
        service: "YAPZONE"
    });
});

// CHECK CURRENT LOGIN

app.get("/api/me", asyncRoute(async (req, res) => {
    if (!req.session.userId) {
        return res.json({ user: null });
    }

    const result = await pool.query(
        "SELECT id, username FROM users WHERE id = $1",
        [req.session.userId]
    );

    if (!result.rowCount) {
        req.session.destroy(() => {});
        return res.json({ user: null });
    }

    res.json({ user: result.rows[0] });
}));

// SIGN UP

app.post("/api/signup", authRateLimited, asyncRoute(async (req, res) => {
    const username = cleanUsername(req.body && req.body.username);
    const password = req.body && req.body.password;

    if (!req.body || req.body.termsAccepted !== true) {
        return res.status(400).json({
            error: "You must agree to the Terms & Conditions."
        });
    }

    if (!validUsername(username)) {
        return res.status(400).json({
            error: "Username must be 2-20 characters and use only letters, numbers, spaces, _ or -."
        });
    }

    if (
        typeof password !== "string" ||
        password.length < 8 ||
        password.length > 72
    ) {
        return res.status(400).json({
            error: "Password must be between 8 and 72 characters."
        });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    let user;

    try {
        const result = await pool.query(
            `INSERT INTO users
             (username, password_hash, terms_version, terms_accepted_at)
             VALUES ($1, $2, $3, NOW())
             RETURNING id, username`,
            [username, passwordHash, TERMS_VERSION]
        );

        user = result.rows[0];

    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({
                error: "That username is already registered. Try logging in."
            });
        }

        throw error;
    }

    await new Promise((resolve, reject) => {
        req.session.regenerate(error =>
            error ? reject(error) : resolve()
        );
    });

    req.session.userId = user.id;

    await new Promise((resolve, reject) => {
        req.session.save(error =>
            error ? reject(error) : resolve()
        );
    });

    res.status(201).json({ user });
}));

// LOG IN

app.post("/api/login", authRateLimited, asyncRoute(async (req, res) => {
    const username = cleanUsername(req.body && req.body.username);
    const password = req.body && req.body.password;

    if (!username || typeof password !== "string") {
        return res.status(400).json({
            error: "Enter your username and password."
        });
    }

    const result = await pool.query(
        `SELECT id, username, password_hash
         FROM users
         WHERE LOWER(username) = LOWER($1)`,
        [username]
    );

    const user = result.rows[0];

    const matches = user &&
        await bcrypt.compare(password, user.password_hash);

    if (!matches) {
        return res.status(401).json({
            error: "Incorrect username or password."
        });
    }

    await new Promise((resolve, reject) => {
        req.session.regenerate(error =>
            error ? reject(error) : resolve()
        );
    });

    req.session.userId = user.id;

    await new Promise((resolve, reject) => {
        req.session.save(error =>
            error ? reject(error) : resolve()
        );
    });

    res.json({
        user: {
            id: user.id,
            username: user.username
        }
    });
}));

// LOG OUT

app.post("/api/logout", asyncRoute(async (req, res) => {
    if (!req.session) {
        return res.json({ ok: true });
    }

    await new Promise(resolve => {
        req.session.destroy(() => resolve());
    });

    res.clearCookie("connect.sid", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax"
    });

    res.json({ ok: true });
}));

// ERROR HANDLER

app.use((error, req, res, next) => {
    console.error("Request error:", error);

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        error: "Something went wrong. Please try again."
    });
});

// REAL-TIME CHAT

io.on("connection", async socket => {
    const userId = socket.request.session &&
        socket.request.session.userId;

    if (!userId) {
        socket.disconnect(true);
        return;
    }

    try {
        const userResult = await pool.query(
            "SELECT id, username FROM users WHERE id = $1",
            [userId]
        );

        if (!userResult.rowCount) {
            socket.disconnect(true);
            return;
        }

        const username = userResult.rows[0].username;
        const messageTimes = [];

        activeUsers.set(socket.id, username);

        socket.emit("user:joined", {
            username,
            usersOnline: activeUsers.size
        });

        // LOAD THE COMPLETE SHARED CHAT HISTORY

        const history = await pool.query(
            `SELECT id, username, text, created_at
             FROM messages
             ORDER BY created_at ASC, id ASC`
        );

        socket.emit(
            "chat:history",
            history.rows.map(row => ({
                id: row.id,
                type: "message",
                username: row.username,
                text: row.text,
                timestamp: row.created_at
            }))
        );

        io.emit("chat:system", {
            id: randomUUID(),
            type: "system",
            text: `${username} joined YAPZONE.`,
            timestamp: new Date().toISOString()
        });

        io.emit("chat:users", activeUsers.size);

        // SEND A MESSAGE

        socket.on("chat:send", async data => {
            if (!data || typeof data.text !== "string") {
                socket.emit("chat:error", "Invalid message.");
                return;
            }

            const text = data.text
                .replace(/[\u0000-\u001F\u007F]/g, "")
                .trim();

            if (!text) return;

            if (text.length > MAX_MESSAGE_LENGTH) {
                socket.emit(
                    "chat:error",
                    "Messages cannot exceed 500 characters."
                );
                return;
            }

            const now = Date.now();

            while (
                messageTimes.length &&
                now - messageTimes[0] >= MESSAGE_WINDOW
            ) {
                messageTimes.shift();
            }

            if (messageTimes.length >= MESSAGE_LIMIT) {
                socket.emit(
                    "chat:error",
                    "Slow down! You're sending messages too quickly."
                );
                return;
            }

            messageTimes.push(now);

            try {
                const saved = await pool.query(
                    `INSERT INTO messages (username, text)
                     VALUES ($1, $2)
                     RETURNING id, created_at`,
                    [username, text]
                );

                io.emit("chat:message", {
                    id: saved.rows[0].id,
                    type: "message",
                    username,
                    text,
                    timestamp: saved.rows[0].created_at
                });

            } catch (error) {
                console.error("Message save failed:", error);

                socket.emit(
                    "chat:error",
                    "Your message could not be saved. Please try again."
                );
            }
        });

        // DISCONNECT

        socket.on("disconnect", () => {
            activeUsers.delete(socket.id);

            io.emit("chat:system", {
                id: randomUUID(),
                type: "system",
                text: `${username} left YAPZONE.`,
                timestamp: new Date().toISOString()
            });

            io.emit("chat:users", activeUsers.size);
        });

    } catch (error) {
        console.error("Socket setup failed:", error);
        socket.disconnect(true);
    }
});

// DATABASE SETUP

async function start() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username VARCHAR(20) NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS terms_version TEXT
    `);

    await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMPTZ
    `);

    await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_unique
        ON users (LOWER(username))
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id BIGSERIAL PRIMARY KEY,
            username VARCHAR(20) NOT NULL,
            text VARCHAR(500) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    server.listen(PORT, "0.0.0.0", () => {
        console.log("--------------------------------");
        console.log("       YAPZONE SERVER");
        console.log("--------------------------------");
        console.log(`Server running on port ${PORT}`);
    });
}

start().catch(error => {
    console.error("Could not start YAPZONE:", error);
    process.exit(1);
});
