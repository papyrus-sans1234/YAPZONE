const express = require("express");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");
const { randomUUID } = require("crypto");

const app = express();
const server = http.createServer(app);

// Hosting configuration
const PORT = process.env.PORT || 3000;

// Allow your website's origin.
// Leave unset when the frontend is served by this same server.
const allowedOrigins = process.env.CLIENT_ORIGIN
    ? process.env.CLIENT_ORIGIN.split(",").map(x => x.trim())
    : "*";

// Serve frontend files
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (req, res) => {
    res.json({
        status: "online",
        service: "YAPZONE"
    });
});

// Socket.IO setup
const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ["GET", "POST"]
    },
    maxHttpBufferSize: 1e6
});

// Active users
const activeUsers = new Map();

// Configuration
const MAX_MESSAGE_LENGTH = 500;
const MAX_USERNAME_LENGTH = 20;
const MESSAGE_LIMIT = 5;
const MESSAGE_WINDOW = 5000;

// Create system messages
function systemMessage(text) {
    return {
        id: randomUUID(),
        type: "system",
        text,
        timestamp: new Date().toISOString()
    };
}

// Connection handler
io.on("connection", (socket) => {

    console.log("A visitor connected:", socket.id);

    let username = null;
    const messageTimes = [];

    // USER JOINS
    socket.on("user:join", (data) => {

        if (username) return;

        if (!data || typeof data.username !== "string") {
            socket.emit("chat:error", "Invalid username.");
            return;
        }

        const cleanUsername = data.username.trim();

        // Validate username
        if (
            cleanUsername.length < 2 ||
            cleanUsername.length > MAX_USERNAME_LENGTH ||
            !/^[\p{L}\p{N}_ -]+$/u.test(cleanUsername)
        ) {
            socket.emit(
                "chat:error",
                "Username must be 2-20 characters and contain only letters, numbers, spaces, _ or -."
            );
            return;
        }

        // Prevent duplicate usernames
        const taken = [...activeUsers.values()].some(
            name => name.toLowerCase() === cleanUsername.toLowerCase()
        );

        if (taken) {
            socket.emit("chat:error", "That username is already taken.");
            return;
        }

        username = cleanUsername;
        activeUsers.set(socket.id, username);

        console.log(username, "joined YAPZONE");

        socket.emit("user:joined", {
            username,
            usersOnline: activeUsers.size
        });

        // Notify everyone
        io.emit(
            "chat:system",
            systemMessage(`${username} joined YAPZONE.`)
        );

        io.emit("chat:users", activeUsers.size);
    });

    // SEND MESSAGE
    socket.on("chat:send", (data) => {

        if (!username) {
            socket.emit("chat:error", "Join the chat first.");
            return;
        }

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

        // Basic rate limiting
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

        // Create message
        const message = {
            id: randomUUID(),
            type: "message",
            username,
            text,
            timestamp: new Date().toISOString()
        };

        // Broadcast to EVERYONE
        io.emit("chat:message", message);
    });

    // USER DISCONNECTS
    socket.on("disconnect", () => {

        if (username) {
            activeUsers.delete(socket.id);

            console.log(username, "left YAPZONE");

            io.emit(
                "chat:system",
                systemMessage(`${username} left YAPZONE.`)
            );

            io.emit("chat:users", activeUsers.size);
        }

        console.log("Disconnected:", socket.id);
    });

});

// Start server
server.listen(PORT, "0.0.0.0", () => {
    console.log("--------------------------------");
    console.log("       YAPZONE SERVER");
    console.log("--------------------------------");
    console.log(`Server running on port ${PORT}`);
});