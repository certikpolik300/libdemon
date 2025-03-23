const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const E2EE = require('./libswiftproto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const dbPath = path.join(__dirname, 'vxb.db');

if (!fs.existsSync(dbPath)) {
    const db = new sqlite3.Database(dbPath);
    db.serialize(() => {
        db.run(`CREATE TABLE Messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    });
    db.close();
}

const db = new sqlite3.Database(dbPath);

app.use(express.static(path.join(__dirname, 'public')));

io.on('connection', (socket) => {
    const e2ee = new E2EE();

    socket.on('handshake', (peerPublicKey) => {
        e2ee.deriveSharedSecret(peerPublicKey);
        socket.emit('handshake', e2ee.getECDHPublicKey());
    });

    socket.on('message', (data) => {
        const { username, message } = data;
        const encryptedMessage = e2ee.encrypt(message);
        db.run(`INSERT INTO Messages (username, message) VALUES (?, ?)`, [username, encryptedMessage]);
        io.emit('message', { username, message: encryptedMessage });
    });
});

server.listen(3000, () => {
    console.log('Server is running on port 3000');
});
