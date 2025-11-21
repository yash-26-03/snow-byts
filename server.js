require('dotenv').config();
const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const pty = require('node-pty');
const os = require('os');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Import routers
const virusTotalRouter = require('./routes/virustotal');
const tempServicesRouter = require('./routes/tempservices');

// Make io accessible to routes
app.set('io', io);

// Mount routers
app.use('/api/vt', virusTotalRouter);
app.use('/api/temp', tempServicesRouter);

// Route for the home page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// WebSocket for terminal
const terminals = {};
const logs = {};

io.on('connection', (socket) => {
  console.log('Client connected to terminal');

  socket.on('create-terminal', () => {
    // Determine shell based on OS
    const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';

    // Create pseudo-terminal
    const term = pty.spawn(shell, [], {
      name: 'xterm-color',
      cols: 80,
      rows: 30,
      cwd: process.env.HOME || process.env.USERPROFILE,
      env: process.env
    });

    terminals[socket.id] = term;
    logs[socket.id] = '';

    // Send data from terminal to client
    term.on('data', (data) => {
      logs[socket.id] += data;
      socket.emit('terminal-output', data);
    });

    // Handle terminal exit
    term.on('exit', () => {
      socket.emit('terminal-output', '\r\n*** Terminal session ended ***\r\n');
      delete terminals[socket.id];
    });

    console.log(`Terminal created for socket ${socket.id}`);
  });

  socket.on('terminal-input', (data) => {
    if (terminals[socket.id]) {
      terminals[socket.id].write(data);
    }
  });

  socket.on('terminal-resize', (size) => {
    if (terminals[socket.id]) {
      terminals[socket.id].resize(size.cols, size.rows);
    }
  });

  socket.on('disconnect', () => {
    if (terminals[socket.id]) {
      terminals[socket.id].kill();
      delete terminals[socket.id];
      delete logs[socket.id];
    }
    console.log('Client disconnected from terminal');
  });
});

server.listen(port, () => {
  console.log(`Cyber Security Tools Portal listening at http://localhost:${port}`);
});
