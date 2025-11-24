require('dotenv').config();
const express = require('express');
const path = require('path');
const http = require('http');
const os = require('os');

const app = express();
const server = http.createServer(app);
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// CORS Middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// Import routers with error handling
let virusTotalRouter;
let tempServicesRouter;
let pcapRouter;

try {
  virusTotalRouter = require('./routes/virustotal');
} catch (error) {
  console.error('Failed to load VirusTotal router:', error.message);
}

try {
  tempServicesRouter = require('./routes/tempservices');
} catch (error) {
  console.error('Failed to load Temp Services router:', error.message);
}

try {
  pcapRouter = require('./routes/pcap');
} catch (error) {
  console.error('Failed to load PCAP router:', error.message);
}

// Mount routers if available
if (virusTotalRouter) {
  app.use('/api/vt', virusTotalRouter);
} else {
  app.use('/api/vt', (req, res) => res.status(503).json({ error: 'Service unavailable' }));
}

if (tempServicesRouter) {
  app.use('/api/temp', tempServicesRouter);
} else {
  app.use('/api/temp', (req, res) => res.status(503).json({ error: 'Service unavailable' }));
}

if (pcapRouter) {
  app.use('/api/pcap', pcapRouter);
} else {
  app.use('/api/pcap', (req, res) => res.status(503).json({ error: 'Service unavailable' }));
}

// Route for the home page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// WebSocket - ONLY if not on Vercel
// On Vercel, we don't initialize Socket.IO server-side to avoid 500 errors
// The terminal is now fully client-side simulated, so it doesn't need this.
if (!process.env.VERCEL) {
  try {
    const { Server } = require('socket.io');
    const io = new Server(server, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    // Make io accessible to routes (e.g. for PCAP streaming)
    app.set('io', io);

    // Import node-pty
    const pty = require('node-pty');

    io.on('connection', (socket) => {
      console.log('Client connected');

      const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';

      const ptyProcess = pty.spawn(shell, [], {
        name: 'xterm-color',
        cols: 80,
        rows: 24,
        cwd: process.env.HOME,
        env: process.env
      });

      // Send data from pty to client
      ptyProcess.on('data', (data) => {
        socket.emit('output', data);
      });

      // Receive data from client to pty
      socket.on('input', (data) => {
        ptyProcess.write(data);
      });

      // Handle resize
      socket.on('resize', (size) => {
        ptyProcess.resize(size.cols, size.rows);
      });

      // Cleanup on disconnect
      socket.on('disconnect', () => {
        console.log('Client disconnected');
        ptyProcess.kill();
      });
    });
  } catch (err) {
    console.warn('WebSocket initialization failed:', err.message);
    app.set('io', { emit: () => { } });
  }
} else {
  // Mock io for Vercel to prevent crashes in routes that try to use req.app.get('io')
  app.set('io', { emit: () => { } });
}

// Start server
if (require.main === module) {
  server.listen(port, '0.0.0.0', () => {
    console.log(`Cyber Security Tools Portal listening at http://0.0.0.0:${port}`);
    console.log(`Access from network: http://<YOUR_IP>:${port}`);
  });
}

module.exports = app;
