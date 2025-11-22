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

// Import routers
const virusTotalRouter = require('./routes/virustotal');
const tempServicesRouter = require('./routes/tempservices');
const pcapRouter = require('./routes/pcap');

// Mount routers
app.use('/api/vt', virusTotalRouter);
app.use('/api/temp', tempServicesRouter);
app.use('/api/pcap', pcapRouter);

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

    io.on('connection', (socket) => {
      console.log('Client connected');
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
  server.listen(port, () => {
    console.log(`Cyber Security Tools Portal listening at http://localhost:${port}`);
  });
}

module.exports = app;
