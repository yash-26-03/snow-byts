require('dotenv').config();
const express = require('express');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Import routers
const virusTotalRouter = require('../routes/virustotal');
const tempServicesRouter = require('../routes/tempservices');

// Mount routers
app.use('/api/vt', virusTotalRouter);
app.use('/api/temp', tempServicesRouter);

// Route for the home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public', 'index.html'));
});

module.exports = app;
