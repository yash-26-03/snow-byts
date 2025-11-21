const express = require('express');
const axios = require('axios');
const multer = require('multer');
const FormData = require('form-data');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// VirusTotal API configuration
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE_URL = 'https://www.virustotal.com/api/v3';

// Helper function to make VT API requests
async function vtRequest(endpoint, method = 'GET', data = null) {
    const config = {
        method,
        url: `${VT_BASE_URL}${endpoint}`,
        headers: {
            'x-apikey': VT_API_KEY
        }
    };

    if (data) {
        config.data = data;
        if (data instanceof FormData) {
            config.headers = { ...config.headers, ...data.getHeaders() };
        }
    }

    return axios(config);
}

// File scan - upload file
router.post('/file-scan', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const formData = new FormData();
        formData.append('file', req.file.buffer, req.file.originalname);

        const response = await vtRequest('/files', 'POST', formData);
        res.json(response.data);
    } catch (error) {
        console.error('VT File Scan Error:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error?.message || 'File scan failed'
        });
    }
});

// Get file report by analysis ID
router.get('/file-report/:id', async (req, res) => {
    try {
        const response = await vtRequest(`/analyses/${req.params.id}`);
        res.json(response.data);
    } catch (error) {
        console.error('VT File Report Error:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error?.message || 'Failed to get file report'
        });
    }
});

// URL scan
router.post('/url-scan', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        const formData = new FormData();
        formData.append('url', url);

        const response = await vtRequest('/urls', 'POST', formData);
        res.json(response.data);
    } catch (error) {
        console.error('VT URL Scan Error:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error?.message || 'URL scan failed'
        });
    }
});

// Get URL report by analysis ID
router.get('/url-report/:id', async (req, res) => {
    try {
        const response = await vtRequest(`/analyses/${req.params.id}`);
        res.json(response.data);
    } catch (error) {
        console.error('VT URL Report Error:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error?.message || 'Failed to get URL report'
        });
    }
});

// Hash lookup
router.get('/hash-lookup/:hash', async (req, res) => {
    try {
        const response = await vtRequest(`/files/${req.params.hash}`);
        res.json(response.data);
    } catch (error) {
        console.error('VT Hash Lookup Error:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error?.message || 'Hash lookup failed'
        });
    }
});

// IP lookup
router.get('/ip-lookup/:ip', async (req, res) => {
    try {
        const response = await vtRequest(`/ip_addresses/${req.params.ip}`);
        res.json(response.data);
    } catch (error) {
        console.error('VT IP Lookup Error:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error?.message || 'IP lookup failed'
        });
    }
});

// Domain lookup
router.get('/domain-lookup/:domain', async (req, res) => {
    try {
        const response = await vtRequest(`/domains/${req.params.domain}`);
        res.json(response.data);
    } catch (error) {
        console.error('VT Domain Lookup Error:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error?.message || 'Domain lookup failed'
        });
    }
});

module.exports = router;
