const express = require('express');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

// In-memory storage for temp emails and SMS
const tempEmails = new Map(); // { id: { email, inbox: [] } }
const tempSMS = new Map(); // { id: { phone, messages: [] } }

// Generate random email
function generateRandomEmail() {
    const adjectives = ['cool', 'fast', 'smart', 'cyber', 'secure', 'anon', 'temp', 'quick'];
    const nouns = ['user', 'agent', 'ninja', 'hacker', 'dev', 'tester', 'bot'];
    const domains = ['tempmail.dev', 'disposable.email', 'throwaway.net', 'temp-inbox.com'];

    const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    const num = Math.floor(Math.random() * 9999);
    const domain = domains[Math.floor(Math.random() * domains.length)];

    return `${adj}${noun}${num}@${domain}`;
}

// Generate random phone number (Indian format)
function generateRandomPhone() {
    // Indian mobile numbers: +91 followed by 10 digits (starting with 6-9)
    const firstDigit = Math.floor(Math.random() * 4) + 6; // 6, 7, 8, or 9
    const remaining = Math.floor(Math.random() * 900000000) + 100000000; // 9 more digits

    const number = `${firstDigit}${remaining}`;
    return `+91 ${number.substring(0, 5)} ${number.substring(5)}`;
}

const axios = require('axios');
const crypto = require('crypto');

// Guerrilla Mail API Configuration
const GUERRILLA_API_URL = 'https://api.guerrillamail.com/ajax.php';

// Generate temporary email
router.post('/email/generate', async (req, res) => {
    try {
        // Call Guerrilla Mail to get email and session token
        const response = await axios.get(`${GUERRILLA_API_URL}?f=get_email_address`);
        const { sid_token, email_addr } = response.data;

        if (!sid_token || !email_addr) {
            throw new Error('Invalid response from Guerrilla Mail');
        }

        const id = uuidv4(); // Use our own UUID to manage the session

        // Store session data
        tempEmails.set(id, {
            email: email_addr,
            sid_token: sid_token,
            inbox: [], // Cache or just for simulation fallback structure
            createdAt: new Date(),
            isApi: true
        });

        // Auto-delete after 1 hour
        setTimeout(() => {
            tempEmails.delete(id);
        }, 60 * 60 * 1000);

        res.json({ id, email: email_addr, isSimulation: false });
    } catch (error) {
        console.error('Error generating email via API, falling back to simulation:', error.message);

        // Fallback to simulation
        const id = uuidv4();
        const email = generateRandomEmail();

        tempEmails.set(id, {
            email,
            inbox: [],
            createdAt: new Date(),
            isApi: false
        });

        // Auto-delete after 1 hour
        setTimeout(() => {
            tempEmails.delete(id);
        }, 60 * 60 * 1000);

        res.json({ id, email, isSimulation: true });
    }
});

// Get email inbox
router.get('/email/:id/inbox', async (req, res) => {
    const { id } = req.params;
    const emailData = tempEmails.get(id);

    if (!emailData) {
        return res.status(404).json({ error: 'Email session not found or expired' });
    }

    // If simulation
    if (!emailData.isApi) {
        return res.json({ inbox: emailData.inbox });
    }

    try {
        // Fetch inbox from Guerrilla Mail
        const response = await axios.get(`${GUERRILLA_API_URL}?f=get_email_list&offset=0&limit=20&sid_token=${emailData.sid_token}`);
        const { list } = response.data;

        if (!Array.isArray(list)) {
            return res.json({ inbox: [] });
        }

        const inbox = list.map(mail => ({
            id: mail.mail_id,
            from: mail.mail_from,
            subject: mail.mail_subject,
            body: mail.mail_excerpt, // Preview only, full body needs fetch
            receivedAt: new Date(parseInt(mail.mail_timestamp) * 1000).toISOString(),
            read: parseInt(mail.mail_read) === 1
        }));

        res.json({ inbox });
    } catch (error) {
        console.error('Error fetching inbox from API:', error.message);
        res.json({ inbox: [] });
    }
});

// Get specific message content
router.get('/email/:id/message/:messageId', async (req, res) => {
    const { id } = req.params;
    const emailData = tempEmails.get(id);

    if (!emailData) {
        return res.status(404).json({ error: 'Email session not found' });
    }

    // If simulation
    if (!emailData.isApi) {
        const message = emailData.inbox.find(m => m.id === messageId);
        if (message) return res.json(message);
        return res.status(404).json({ error: 'Message not found' });
    }

    try {
        // Fetch full message from Guerrilla Mail
        const response = await axios.get(`${GUERRILLA_API_URL}?f=fetch_email&email_id=${messageId}&sid_token=${emailData.sid_token}`);
        const mail = response.data;

        if (mail) {
            return res.json({
                id: mail.mail_id,
                from: mail.mail_from,
                subject: mail.mail_subject,
                body: mail.mail_body, // Full body
                receivedAt: new Date(parseInt(mail.mail_timestamp) * 1000).toISOString()
            });
        }
        res.status(404).json({ error: 'Message not found' });
    } catch (error) {
        console.error('Error fetching message from API:', error.message);
        res.status(500).json({ error: 'Failed to fetch message' });
    }
});

// Simulate receiving email (for fallback mode)
router.post('/email/:id/receive', (req, res) => {
    const emailData = tempEmails.get(req.params.id);

    if (!emailData) {
        return res.status(404).json({ error: 'Email not found or expired' });
    }

    const { from, subject, body } = req.body;

    const message = {
        id: uuidv4(),
        from: from || 'demo@example.com',
        subject: subject || 'Test Email',
        body: body || 'This is a test email message.',
        receivedAt: new Date(),
        read: false
    };

    // If it's an API session, we can't really "inject" into the real inbox easily 
    // unless we just store it locally and merge. 
    // But for now, let's assume simulation is only for non-API sessions.
    // Or if user forces simulation on an API session (which the UI allows),
    // we can store it in a local 'simulatedMessages' array and merge it.

    if (!emailData.inbox) emailData.inbox = [];
    emailData.inbox.unshift(message);

    if (req.app.get('io')) {
        req.app.get('io').emit('new-email', { emailId: req.params.id, message });
    }

    res.json({ success: true, message });
});

// Generate temporary phone number
router.post('/sms/generate', (req, res) => {
    const id = uuidv4();
    const phone = generateRandomPhone();

    tempSMS.set(id, {
        phone,
        messages: [],
        createdAt: new Date()
    });

    // Auto-delete after 1 hour
    setTimeout(() => {
        tempSMS.delete(id);
    }, 60 * 60 * 1000);

    res.json({ id, phone });
});

// Get SMS messages
router.get('/sms/:id/messages', (req, res) => {
    const smsData = tempSMS.get(req.params.id);

    if (!smsData) {
        return res.status(404).json({ error: 'Phone number not found or expired' });
    }

    res.json({ messages: smsData.messages });
});

// Simulate receiving SMS (for demo purposes)
router.post('/sms/:id/receive', (req, res) => {
    const smsData = tempSMS.get(req.params.id);

    if (!smsData) {
        return res.status(404).json({ error: 'Phone number not found or expired' });
    }

    const { from, body } = req.body;

    const message = {
        id: uuidv4(),
        from: from || '+1 (555) 000-0000',
        body: body || 'This is a test SMS message.',
        receivedAt: new Date(),
        read: false
    };

    smsData.messages.unshift(message);

    // Emit socket event if available
    if (req.app.get('io')) {
        req.app.get('io').emit('new-sms', { smsId: req.params.id, message });
    }

    res.json({ success: true, message });
});

// Mark SMS as read
router.put('/sms/:smsId/message/:messageId/read', (req, res) => {
    const smsData = tempSMS.get(req.params.smsId);

    if (!smsData) {
        return res.status(404).json({ error: 'Phone number not found' });
    }

    const message = smsData.messages.find(m => m.id === req.params.messageId);
    if (message) {
        message.read = true;
    }

    res.json({ success: true });
});

module.exports = router;
