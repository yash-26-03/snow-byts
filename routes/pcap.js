const express = require('express');
const multer = require('multer');
const pcapp = require('pcap-parser');
const { Readable } = require('stream');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// PCAP file upload and analysis
router.post('/upload', upload.single('pcapFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No PCAP file uploaded' });
        }

        const packets = [];
        const protocols = {};
        const conversations = {};
        let totalBytes = 0;

        // Create a readable stream from the buffer
        const stream = Readable.from(req.file.buffer);
        const parser = pcapp.parse(stream);

        parser.on('packet', (packet) => {
            try {
                const packetInfo = {
                    timestamp: packet.header.timestampSeconds + packet.header.timestampMicroseconds / 1000000,
                    length: packet.header.originalLength,
                    capturedLength: packet.header.capturedLength,
                    rawData: packet.data ? packet.data.toString('hex') : ''
                };

                // Parse basic packet info
                if (packet.data && packet.data.length > 0) {
                    // Ethernet header (14 bytes)
                    if (packet.data.length >= 14) {
                        const etherType = packet.data.readUInt16BE(12);

                        // IPv4
                        if (etherType === 0x0800 && packet.data.length >= 34) {
                            const ihl = (packet.data[14] & 0x0F) * 4; // IP header length
                            const protocol = packet.data[23];
                            const srcIP = `${packet.data[26]}.${packet.data[27]}.${packet.data[28]}.${packet.data[29]}`;
                            const dstIP = `${packet.data[30]}.${packet.data[31]}.${packet.data[32]}.${packet.data[33]}`;

                            packetInfo.protocol = getProtocolName(protocol);
                            packetInfo.src = srcIP;
                            packetInfo.dst = dstIP;
                            packetInfo.ipHeaderLength = ihl;

                            // TCP (Protocol 6)
                            if (protocol === 6 && packet.data.length >= 14 + ihl + 4) {
                                const tcpStart = 14 + ihl;
                                packetInfo.srcPort = packet.data.readUInt16BE(tcpStart);
                                packetInfo.dstPort = packet.data.readUInt16BE(tcpStart + 2);

                                // TCP flags (byte at offset 13 in TCP header)
                                if (packet.data.length >= tcpStart + 14) {
                                    const flags = packet.data[tcpStart + 13];
                                    packetInfo.flags = parseTCPFlags(flags);
                                    const tcpHeaderLen = ((packet.data[tcpStart + 12] >> 4) * 4);
                                    packetInfo.payloadSize = packet.data.length - 14 - ihl - tcpHeaderLen;
                                }
                            }
                            // UDP (Protocol 17)
                            else if (protocol === 17 && packet.data.length >= 14 + ihl + 4) {
                                const udpStart = 14 + ihl;
                                packetInfo.srcPort = packet.data.readUInt16BE(udpStart);
                                packetInfo.dstPort = packet.data.readUInt16BE(udpStart + 2);
                                packetInfo.payloadSize = packet.data.length - 14 - ihl - 8; // UDP header is 8 bytes
                            }

                            // Count protocols
                            protocols[packetInfo.protocol] = (protocols[packetInfo.protocol] || 0) + 1;

                            // Track conversations
                            const convKey = `${srcIP} <-> ${dstIP}`;
                            if (!conversations[convKey]) {
                                conversations[convKey] = { packets: 0, bytes: 0 };
                            }
                            conversations[convKey].packets++;
                            conversations[convKey].bytes += packet.header.originalLength;
                        }
                        // IPv6
                        else if (etherType === 0x86DD) {
                            packetInfo.protocol = 'IPv6';
                            protocols['IPv6'] = (protocols['IPv6'] || 0) + 1;
                        }
                        // ARP
                        else if (etherType === 0x0806) {
                            packetInfo.protocol = 'ARP';
                            protocols['ARP'] = (protocols['ARP'] || 0) + 1;
                        }
                        else {
                            packetInfo.protocol = 'Other';
                            protocols['Other'] = (protocols['Other'] || 0) + 1;
                        }
                    }
                }

                totalBytes += packet.header.originalLength;
                packets.push(packetInfo);
            } catch (err) {
                console.error('Error parsing packet:', err);
            }
        });

        parser.on('end', () => {
            try {
                // Calculate statistics
                const stats = {
                    totalPackets: packets.length,
                    totalBytes: totalBytes,
                    averagePacketSize: packets.length > 0 ? (totalBytes / packets.length).toFixed(2) : 0,
                    duration: packets.length > 1 ?
                        (packets[packets.length - 1].timestamp - packets[0].timestamp).toFixed(2) : 0,
                    protocols: protocols,
                    topConversations: Object.entries(conversations)
                        .sort((a, b) => b[1].packets - a[1].packets)
                        .slice(0, 10)
                        .map(([key, value]) => ({ conversation: key, ...value }))
                };

                res.json({
                    success: true,
                    filename: req.file.originalname,
                    stats: stats,
                    packets: packets.slice(0, 2000) // Return first 2000 packets for display
                });
            } catch (err) {
                console.error('Error calculating stats:', err);
                res.status(500).json({ error: 'Failed to calculate statistics: ' + err.message });
            }
        });

        parser.on('error', (err) => {
            console.error('PCAP Parse Error:', err);
            res.status(500).json({ error: 'Failed to parse PCAP file: ' + err.message });
        });

    } catch (error) {
        console.error('PCAP Upload Error:', error);
        res.status(500).json({ error: 'Failed to process PCAP file: ' + error.message });
    }
});

// Helper function to parse TCP flags
function parseTCPFlags(flagsByte) {
    const flags = [];
    if (flagsByte & 0x01) flags.push('FIN');
    if (flagsByte & 0x02) flags.push('SYN');
    if (flagsByte & 0x04) flags.push('RST');
    if (flagsByte & 0x08) flags.push('PSH');
    if (flagsByte & 0x10) flags.push('ACK');
    if (flagsByte & 0x20) flags.push('URG');
    return flags.join(', ');
}

// Helper function to get protocol name from number
function getProtocolName(protocolNum) {
    const protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
        89: 'OSPF',
        132: 'SCTP'
    };
    return protocols[protocolNum] || `Protocol ${protocolNum}`;
}

// Live capture management
const { spawn } = require('child_process');
const os = require('os');
let captureProcess = null;
let captureStats = { packets: 0, bytes: 0 };

// Get available network interfaces
router.get('/interfaces', async (req, res) => {
    // Check if running on Vercel or if tshark is missing
    if (process.env.VERCEL) {
        return res.json({
            interfaces: [],
            warning: 'Live capture not supported in serverless environment'
        });
    }

    try {
        const { exec } = require('child_process');
        exec('tshark -D', (error, stdout, stderr) => {
            if (error) {
                console.warn('tshark not found or failed:', error.message);
                return res.json({
                    interfaces: [],
                    warning: 'tshark not installed - live capture disabled'
                });
            }

            const interfaces = stdout.trim().split('\n').map(line => {
                const match = line.match(/^(\d+)\.\s+(.+?)(?:\s+\((.+)\))?$/);
                if (match) {
                    return {
                        id: match[1],
                        name: match[2],
                        description: match[3] || match[2]
                    };
                }
                return null;
            }).filter(Boolean);

            // Find active interfaces using os.networkInterfaces()
            try {
                const osInterfaces = os.networkInterfaces();
                interfaces.forEach(iface => {
                    const osIface = osInterfaces[iface.name] || osInterfaces[iface.description];
                    if (osIface) {
                        // Check if it has an IPv4 address that is not internal
                        const active = osIface.some(details => details.family === 'IPv4' && !details.internal);
                        if (active) iface.active = true;
                    }
                });
            } catch (err) {
                console.warn('Error matching OS interfaces:', err);
            }

            // Sort active interfaces to top
            interfaces.sort((a, b) => (b.active ? 1 : 0) - (a.active ? 1 : 0));

            res.json({ interfaces });
        });
    } catch (error) {
        console.error('Interface listing error:', error);
        res.json({ interfaces: [], error: error.message });
    }
});

// Start live packet capture
router.post('/capture/start', (req, res) => {
    try {
        const { interface: iface, filter } = req.body;

        if (captureProcess) {
            return res.status(400).json({ error: 'Capture already running' });
        }

        const io = req.app.get('io');
        if (!io) {
            return res.status(500).json({ error: 'WebSocket not available' });
        }

        // Reset stats
        captureStats = { packets: 0, bytes: 0, startTime: Date.now() };

        // Build tshark command
        const args = [
            '-i', iface || 'any',
            '-T', 'ek',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', '_ws.col.Protocol',
            '-e', 'frame.len',
            '-e', 'tcp.flags',
            '-l' // Line buffered
        ];

        if (filter) {
            args.push('-f', filter);
        }

        captureProcess = spawn('tshark', args);

        let buffer = '';

        captureProcess.stdout.on('data', (data) => {
            buffer += data.toString();
            const lines = buffer.split('\n');
            buffer = lines.pop(); // Keep incomplete line in buffer

            lines.forEach(line => {
                if (line.trim()) {
                    try {
                        const packet = JSON.parse(line);

                        // Skip index lines in EK format
                        if (packet.index) return;

                        const layers = packet.layers;

                        if (layers) {
                            const packetData = {
                                timestamp: parseFloat(layers['frame.time_epoch']?.[0]) || Date.now() / 1000,
                                src: layers['ip.src']?.[0] || 'N/A',
                                dst: layers['ip.dst']?.[0] || 'N/A',
                                srcPort: layers['tcp.srcport']?.[0] || layers['udp.srcport']?.[0] || '-',
                                dstPort: layers['tcp.dstport']?.[0] || layers['udp.dstport']?.[0] || '-',
                                protocol: layers['_ws.col.Protocol']?.[0] || 'Unknown',
                                length: parseInt(layers['frame.len']?.[0]) || 0,
                                flags: layers['tcp.flags']?.[0] || ''
                            };

                            captureStats.packets++;
                            captureStats.bytes += packetData.length;

                            io.emit('live-packet', packetData);
                            io.emit('capture-stats', captureStats);
                        }
                    } catch (err) {
                        console.error('Error parsing packet:', err);
                    }
                }
            });
        });

        captureProcess.stderr.on('data', (data) => {
            console.error('tshark stderr:', data.toString());
        });

        captureProcess.on('close', (code) => {
            console.log(`tshark process exited with code ${code}`);
            captureProcess = null;
            io.emit('capture-stopped', captureStats);
        });

        res.json({ success: true, message: 'Capture started' });

    } catch (error) {
        console.error('Capture start error:', error);
        res.status(500).json({ error: 'Failed to start capture: ' + error.message });
    }
});

// Stop live packet capture
router.post('/capture/stop', (req, res) => {
    try {
        if (!captureProcess) {
            return res.status(400).json({ error: 'No capture running' });
        }

        captureProcess.kill('SIGINT');
        captureProcess = null;

        res.json({
            success: true,
            message: 'Capture stopped',
            stats: captureStats
        });

    } catch (error) {
        res.status(500).json({ error: 'Failed to stop capture: ' + error.message });
    }
});

// Get capture status
router.get('/capture/status', (req, res) => {
    res.json({
        capturing: !!captureProcess,
        stats: captureStats
    });
});

module.exports = router;
