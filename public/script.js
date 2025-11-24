document.addEventListener('DOMContentLoaded', () => {
    // Clock functionality
    function updateClock() {
        const now = new Date();
        const timeString = now.toLocaleTimeString('en-US', { hour12: false });
        document.getElementById('clock').textContent = timeString;
    }
    setInterval(updateClock, 1000);
    updateClock();

    // Route to tool ID mapping
    const routeMap = {
        'encoders/base64': 'base64',
        'encoders/base32': 'base32',
        'encoders/url': 'url',
        'encoders/hex': 'hex',
        'encoders/hash': 'hash',
        'generators/password': 'password',
        'hash/md5': 'md5',
        'hash/sha1': 'sha1',
        'hash/sha256': 'sha256',
        'hash/sha512': 'sha512',
        'scanners/virustotal-file': 'vt-file',
        'scanners/virustotal-hash': 'vt-hash',
        'scanners/virustotal-url': 'vt-url',
        'scanners/virustotal-ip': 'vt-ip',
        'network/pcap': 'pcap',
        'terminal/shell': 'terminal',
        'temp/email': 'temp-email',
        'temp/sms': 'temp-sms'
    };

    // Category names mapping
    const categoryNames = {
        'encoders': 'ENCODERS/DECODERS',
        'hash': 'HASH_TOOLS',
        'virustotal': 'VIRUSTOTAL',
        'terminal': 'TERMINAL',
        'temp': 'TEMP_SERVICES'
    };

    // Tool names mapping
    const toolNames = {
        'base64': 'BASE64',
        'base32': 'BASE32',
        'url': 'URL_ENCODER',
        'hex': 'HEX',
        'md5': 'MD5',
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'sha512': 'SHA512',
        'vt-file': 'FILE_SCANNER',
        'vt-url': 'URL_SCANNER',
        'vt-hash': 'HASH_LOOKUP',
        'vt-ip': 'IP/DOMAIN_LOOKUP',
        'terminal': 'WEB_TERMINAL',
        'temp-email': 'TEMP_EMAIL',
        'temp-sms': 'TEMP_SMS'
    };

    // Category expand/collapse logic
    const categoryHeaders = document.querySelectorAll('.category-header');
    categoryHeaders.forEach(header => {
        header.addEventListener('click', () => {
            const items = header.nextElementSibling;
            const isExpanded = header.classList.contains('expanded');

            if (isExpanded) {
                header.classList.remove('expanded');
                items.classList.remove('expanded');
            } else {
                header.classList.add('expanded');
                items.classList.add('expanded');
            }
        });
    });

    // Update breadcrumb
    function updateBreadcrumb(route) {
        const breadcrumb = document.getElementById('breadcrumb');
        if (!route) {
            breadcrumb.innerHTML = '<span class="breadcrumb-item">HOME</span>';
            return;
        }

        const parts = route.split('/');
        const category = categoryNames[parts[0]] || parts[0].toUpperCase();
        const toolId = routeMap[route];
        const tool = toolNames[toolId] || parts[1].toUpperCase();

        breadcrumb.innerHTML = `
            <span class="breadcrumb-item">HOME</span>
            <span class="breadcrumb-item">${category}</span>
            <span class="breadcrumb-item">${tool}</span>
        `;
    }

    // Navigate to route
    function navigateTo(route) {
        const toolId = routeMap[route];
        if (!toolId) return;

        // Update URL hash
        window.location.hash = route;

        // Remove active class from all items and panels
        document.querySelectorAll('.category-items li').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelectorAll('.tool-panel').forEach(panel => {
            panel.classList.remove('active');
        });

        // Add active class to current item
        const activeItem = document.querySelector(`[data-route="${route}"]`);
        if (activeItem) {
            activeItem.classList.add('active');

            // Expand parent category
            const categoryItems = activeItem.closest('.category-items');
            const categoryHeader = categoryItems.previousElementSibling;
            categoryHeader.classList.add('expanded', 'active');
            categoryItems.classList.add('expanded');
        }

        // Show corresponding panel
        const panel = document.getElementById(`${toolId}-tool`);
        if (panel) {
            panel.classList.add('active');
        }

        // Update breadcrumb
        updateBreadcrumb(route);
    }

    // Handle route clicks
    document.querySelectorAll('[data-route]').forEach(item => {
        item.addEventListener('click', () => {
            const route = item.dataset.route;
            navigateTo(route);
        });
    });

    // Handle browser back/forward
    window.addEventListener('hashchange', () => {
        const route = window.location.hash.slice(1);
        if (route && routeMap[route]) {
            navigateTo(route);
        }
    });

    // Initialize route from URL hash or default to first tool
    const initialRoute = window.location.hash.slice(1);
    if (initialRoute && routeMap[initialRoute]) {
        navigateTo(initialRoute);
    } else {
        navigateTo('encoders/base64');
    }

    // --- Base64 Tool ---
    const base64Input = document.getElementById('base64-input');
    const base64Output = document.getElementById('base64-output');

    document.getElementById('btn-base64-encode').addEventListener('click', () => {
        try {
            if (!base64Input.value) return;
            base64Output.value = btoa(base64Input.value);
        } catch (e) { base64Output.value = 'ERROR: ENCODING_FAILED'; }
    });

    document.getElementById('btn-base64-decode').addEventListener('click', () => {
        try {
            if (!base64Input.value) return;
            base64Output.value = atob(base64Input.value);
        } catch (e) { base64Output.value = 'ERROR: INVALID_BASE64'; }
    });

    document.getElementById('btn-base64-clear').addEventListener('click', () => {
        base64Input.value = '';
        base64Output.value = '';
    });

    // --- Base32 Tool (Simple Implementation) ---
    const base32Input = document.getElementById('base32-input');
    const base32Output = document.getElementById('base32-output');
    const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    function base32Encode(s) {
        let bits = 0;
        let value = 0;
        let output = "";
        for (let i = 0; i < s.length; i++) {
            value = (value << 8) | s.charCodeAt(i);
            bits += 8;
            while (bits >= 5) {
                output += base32Chars[(value >>> (bits - 5)) & 31];
                bits -= 5;
            }
        }
        if (bits > 0) {
            output += base32Chars[(value << (5 - bits)) & 31];
        }
        while (output.length % 8 !== 0) {
            output += "=";
        }
        return output;
    }

    function base32Decode(s) {
        let bits = 0;
        let value = 0;
        let output = "";
        s = s.replace(/=+$/, "");
        for (let i = 0; i < s.length; i++) {
            let idx = base32Chars.indexOf(s[i].toUpperCase());
            if (idx === -1) throw new Error("Invalid Base32 character");
            value = (value << 5) | idx;
            bits += 5;
            while (bits >= 8) {
                output += String.fromCharCode((value >>> (bits - 8)) & 255);
                bits -= 8;
            }
        }
        return output;
    }

    document.getElementById('btn-base32-encode').addEventListener('click', () => {
        try {
            if (!base32Input.value) return;
            base32Output.value = base32Encode(base32Input.value);
        } catch (e) { base32Output.value = 'ERROR: ENCODING_FAILED'; }
    });

    document.getElementById('btn-base32-decode').addEventListener('click', () => {
        try {
            if (!base32Input.value) return;
            base32Output.value = base32Decode(base32Input.value);
        } catch (e) { base32Output.value = 'ERROR: INVALID_BASE32'; }
    });

    document.getElementById('btn-base32-clear').addEventListener('click', () => {
        base32Input.value = '';
        base32Output.value = '';
    });

    // --- Hashing Tools (MD5, SHA1, SHA256, SHA512) ---
    function setupHasher(type, algo) {
        const input = document.getElementById(`${type}-input`);
        const output = document.getElementById(`${type}-output`);
        const fileInput = document.getElementById(`${type}-file`);

        document.getElementById(`btn-${type}-hash`).addEventListener('click', () => {
            if (fileInput && fileInput.files.length > 0) {
                const file = fileInput.files[0];
                const reader = new FileReader();
                reader.onload = function (e) {
                    const wordArray = CryptoJS.lib.WordArray.create(e.target.result);
                    output.value = algo(wordArray).toString();
                };
                reader.readAsArrayBuffer(file);
            } else if (input.value) {
                output.value = algo(input.value).toString();
            }
        });

        document.getElementById(`btn-${type}-clear`).addEventListener('click', () => {
            input.value = '';
            output.value = '';
            if (fileInput) fileInput.value = '';
        });
    }

    if (typeof CryptoJS !== 'undefined') {
        setupHasher('md5', CryptoJS.MD5);
        setupHasher('sha1', CryptoJS.SHA1);
        setupHasher('sha256', CryptoJS.SHA256);
        setupHasher('sha512', CryptoJS.SHA512);
    } else {
        console.error("CryptoJS not loaded");
    }

    // --- MD5 Hash Comparison ---
    const md5Expected = document.getElementById('md5-expected');
    const md5Output = document.getElementById('md5-output');
    const md5ComparisonResult = document.getElementById('md5-comparison-result');

    document.getElementById('btn-md5-compare').addEventListener('click', () => {
        const expectedHash = md5Expected.value.trim().toLowerCase();
        const actualHash = md5Output.value.trim().toLowerCase();

        if (!expectedHash || !actualHash) {
            md5ComparisonResult.className = 'comparison-result mismatch';
            md5ComparisonResult.textContent = 'ERROR: BOTH HASHES REQUIRED FOR COMPARISON';
            return;
        }

        if (expectedHash === actualHash) {
            md5ComparisonResult.className = 'comparison-result match';
            md5ComparisonResult.textContent = '✓ MATCH: FILE INTEGRITY VERIFIED';
        } else {
            md5ComparisonResult.className = 'comparison-result mismatch';
            md5ComparisonResult.textContent = '✗ MISMATCH: FILE INTEGRITY COMPROMISED';
        }
    });

    // Clear comparison result when clearing MD5 fields
    const originalMd5Clear = document.getElementById('btn-md5-clear');
    originalMd5Clear.addEventListener('click', () => {
        md5Expected.value = '';
        md5ComparisonResult.className = 'comparison-result';
        md5ComparisonResult.textContent = '';
    });

    // --- URL Tool ---
    const urlInput = document.getElementById('url-input');
    const urlOutput = document.getElementById('url-output');

    document.getElementById('btn-url-encode').addEventListener('click', () => {
        if (!urlInput.value) return;
        urlOutput.value = encodeURIComponent(urlInput.value);
    });

    document.getElementById('btn-url-decode').addEventListener('click', () => {
        try {
            if (!urlInput.value) return;
            urlOutput.value = decodeURIComponent(urlInput.value);
        } catch (e) { urlOutput.value = 'ERROR: INVALID_URL_ENCODING'; }
    });

    document.getElementById('btn-url-clear').addEventListener('click', () => {
        urlInput.value = '';
        urlOutput.value = '';
    });

    // --- Hex Tool ---
    const hexInput = document.getElementById('hex-input');
    const hexOutput = document.getElementById('hex-output');

    document.getElementById('btn-hex-encode').addEventListener('click', () => {
        if (!hexInput.value) return;
        let hex = '';
        for (let i = 0; i < hexInput.value.length; i++) {
            hex += hexInput.value.charCodeAt(i).toString(16).padStart(2, '0');
        }
        hexOutput.value = hex;
    });

    document.getElementById('btn-hex-decode').addEventListener('click', () => {
        try {
            let hex = hexInput.value.replace(/\s/g, '');
            if (hex.length % 2 !== 0) throw new Error('Invalid length');
            let str = '';
            for (let i = 0; i < hex.length; i += 2) {
                str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
            }
            hexOutput.value = str;
        } catch (e) { hexOutput.value = 'ERROR: INVALID_HEX_STRING'; }
    });

    document.getElementById('btn-hex-clear').addEventListener('click', () => {
        hexInput.value = '';
        hexOutput.value = '';
    });

    // Glitch effect
    const title = document.querySelector('.glitch');
    title.addEventListener('mouseover', () => {
        let original = title.dataset.text;
        let iterations = 0;
        const interval = setInterval(() => {
            title.innerText = title.innerText.split('')
                .map((letter, index) => {
                    if (index < iterations) return original[index];
                    return String.fromCharCode(65 + Math.floor(Math.random() * 26));
                })
                .join('');

            if (iterations >= original.length) clearInterval(interval);
            iterations += 1 / 3;
        }, 30);
    });

    // --- VirusTotal Integration ---

    // Helper function to show status
    function showStatus(elementId, message) {
        const statusEl = document.getElementById(elementId);
        statusEl.textContent = message;
        statusEl.classList.add('active');
    }

    // Helper function to hide status
    function hideStatus(elementId) {
        const statusEl = document.getElementById(elementId);
        statusEl.classList.remove('active');
    }

    // Helper function to show result
    function showResult(elementId, html) {
        const resultEl = document.getElementById(elementId);
        resultEl.innerHTML = html;
        resultEl.classList.add('active');
    }

    // Helper function to hide result
    function hideResult(elementId) {
        const resultEl = document.getElementById(elementId);
        resultEl.classList.remove('active');
        resultEl.innerHTML = '';
    }

    // Helper function to get threat class
    function getThreatClass(malicious, suspicious) {
        if (malicious > 0) return 'malicious';
        if (suspicious > 0) return 'suspicious';
        return 'safe';
    }

    // Helper function to poll for analysis results
    async function pollAnalysis(analysisId, resultElementId, statusElementId) {
        showStatus(statusElementId, 'ANALYZING... PLEASE WAIT...');

        let attempts = 0;
        const maxAttempts = 20;

        const poll = async () => {
            try {
                const response = await fetch(`/api/vt/file-report/${analysisId}`);
                const data = await response.json();

                if (data.data && data.data.attributes && data.data.attributes.status === 'completed') {
                    hideStatus(statusElementId);
                    displayAnalysisResult(data.data.attributes, resultElementId);
                } else if (attempts < maxAttempts) {
                    attempts++;
                    setTimeout(poll, 3000); // Poll every 3 seconds
                } else {
                    hideStatus(statusElementId);
                    showResult(resultElementId, '<p style="color: #ff3333;">ANALYSIS TIMEOUT. TRY AGAIN LATER.</p>');
                }
            } catch (error) {
                hideStatus(statusElementId);
                showResult(resultElementId, `<p style="color: #ff3333;">ERROR: ${error.message}</p>`);
            }
        };

        poll();
    }

    // Helper function to display analysis results
    function displayAnalysisResult(attributes, resultElementId) {
        const stats = attributes.stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const undetected = stats.undetected || 0;
        const total = malicious + suspicious + undetected + (stats.harmless || 0);

        const threatClass = getThreatClass(malicious, suspicious);

        let html = `
            <h3>SCAN RESULTS</h3>
            <div class="detection-ratio ${threatClass}">
                DETECTION: ${malicious}/${total} (${suspicious} SUSPICIOUS)
            </div>
            <div class="info-row">
                <span class="info-label">STATUS:</span>
                <span class="info-value">${threatClass.toUpperCase()}</span>
            </div>
        `;

        if (attributes.results) {
            html += '<h3>VENDOR DETECTIONS</h3><div class="vendor-list">';
            const vendors = Object.entries(attributes.results).slice(0, 20);
            vendors.forEach(([vendor, result]) => {
                const detected = result.category === 'malicious' || result.category === 'suspicious';
                const detectedClass = detected ? 'detected' : '';
                html += `
                    <div class="vendor-item ${detectedClass}">
                        <strong>${vendor}:</strong> ${result.result || 'Clean'}
                    </div>
                `;
            });
            html += '</div>';
        }

        showResult(resultElementId, html);
    }

    // VirusTotal File Scanner
    const vtFileInput = document.getElementById('vt-file-input');
    document.getElementById('btn-vt-file-scan').addEventListener('click', async () => {
        if (!vtFileInput.files.length) {
            showResult('vt-file-result', '<p style="color: #ff3333;">ERROR: NO FILE SELECTED</p>');
            return;
        }

        const formData = new FormData();
        formData.append('file', vtFileInput.files[0]);

        showStatus('vt-file-status', 'UPLOADING FILE TO VIRUSTOTAL...');
        hideResult('vt-file-result');

        try {
            const response = await fetch('/api/vt/file-scan', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (data.data && data.data.id) {
                pollAnalysis(data.data.id, 'vt-file-result', 'vt-file-status');
            } else {
                hideStatus('vt-file-status');
                showResult('vt-file-result', `<p style="color: #ff3333;">ERROR: ${data.error || 'SCAN FAILED'}</p>`);
            }
        } catch (error) {
            hideStatus('vt-file-status');
            showResult('vt-file-result', `<p style="color: #ff3333;">ERROR: ${error.message}</p>`);
        }
    });

    document.getElementById('btn-vt-file-clear').addEventListener('click', () => {
        vtFileInput.value = '';
        hideStatus('vt-file-status');
        hideResult('vt-file-result');
    });

    // VirusTotal URL Scanner
    const vtUrlInput = document.getElementById('vt-url-input');
    document.getElementById('btn-vt-url-scan').addEventListener('click', async () => {
        const url = vtUrlInput.value.trim();
        if (!url) {
            showResult('vt-url-result', '<p style="color: #ff3333;">ERROR: NO URL PROVIDED</p>');
            return;
        }

        showStatus('vt-url-status', 'SUBMITTING URL TO VIRUSTOTAL...');
        hideResult('vt-url-result');

        try {
            const response = await fetch('/api/vt/url-scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (data.data && data.data.id) {
                pollAnalysis(data.data.id, 'vt-url-result', 'vt-url-status');
            } else {
                hideStatus('vt-url-status');
                showResult('vt-url-result', `<p style="color: #ff3333;">ERROR: ${data.error || 'SCAN FAILED'}</p>`);
            }
        } catch (error) {
            hideStatus('vt-url-status');
            showResult('vt-url-result', `<p style="color: #ff3333;">ERROR: ${error.message}</p>`);
        }
    });

    document.getElementById('btn-vt-url-clear').addEventListener('click', () => {
        vtUrlInput.value = '';
        hideStatus('vt-url-status');
        hideResult('vt-url-result');
    });

    // VirusTotal Hash Lookup
    const vtHashInput = document.getElementById('vt-hash-input');
    document.getElementById('btn-vt-hash-lookup').addEventListener('click', async () => {
        const hash = vtHashInput.value.trim();
        if (!hash) {
            showResult('vt-hash-result', '<p style="color: #ff3333;">ERROR: NO HASH PROVIDED</p>');
            return;
        }

        showStatus('vt-hash-status', 'LOOKING UP HASH IN VIRUSTOTAL DATABASE...');
        hideResult('vt-hash-result');

        try {
            const response = await fetch(`/api/vt/hash-lookup/${hash}`);
            const data = await response.json();

            if (data.data && data.data.attributes) {
                hideStatus('vt-hash-status');
                const attrs = data.data.attributes;
                const stats = attrs.last_analysis_stats || {};
                const malicious = stats.malicious || 0;
                const suspicious = stats.suspicious || 0;
                const undetected = stats.undetected || 0;
                const total = malicious + suspicious + undetected + (stats.harmless || 0);

                const threatClass = getThreatClass(malicious, suspicious);

                let html = `
                    <h3>HASH LOOKUP RESULTS</h3>
                    <div class="detection-ratio ${threatClass}">
                        DETECTION: ${malicious}/${total} (${suspicious} SUSPICIOUS)
                    </div>
                    <div class="info-row">
                        <span class="info-label">FILE NAME:</span>
                        <span class="info-value">${attrs.meaningful_name || 'N/A'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">FILE TYPE:</span>
                        <span class="info-value">${attrs.type_description || 'N/A'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">SIZE:</span>
                        <span class="info-value">${attrs.size || 'N/A'} bytes</span>
                    </div>
                `;

                showResult('vt-hash-result', html);
            } else {
                hideStatus('vt-hash-status');
                showResult('vt-hash-result', `<p style="color: #ff3333;">ERROR: ${data.error || 'HASH NOT FOUND'}</p>`);
            }
        } catch (error) {
            hideStatus('vt-hash-status');
            showResult('vt-hash-result', `<p style="color: #ff3333;">ERROR: ${error.message}</p>`);
        }
    });

    document.getElementById('btn-vt-hash-clear').addEventListener('click', () => {
        vtHashInput.value = '';
        hideStatus('vt-hash-status');
        hideResult('vt-hash-result');
    });

    // VirusTotal IP/Domain Lookup
    const vtIpInput = document.getElementById('vt-ip-input');
    const vtIpType = document.getElementById('vt-ip-type');

    document.getElementById('btn-vt-ip-lookup').addEventListener('click', async () => {
        const value = vtIpInput.value.trim();
        const type = vtIpType.value;

        if (!value) {
            showResult('vt-ip-result', '<p style="color: #ff3333;">ERROR: NO IP/DOMAIN PROVIDED</p>');
            return;
        }

        const endpoint = type === 'ip' ? `/api/vt/ip-lookup/${value}` : `/api/vt/domain-lookup/${value}`;
        showStatus('vt-ip-status', `LOOKING UP ${type.toUpperCase()} IN VIRUSTOTAL...`);
        hideResult('vt-ip-result');

        try {
            const response = await fetch(endpoint);
            const data = await response.json();

            if (data.data && data.data.attributes) {
                hideStatus('vt-ip-status');
                const attrs = data.data.attributes;
                const stats = attrs.last_analysis_stats || {};
                const malicious = stats.malicious || 0;
                const suspicious = stats.suspicious || 0;
                const harmless = stats.harmless || 0;
                const undetected = stats.undetected || 0;
                const total = malicious + suspicious + harmless + undetected;

                const threatClass = getThreatClass(malicious, suspicious);

                let html = `
                    <h3>${type.toUpperCase()} REPUTATION</h3>
                    <div class="detection-ratio ${threatClass}">
                        MALICIOUS: ${malicious}/${total} (${suspicious} SUSPICIOUS)
                    </div>
                    <div class="info-row">
                        <span class="info-label">REPUTATION:</span>
                        <span class="info-value">${attrs.reputation || 0}</span>
                    </div>
                `;

                if (type === 'domain') {
                    html += `
                        <div class="info-row">
                            <span class="info-label">CATEGORIES:</span>
                            <span class="info-value">${Object.values(attrs.categories || {}).join(', ') || 'N/A'}</span>
                        </div>
                    `;
                }

                showResult('vt-ip-result', html);
            } else {
                hideStatus('vt-ip-status');
                showResult('vt-ip-result', `<p style="color: #ff3333;">ERROR: ${data.error || 'LOOKUP FAILED'}</p>`);
            }
        } catch (error) {
            hideStatus('vt-ip-status');
            showResult('vt-ip-result', `<p style="color: #ff3333;">ERROR: ${error.message}</p>`);
        }
    });

    document.getElementById('btn-vt-ip-clear').addEventListener('click', () => {
        vtIpInput.value = '';
        hideStatus('vt-ip-status');
        hideResult('vt-ip-result');
    });

    // --- Hybrid Terminal Integration ---
    let terminalInstance = null;
    let terminalInitialized = false;
    let socket = null;
    let terminalMode = null; // 'simulated' or 'real'

    // Client-side File System (Restored)
    const fileSystem = {
        '/root': {
            type: 'dir',
            children: {
                'Documents': { type: 'dir', children: {} },
                'Downloads': { type: 'dir', children: {} },
                'Tools': { type: 'dir', children: {} },
                'scan_report.pdf': { type: 'file' },
                'notes.txt': { type: 'file' }
            }
        }
    };

    let currentCwd = '/root';
    let commandBuffer = '';

    function resolvePath(cwd, target) {
        if (!target) return cwd;
        let parts;
        if (target.startsWith('/')) {
            parts = target.split('/').filter(p => p);
        } else {
            const cwdParts = cwd.split('/').filter(p => p);
            const targetParts = target.split('/').filter(p => p);
            parts = [...cwdParts, ...targetParts];
        }
        const stack = [];
        for (const part of parts) {
            if (part === '.') continue;
            if (part === '..') {
                stack.pop();
            } else {
                stack.push(part);
            }
        }
        return '/' + stack.join('/');
    }

    function getDir(path) {
        if (path === '/') return { type: 'dir', children: fileSystem };
        if (path === '/root') return fileSystem['/root'];
        if (path.startsWith('/root/')) {
            const parts = path.split('/').slice(2);
            let current = fileSystem['/root'];
            for (const part of parts) {
                if (current && current.children && current.children[part]) {
                    current = current.children[part];
                } else {
                    return null;
                }
            }
            return current;
        } else if (path === '/') {
            return { type: 'dir', children: { 'root': fileSystem['/root'] } };
        }
        return null;
    }

    function initializeTerminal(mode) {
        if (terminalInitialized) return;
        terminalMode = mode;

        // Create xterm instance
        terminalInstance = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            fontFamily: 'Share Tech Mono, monospace',
            theme: {
                background: '#000000',
                foreground: '#00ff00',
                cursor: '#00ff00',
                cursorAccent: '#000000',
                selection: '#003300'
            },
            scrollback: 5000,
            scrollOnUserInput: true,
            screenReaderMode: true
        });

        const fitAddon = new FitAddon.FitAddon();
        terminalInstance.loadAddon(fitAddon);

        const container = document.getElementById('terminal-container');
        terminalInstance.open(container);
        fitAddon.fit();

        window.addEventListener('resize', () => {
            fitAddon.fit();
            if (terminalMode === 'real' && socket) {
                socket.emit('resize', { cols: terminalInstance.cols, rows: terminalInstance.rows });
            }
        });

        if (terminalMode === 'real') {
            // Real-time mode
            terminalInstance.writeln('\x1b[1;32m╔═══════════════════════════════════════════════════════════╗\x1b[0m');
            terminalInstance.writeln('\x1b[1;32m║         REAL-TIME TERMINAL (EXPERIMENTAL)                ║\x1b[0m');
            terminalInstance.writeln('\x1b[1;32m╚═══════════════════════════════════════════════════════════╝\x1b[0m');
            terminalInstance.writeln('');

            // Connect socket
            if (!socket) socket = io();

            // Forward input to server
            terminalInstance.onData(data => {
                if (socket) {
                    socket.emit('input', data);
                }
            });

            // Receive output from server
            socket.on('output', data => {
                terminalInstance.write(data);
            });

            // Initial resize
            socket.emit('resize', { cols: terminalInstance.cols, rows: terminalInstance.rows });

        } else {
            // Simulated Mode
            terminalInstance.writeln('\x1b[1;32m╔═══════════════════════════════════════════════════════════╗\x1b[0m');
            terminalInstance.writeln('\x1b[1;32m║         CYBER SECURITY TOOLS - WEB TERMINAL              ║\x1b[0m');
            terminalInstance.writeln('\x1b[1;32m╚═══════════════════════════════════════════════════════════╝\x1b[0m');
            terminalInstance.writeln('');
            terminalInstance.writeln('\x1b[1;33m⚠️  WARNING: Simulated Environment (Safe Mode)\x1b[0m');
            terminalInstance.writeln('');

            const prompt = () => {
                terminalInstance.write(`\r\nroot@kali:${currentCwd}# `);
            };

            prompt();

            terminalInstance.onData(e => {
                switch (e) {
                    case '\r': // Enter
                        terminalInstance.write('\r\n');
                        if (commandBuffer.trim()) {
                            handleCommand(commandBuffer.trim());
                        } else {
                            prompt();
                        }
                        commandBuffer = '';
                        break;
                    case '\u007F': // Backspace
                        if (commandBuffer.length > 0) {
                            terminalInstance.write('\b \b');
                            commandBuffer = commandBuffer.slice(0, -1);
                        }
                        break;
                    default:
                        if (e >= String.fromCharCode(0x20) && e <= String.fromCharCode(0x7E) || e >= '\u00a0') {
                            commandBuffer += e;
                            terminalInstance.write(e);
                        }
                }
            });

            function handleCommand(cmdStr) {
                const args = cmdStr.split(' ');
                const cmd = args[0].toLowerCase();

                switch (cmd) {
                    case 'help':
                        terminalInstance.writeln('Available commands:');
                        terminalInstance.writeln('  \x1b[1;33mhelp\x1b[0m     - Show this help message');
                        terminalInstance.writeln('  \x1b[1;33mls\x1b[0m       - List files');
                        terminalInstance.writeln('  \x1b[1;33mpwd\x1b[0m      - Print working directory');
                        terminalInstance.writeln('  \x1b[1;33mcd\x1b[0m       - Change directory');
                        terminalInstance.writeln('  \x1b[1;33mmkdir\x1b[0m    - Create directory');
                        terminalInstance.writeln('  \x1b[1;33mwhoami\x1b[0m   - Print current user');
                        terminalInstance.writeln('  \x1b[1;33mclear\x1b[0m    - Clear terminal screen');
                        terminalInstance.writeln('  \x1b[1;33msudo\x1b[0m     - Execute a command as another user');
                        terminalInstance.writeln('  \x1b[1;33mpkg\x1b[0m      - Package manager simulation');
                        terminalInstance.writeln('  \x1b[1;33mping\x1b[0m     - Send ICMP ECHO_REQUEST to network hosts');
                        terminalInstance.writeln('  \x1b[1;33mnmap\x1b[0m     - Network exploration tool and security scanner');
                        terminalInstance.writeln('  \x1b[1;33mip\x1b[0m       - Show IP address');
                        terminalInstance.writeln('  \x1b[1;33mnc\x1b[0m       - Netcat (Connect/Listen)');
                        prompt();
                        break;
                    case 'clear':
                        terminalInstance.write('\x1b[2J\x1b[H');
                        prompt();
                        break;
                    case 'ls':
                        const dir = getDir(currentCwd);
                        if (dir && dir.children) {
                            const items = Object.entries(dir.children).map(([name, item]) => {
                                return item.type === 'dir' ? `\x1b[1;34m${name}\x1b[0m` : `\x1b[1;32m${name}\x1b[0m`;
                            });
                            terminalInstance.writeln(items.join('  '));
                        }
                        prompt();
                        break;
                    case 'pwd':
                        terminalInstance.writeln(currentCwd);
                        prompt();
                        break;
                    case 'cd':
                        if (!args[1]) {
                            currentCwd = '/root';
                        } else {
                            const target = resolvePath(currentCwd, args[1]);
                            const targetDir = getDir(target);
                            if (targetDir && targetDir.type === 'dir') {
                                currentCwd = target;
                            } else {
                                terminalInstance.writeln(`bash: cd: ${args[1]}: No such file or directory`);
                            }
                        }
                        prompt();
                        break;
                    case 'mkdir':
                        if (!args[1]) {
                            terminalInstance.writeln('mkdir: missing operand');
                        } else {
                            const currentDirObj = getDir(currentCwd);
                            if (currentDirObj && currentDirObj.type === 'dir') {
                                if (currentDirObj.children[args[1]]) {
                                    terminalInstance.writeln(`mkdir: cannot create directory '${args[1]}': File exists`);
                                } else {
                                    currentDirObj.children[args[1]] = { type: 'dir', children: {} };
                                }
                            } else {
                                terminalInstance.writeln(`mkdir: cannot create directory '${args[1]}': No such file or directory`);
                            }
                        }
                        prompt();
                        break;
                    case 'whoami':
                        terminalInstance.writeln('root');
                        prompt();
                        break;
                    case 'ip':
                        terminalInstance.writeln('eth0: 192.168.1.105');
                        terminalInstance.writeln('lo: 127.0.0.1');
                        prompt();
                        break;
                    case 'sudo':
                        if (args.length > 1) {
                            terminalInstance.write(`[sudo] password for root: `);
                            setTimeout(() => {
                                terminalInstance.writeln('');
                                const subCmd = args.slice(1).join(' ');
                                handleCommand(subCmd);
                            }, 500);
                            return;
                        } else {
                            terminalInstance.writeln('sudo: missing command');
                            prompt();
                        }
                        break;
                    case 'pkg':
                        if (args[1] === 'install') {
                            terminalInstance.writeln('Updating repository lists...');
                            terminalInstance.writeln(`Downloading ${args[2] || 'package'}...`);
                            terminalInstance.writeln('Installing...');
                            setTimeout(() => {
                                terminalInstance.writeln('\x1b[1;32mDone!\x1b[0m');
                                prompt();
                            }, 1000);
                            return;
                        } else {
                            terminalInstance.writeln('Usage: pkg install <package_name>');
                            prompt();
                        }
                        break;
                    case 'ping':
                        if (!args[1]) {
                            terminalInstance.writeln('Usage: ping <host>');
                            prompt();
                        } else {
                            const host = args[1];
                            terminalInstance.writeln(`PING ${host} (${host}) 56(84) bytes of data.`);
                            let count = 0;
                            const max = 4;
                            const interval = setInterval(() => {
                                count++;
                                const time = (Math.random() * 10 + 20).toFixed(1);
                                terminalInstance.writeln(`64 bytes from ${host}: icmp_seq=${count} ttl=57 time=${time} ms`);
                                if (count >= max) {
                                    clearInterval(interval);
                                    terminalInstance.writeln(`--- ${host} ping statistics ---`);
                                    terminalInstance.writeln(`${max} packets transmitted, ${max} received, 0% packet loss, time ${max * 1000}ms`);
                                    prompt();
                                }
                            }, 1000);
                            return;
                        }
                        break;
                    case 'nmap':
                        if (!args[1]) {
                            terminalInstance.writeln('Usage: nmap <target>');
                            prompt();
                        } else {
                            const target = args[1];
                            terminalInstance.writeln(`Starting Nmap 7.94 ( https://nmap.org ) at ${new Date().toISOString().split('T')[0]}`);
                            const latency = (Math.random() * 0.05 + 0.001).toFixed(4);
                            terminalInstance.writeln(`Nmap scan report for ${target}`);
                            terminalInstance.writeln(`Host is up (${latency}s latency).`);
                            const closedPorts = 990 + Math.floor(Math.random() * 10);
                            terminalInstance.writeln(`Not shown: ${closedPorts} closed tcp ports (reset)`);

                            setTimeout(() => {
                                terminalInstance.writeln(`PORT    STATE SERVICE`);
                                const commonPorts = [
                                    { port: 21, service: 'ftp' }, { port: 22, service: 'ssh' }, { port: 23, service: 'telnet' },
                                    { port: 25, service: 'smtp' }, { port: 53, service: 'domain' }, { port: 80, service: 'http' },
                                    { port: 110, service: 'pop3' }, { port: 143, service: 'imap' }, { port: 443, service: 'https' },
                                    { port: 3306, service: 'mysql' }, { port: 3389, service: 'ms-wbt-server' },
                                    { port: 5432, service: 'postgresql' }, { port: 8080, service: 'http-proxy' }
                                ];
                                const openPorts = [];
                                if (Math.random() > 0.5) openPorts.push({ port: 22, service: 'ssh' });
                                if (Math.random() > 0.2) { openPorts.push({ port: 80, service: 'http' }); openPorts.push({ port: 443, service: 'https' }); }
                                const extraCount = Math.floor(Math.random() * 4);
                                for (let i = 0; i < extraCount; i++) {
                                    const randomPort = commonPorts[Math.floor(Math.random() * commonPorts.length)];
                                    if (!openPorts.find(p => p.port === randomPort.port)) openPorts.push(randomPort);
                                }
                                openPorts.sort((a, b) => a.port - b.port);
                                openPorts.forEach(p => {
                                    terminalInstance.writeln(`${p.port}/tcp  \x1b[1;32mopen\x1b[0m  ${p.service}`);
                                });
                                const time = (Math.random() * 2 + 0.5).toFixed(2);
                                terminalInstance.writeln(`\nNmap done: 1 IP address (1 host up) scanned in ${time} seconds`);
                                prompt();
                            }, 1500);
                            return;
                        }
                        break;
                    case 'nc':
                    case 'netcat':
                        if (args.includes('-h') || args.includes('--help')) {
                            terminalInstance.writeln('OpenBSD netcat (Debian patch v1.218-4ubuntu1)');
                            terminalInstance.writeln('usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]');
                            terminalInstance.writeln('          [-m minttl] [-O length] [-P proxy_username] [-p source_port]');
                            terminalInstance.writeln('          [-q seconds] [-s source] [-T tos] [-V rtable] [-w timeout]');
                            terminalInstance.writeln('          [-X proxy_protocol] [-x proxy_address[:port]] [destination] [port]');
                            prompt();
                            return;
                        }
                        let isListening = args.includes('-l');
                        let portIndex = args.indexOf('-p');
                        let port = portIndex !== -1 ? args[portIndex + 1] : null;
                        let host = null;
                        if (!isListening) {
                            const cleanArgs = args.slice(1).filter(arg => !arg.startsWith('-'));
                            if (cleanArgs.length >= 2) {
                                host = cleanArgs[0];
                                port = cleanArgs[1];
                            }
                        }
                        if (isListening) {
                            if (!port) {
                                terminalInstance.writeln('nc: no port specified');
                                prompt();
                                return;
                            }
                            terminalInstance.writeln(`Listening on [0.0.0.0] (family 0, port ${port})`);
                            setTimeout(() => {
                                terminalInstance.writeln(`Connection from [192.168.1.55] ${Math.floor(Math.random() * 60000) + 1024} received!`);
                                terminalInstance.writeln('Interactive mode not fully supported in web sim. Press Ctrl+C to exit.');
                            }, 2000);
                        } else {
                            if (host && port) {
                                terminalInstance.writeln(`Connection to ${host} ${port} port [tcp/*] succeeded!`);
                                terminalInstance.writeln('Interactive mode not fully supported in web sim. Press Ctrl+C to exit.');
                            } else {
                                terminalInstance.writeln('usage: nc [options] [destination] [port]');
                                prompt();
                            }
                        }
                        break;
                    default:
                        terminalInstance.writeln(`bash: ${cmd}: command not found`);
                        prompt();
                }
            }
        }
        terminalInitialized = true;
    }

    // Override navigateTo to handle terminal initialization
    const originalNavigateTo = navigateTo;
    navigateTo = function (route) {
        originalNavigateTo(route);

        // Initialize terminal when navigating to it
        if (route === 'terminal/shell') {
            if (!terminalInitialized) {
                const modeModal = document.getElementById('terminal-mode-modal');
                modeModal.classList.add('active');

                document.getElementById('btn-mode-simulated').onclick = () => {
                    modeModal.classList.remove('active');
                    setTimeout(() => initializeTerminal('simulated'), 100);
                };

                document.getElementById('btn-mode-real').onclick = () => {
                    modeModal.classList.remove('active');
                    setTimeout(() => initializeTerminal('real'), 100);
                };
            }
        }
    };

    // --- Temp Email & SMS Services ---
    let currentEmailId = null;
    let currentSMSId = null;
    let emailPollInterval = null;
    let smsPollInterval = null;

    // Temp Email Logic
    document.getElementById('btn-generate-email').addEventListener('click', async () => {
        try {
            const response = await fetch('/api/temp/email/generate', { method: 'POST' });
            const data = await response.json();

            currentEmailId = data.id;
            document.getElementById('generated-email').value = data.email;
            document.getElementById('email-display').style.display = 'block';
            document.getElementById('email-inbox-container').style.display = 'block';

            // Check if using simulation
            const isSimulation = data.isSimulation;
            document.getElementById('btn-simulate-email').style.display = isSimulation ? 'block' : 'none';
            document.getElementById('email-simulation-warning').style.display = isSimulation ? 'block' : 'none';

            // Start polling for emails
            if (emailPollInterval) clearInterval(emailPollInterval);
            emailPollInterval = setInterval(() => fetchEmailInbox(), 15000);
            fetchEmailInbox();
        } catch (error) {
            alert('Error generating email: ' + error.message);
        }
    });

    document.getElementById('btn-copy-email').addEventListener('click', () => {
        const email = document.getElementById('generated-email').value;
        navigator.clipboard.writeText(email);
        const btn = document.getElementById('btn-copy-email');
        btn.textContent = 'COPIED!';
        setTimeout(() => btn.textContent = 'COPY', 2000);
    });

    document.getElementById('btn-simulate-email').addEventListener('click', async () => {
        if (!currentEmailId) return;

        const senders = ['support@example.com', 'noreply@service.com', 'admin@test.com'];
        const subjects = ['Welcome!', 'Verify your account', 'Important notification', 'Test email'];
        const bodies = [
            'Welcome to our service! Please verify your email address.',
            'Your verification code is: 123456',
            'This is an important notification about your account.',
            'This is a test email from the demo system.'
        ];

        const from = senders[Math.floor(Math.random() * senders.length)];
        const subject = subjects[Math.floor(Math.random() * subjects.length)];
        const body = bodies[Math.floor(Math.random() * bodies.length)];

        try {
            const response = await fetch(`/api/temp/email/${currentEmailId}/receive`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ from, subject, body })
            });
            const result = await response.json();
            console.log('Email simulated:', result);
            fetchEmailInbox();
        } catch (error) {
            console.error('Error simulating email:', error);
            alert('Error simulating email: ' + error.message);
        }
    });



    async function fetchEmailInbox() {
        if (!currentEmailId) return;

        console.log('Fetching inbox for:', currentEmailId);

        // Show loading
        document.getElementById('email-loading').style.display = 'block';

        try {
            const response = await fetch(`/api/temp/email/${currentEmailId}/inbox`);
            if (!response.ok) {
                if (response.status === 404) {
                    // Session expired
                    clearInterval(emailPollInterval);
                    alert('Email session expired. Please generate a new email.');
                    document.getElementById('email-display').style.display = 'none';
                    document.getElementById('email-inbox-container').style.display = 'none';
                    currentEmailId = null;
                    return;
                }
                if (response.status === 403 || response.status === 429) {
                    // Rate limited or forbidden
                    clearInterval(emailPollInterval);
                    console.warn(`Stopped polling due to status ${response.status}`);
                    const msg = response.status === 429 ? 'Rate limit reached.' : 'Access denied.';
                    alert(`${msg} Auto-refresh stopped. Please use the Reload button manually.`);
                    return;
                }
                throw new Error(`Server returned ${response.status}`);
            }
            const data = await response.json();

            console.log('Inbox data:', data);
            if (data.inbox) {
                displayEmailInbox(data.inbox);
            }
        } catch (error) {
            console.error('Error fetching inbox:', error);
        } finally {
            // Hide loading
            document.getElementById('email-loading').style.display = 'none';
        }
    }

    function displayEmailInbox(inbox) {
        const inboxEl = document.getElementById('email-inbox');
        document.getElementById('email-count').textContent = inbox.length;

        console.log('Displaying inbox with', inbox.length, 'emails');

        if (inbox.length === 0) {
            inboxEl.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--dim-color);">No emails yet...</div>';
            return;
        }

        inboxEl.innerHTML = inbox.map(msg => `
            <div class="inbox-item ${msg.read ? '' : 'unread'}" data-message-id="${msg.id}">
                <div class="inbox-item-header">
                    <span class="inbox-item-from">${msg.from}</span>
                    <span class="inbox-item-time">${new Date(msg.receivedAt).toLocaleTimeString()}</span>
                </div>
                <div class="inbox-item-subject">${msg.subject}</div>
                <div class="inbox-item-preview">${msg.body.substring(0, 100)}...</div>
            </div>
        `).join('');

        // Add click handlers
        inboxEl.querySelectorAll('.inbox-item').forEach(item => {
            item.addEventListener('click', () => {
                const msgId = item.dataset.messageId;
                const message = inbox.find(m => m.id === msgId);
                displayEmailMessage(message);
            });
        });
    }

    function displayEmailMessage(message) {
        const viewer = document.getElementById('email-viewer');
        viewer.innerHTML = `
            <div class="message-viewer-header">
                <div class="message-viewer-from"><strong>From:</strong> ${message.from}</div>
                <div class="message-viewer-subject">${message.subject}</div>
                <div class="message-viewer-time">${new Date(message.receivedAt).toLocaleString()}</div>
            </div>
            <div class="message-viewer-body">${message.body}</div>
            <div class="message-viewer-close">
                <button class="cyber-btn" id="btn-close-email-viewer">CLOSE</button>
            </div>
        `;
        viewer.style.display = 'block';

        document.getElementById('btn-close-email-viewer').addEventListener('click', () => {
            viewer.style.display = 'none';
        });

        // Mark as read
        if (!message.read) {
            fetch(`/api/temp/email/${currentEmailId}/message/${message.id}/read`, { method: 'PUT' });
            message.read = true;
        }
    }

    // Reload email inbox button
    document.getElementById('btn-reload-email').addEventListener('click', () => {
        fetchEmailInbox();
    });

    // Temp SMS Logic
    document.getElementById('btn-generate-sms').addEventListener('click', async () => {
        try {
            const response = await fetch('/api/temp/sms/generate', { method: 'POST' });
            const data = await response.json();

            currentSMSId = data.id;
            document.getElementById('generated-phone').value = data.phone;
            document.getElementById('sms-display').style.display = 'block';
            document.getElementById('sms-inbox-container').style.display = 'block';

            // Start polling for SMS
            if (smsPollInterval) clearInterval(smsPollInterval);
            smsPollInterval = setInterval(() => fetchSMSMessages(), 3000);
            fetchSMSMessages();
        } catch (error) {
            alert('Error generating phone: ' + error.message);
        }
    });

    document.getElementById('btn-copy-phone').addEventListener('click', () => {
        const phone = document.getElementById('generated-phone').value;
        navigator.clipboard.writeText(phone);
        const btn = document.getElementById('btn-copy-phone');
        btn.textContent = 'COPIED!';
        setTimeout(() => btn.textContent = 'COPY', 2000);
    });

    document.getElementById('btn-simulate-sms').addEventListener('click', async () => {
        if (!currentSMSId) return;

        const senders = ['+1 (555) 123-4567', '+1 (666) 987-6543', '+1 (777) 555-0000'];
        const messages = [
            'Your verification code is: 789012',
            'Welcome! Your account has been created.',
            'This is a test SMS message.',
            'Important: Please verify your phone number.'
        ];

        const from = senders[Math.floor(Math.random() * senders.length)];
        const body = messages[Math.floor(Math.random() * messages.length)];

        try {
            await fetch(`/api/temp/sms/${currentSMSId}/receive`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ from, body })
            });
            fetchSMSMessages();
        } catch (error) {
            alert('Error simulating SMS: ' + error.message);
        }
    });

    async function fetchSMSMessages() {
        if (!currentSMSId) return;

        // Show loading
        document.getElementById('sms-loading').style.display = 'block';

        try {
            const response = await fetch(`/api/temp/sms/${currentSMSId}/messages`);
            if (!response.ok) {
                if (response.status === 404) {
                    // Session expired
                    clearInterval(smsPollInterval);
                    alert('Phone session expired. Please generate a new number.');
                    document.getElementById('sms-display').style.display = 'none';
                    document.getElementById('sms-inbox-container').style.display = 'none';
                    currentSMSId = null;
                    return;
                }
                throw new Error(`Server returned ${response.status}`);
            }
            const data = await response.json();

            if (data.messages) {
                displaySMSInbox(data.messages);
            }
        } catch (error) {
            console.error('Error fetching messages:', error);
        } finally {
            // Hide loading
            document.getElementById('sms-loading').style.display = 'none';
        }
    }

    function displaySMSInbox(messages) {
        const inboxEl = document.getElementById('sms-inbox');
        document.getElementById('sms-count').textContent = messages.length;

        if (messages.length === 0) {
            inboxEl.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--dim-color);">No messages yet...</div>';
            return;
        }

        inboxEl.innerHTML = messages.map(msg => `
            <div class="inbox-item ${msg.read ? '' : 'unread'}" data-message-id="${msg.id}">
                <div class="inbox-item-header">
                    <span class="inbox-item-from">${msg.from}</span>
                    <span class="inbox-item-time">${new Date(msg.receivedAt).toLocaleTimeString()}</span>
                </div>
                <div class="inbox-item-preview">${msg.body}</div>
            </div>
        `).join('');

        // Add click handlers
        inboxEl.querySelectorAll('.inbox-item').forEach(item => {
            item.addEventListener('click', () => {
                const msgId = item.dataset.messageId;
                const message = messages.find(m => m.id === msgId);
                displaySMSMessage(message);
            });
        });
    }

    function displaySMSMessage(message) {
        const viewer = document.getElementById('sms-viewer');
        viewer.innerHTML = `
            <div class="message-viewer-header">
                <div class="message-viewer-from"><strong>From:</strong> ${message.from}</div>
                <div class="message-viewer-time">${new Date(message.receivedAt).toLocaleString()}</div>
            </div>
            <div class="message-viewer-body">${message.body}</div>
            <div class="message-viewer-close">
                <button class="cyber-btn" id="btn-close-sms-viewer">CLOSE</button>
            </div>
        `;
        viewer.style.display = 'block';

        document.getElementById('btn-close-sms-viewer').addEventListener('click', () => {
            viewer.style.display = 'none';
        });

        // Mark as read
        if (!message.read) {
            fetch(`/api/temp/sms/${currentSMSId}/message/${message.id}/read`, { method: 'PUT' });
            message.read = true;
        }
    }

    // Reload SMS inbox button
    document.getElementById('btn-reload-sms').addEventListener('click', () => {
        fetchSMSMessages();
    });


    // --- PCAP Analyzer ---
    const pcapFileInput = document.getElementById('pcap-file-input');
    const pcapStatus = document.getElementById('pcap-status');
    const pcapStats = document.getElementById('pcap-stats');

    // Live Capture Variables
    let livePackets = [];
    let isCapturing = false;

    // Load network interfaces
    async function loadNetworkInterfaces() {
        try {
            const response = await fetch('/api/pcap/interfaces');
            const data = await response.json();

            const select = document.getElementById('network-interface');
            select.innerHTML = '';

            if (data.warning) {
                select.innerHTML = `<option value="">${data.warning}</option>`;
                select.disabled = true;
                document.getElementById('btn-start-capture').disabled = true;
                document.getElementById('capture-filter').disabled = true;
                return;
            }

            if (data.interfaces && data.interfaces.length > 0) {
                let activeInterface = null;

                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.name;
                    option.textContent = `${iface.name} - ${iface.description}${iface.active ? ' (Active)' : ''}`;
                    select.appendChild(option);

                    if (iface.active && !activeInterface) {
                        activeInterface = iface.name;
                    }
                });

                // Auto-select active interface
                if (activeInterface) {
                    select.value = activeInterface;

                    // Auto-start capture if socket is ready
                    if (typeof socket !== 'undefined' && socket !== null && !isCapturing) {
                        setTimeout(() => {
                            document.getElementById('btn-start-capture').click();
                        }, 500);
                    }
                }
            } else {
                select.innerHTML = '<option value="">No interfaces found</option>';
            }
        } catch (error) {
            console.error('Failed to load interfaces:', error);
            document.getElementById('network-interface').innerHTML = '<option value="">Error loading interfaces</option>';
        }
    }

    // Load interfaces on page load
    loadNetworkInterfaces();

    // Start Live Capture
    document.getElementById('btn-start-capture').addEventListener('click', async () => {
        const iface = document.getElementById('network-interface').value;
        const filter = document.getElementById('capture-filter').value;

        if (!iface) {
            alert('Please select a network interface');
            return;
        }

        try {
            const response = await fetch('/api/pcap/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface, filter })
            });

            const data = await response.json();

            if (data.success) {
                isCapturing = true;
                livePackets = [];
                document.getElementById('btn-start-capture').disabled = true;
                document.getElementById('btn-stop-capture').disabled = false;
                document.getElementById('capture-indicator').classList.add('capturing');
                pcapStats.style.display = 'block';

                // Clear existing packet table
                document.getElementById('packet-table-body').innerHTML = '';
            } else {
                alert('Failed to start capture: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            alert('Error starting capture: ' + error.message);
        }
    });

    // Stop Live Capture
    document.getElementById('btn-stop-capture').addEventListener('click', async () => {
        try {
            const response = await fetch('/api/pcap/capture/stop', {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                isCapturing = false;
                document.getElementById('btn-start-capture').disabled = false;
                document.getElementById('btn-stop-capture').disabled = true;
                document.getElementById('capture-indicator').classList.remove('capturing');
            }
        } catch (error) {
            alert('Error stopping capture: ' + error.message);
        }
    });

    // WebSocket for live packets - only if socket is initialized
    if (typeof socket !== 'undefined' && socket !== null) {
        socket.on('live-packet', (packet) => {
            if (!isCapturing) return;

            livePackets.push(packet);

            // Add to table
            const tableBody = document.getElementById('packet-table-body');
            const row = tableBody.insertRow(0); // Insert at top
            row.className = 'packet-row live-packet-row';

            let info = '';
            if (packet.flags) info += packet.flags;

            row.innerHTML = `
                <td>${livePackets.length}</td>
                <td>${packet.timestamp ? packet.timestamp.toFixed(6) : 'N/A'}</td>
                <td>${packet.src || 'N/A'}</td>
                <td>${packet.srcPort || '-'}</td>
                <td>${packet.dst || 'N/A'}</td>
                <td>${packet.dstPort || '-'}</td>
                <td><span class="protocol-badge">${packet.protocol || 'Unknown'}</span></td>
                <td>${packet.length} bytes</td>
                <td class="packet-info">${info || '-'}</td>
            `;

            // Limit table to 100 rows
            while (tableBody.rows.length > 100) {
                tableBody.deleteRow(tableBody.rows.length - 1);
            }
        });

        // Update capture stats
        socket.on('capture-stats', (stats) => {
            document.getElementById('live-packet-count').textContent = stats.packets.toLocaleString();
            document.getElementById('live-byte-count').textContent = stats.bytes.toLocaleString();
        });

        // Handle capture stopped
        socket.on('capture-stopped', (stats) => {
            isCapturing = false;
            document.getElementById('btn-start-capture').disabled = false;
            document.getElementById('btn-stop-capture').disabled = true;
            document.getElementById('capture-indicator').classList.remove('capturing');
        });
    } else {
        console.warn('Socket.IO not initialized - live capture features will not work until terminal is opened');
    }


    document.getElementById('btn-analyze-pcap').addEventListener('click', async () => {
        const file = pcapFileInput.files[0];
        if (!file) {
            pcapStatus.innerHTML = '<p style="color: #ff3333;">ERROR: NO FILE SELECTED</p>';
            pcapStatus.style.display = 'block';
            return;
        }

        pcapStatus.innerHTML = '<p style="color: #00ff00;">ANALYZING PCAP FILE...</p>';
        pcapStatus.style.display = 'block';
        pcapStats.style.display = 'none';

        try {
            const formData = new FormData();
            formData.append('pcapFile', file);

            const response = await fetch('/api/pcap/upload', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (data.error) {
                pcapStatus.innerHTML = `<p style="color: #ff3333;">ERROR: ${data.error}</p>`;
                return;
            }

            pcapStatus.style.display = 'none';
            pcapStats.style.display = 'block';

            // Display statistics
            document.getElementById('stat-packets').textContent = data.stats.totalPackets.toLocaleString();
            document.getElementById('stat-bytes').textContent = data.stats.totalBytes.toLocaleString() + ' bytes';
            document.getElementById('stat-avg-size').textContent = data.stats.averagePacketSize + ' bytes';
            document.getElementById('stat-duration').textContent = data.stats.duration + 's';

            // Display protocol distribution
            const protocolChart = document.getElementById('protocol-chart');
            protocolChart.innerHTML = '';
            Object.entries(data.stats.protocols).forEach(([protocol, count]) => {
                const percentage = ((count / data.stats.totalPackets) * 100).toFixed(1);
                protocolChart.innerHTML += `
                    <div class="protocol-bar">
                        <div class="protocol-label">${protocol}: ${count} (${percentage}%)</div>
                        <div class="protocol-bar-fill" style="width: ${percentage}%"></div>
                    </div>
                `;
            });

            // Display top conversations
            const conversationsList = document.getElementById('conversations-list');
            conversationsList.innerHTML = '';
            data.stats.topConversations.forEach((conv, idx) => {
                conversationsList.innerHTML += `
                    <div class="conversation-item">
                        <span class="conv-rank">${idx + 1}.</span>
                        <span class="conv-name">${conv.conversation}</span>
                        <span class="conv-stats">${conv.packets} packets, ${conv.bytes.toLocaleString()} bytes</span>
                    </div>
                `;
            });

            // Display packet table
            const tableBody = document.getElementById('packet-table-body');
            tableBody.innerHTML = '';
            data.packets.forEach((packet, idx) => {
                const row = tableBody.insertRow();
                row.className = 'packet-row';
                row.dataset.packetId = idx;

                // Build info column
                let info = '';
                if (packet.flags) info += packet.flags;
                if (packet.payloadSize !== undefined) info += ` | Payload: ${packet.payloadSize} bytes`;

                row.innerHTML = `
                    <td>${idx + 1}</td>
                    <td>${packet.timestamp ? packet.timestamp.toFixed(6) : 'N/A'}</td>
                    <td>${packet.src || 'N/A'}</td>
                    <td>${packet.srcPort || '-'}</td>
                    <td>${packet.dst || 'N/A'}</td>
                    <td>${packet.dstPort || '-'}</td>
                    <td><span class="protocol-badge">${packet.protocol || 'Unknown'}</span></td>
                    <td>${packet.length} bytes</td>
                    <td class="packet-info">${info || '-'}</td>
                `;

                // Make row clickable to show hex dump
                row.style.cursor = 'pointer';
                row.addEventListener('click', () => {
                    // Check if details row already exists
                    const nextRow = row.nextElementSibling;
                    if (nextRow && nextRow.classList.contains('packet-details-row')) {
                        nextRow.remove();
                        return;
                    }

                    // Create details row
                    const detailsRow = tableBody.insertRow(row.rowIndex);
                    detailsRow.className = 'packet-details-row';
                    detailsRow.innerHTML = `
                        <td colspan="9">
                            <div class="packet-details">
                                <h4>Packet #${idx + 1} Details</h4>
                                <div class="packet-detail-grid">
                                    <div><strong>Timestamp:</strong> ${packet.timestamp}</div>
                                    <div><strong>Total Length:</strong> ${packet.length} bytes</div>
                                    <div><strong>Captured Length:</strong> ${packet.capturedLength} bytes</div>
                                    ${packet.ipHeaderLength ? `<div><strong>IP Header Length:</strong> ${packet.ipHeaderLength} bytes</div>` : ''}
                                    ${packet.payloadSize !== undefined ? `<div><strong>Payload Size:</strong> ${packet.payloadSize} bytes</div>` : ''}
                                </div>
                                <h4>Hex Dump (First 256 bytes)</h4>
                                <div class="hex-dump">${formatHexDump(packet.rawData ? packet.rawData.substring(0, 512) : '')}</div>
                            </div>
                        </td>
                    `;
                });
            });

        } catch (error) {
            console.error('PCAP Analysis Error:', error);
            pcapStatus.innerHTML = `<p style="color: #ff3333;">ERROR: ${error.message || 'Failed to analyze PCAP file'}</p>`;
            pcapStatus.style.display = 'block';
            pcapStats.style.display = 'none';
        }
    });

    // Helper function to format hex dump
    function formatHexDump(hexString) {
        if (!hexString) return 'No data available';

        let output = '';
        const bytesPerLine = 16;

        for (let i = 0; i < hexString.length; i += bytesPerLine * 2) {
            const offset = (i / 2).toString(16).padStart(4, '0');
            const hexPart = hexString.substring(i, i + bytesPerLine * 2);

            // Format hex bytes
            let hexBytes = '';
            for (let j = 0; j < hexPart.length; j += 2) {
                hexBytes += hexPart.substring(j, j + 2) + ' ';
                if (j === 14) hexBytes += ' '; // Extra space in middle
            }
            hexBytes = hexBytes.padEnd(bytesPerLine * 3 + 1, ' ');

            // Format ASCII representation
            let ascii = '';
            for (let j = 0; j < hexPart.length; j += 2) {
                const byte = parseInt(hexPart.substring(j, j + 2), 16);
                ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
            }

            output += `${offset}  ${hexBytes} |${ascii}|\n`;
        }

        return output;
    }

    document.getElementById('btn-pcap-clear').addEventListener('click', () => {
        pcapFileInput.value = '';
        pcapStatus.style.display = 'none';
        pcapStats.style.display = 'none';
    });



    // --- Live Packet Capture Logic ---
    const btnStartCapture = document.getElementById('btn-start-capture');
    const btnStopCapture = document.getElementById('btn-stop-capture');
    const interfaceSelect = document.getElementById('network-interface');
    const captureIndicator = document.getElementById('capture-indicator');
    const livePacketCount = document.getElementById('live-packet-count');
    const liveByteCount = document.getElementById('live-byte-count');
    const packetTableBody = document.getElementById('packet-table-body');
    let packetCounter = 0;

    async function fetchInterfaces() {
        try {
            const response = await fetch('/api/pcap/interfaces');
            const data = await response.json();

            interfaceSelect.innerHTML = '';
            if (data.interfaces && data.interfaces.length > 0) {
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.name;
                    option.textContent = `${iface.id}. ${iface.name} ${iface.description ? `(${iface.description})` : ''} ${iface.active ? '[ACTIVE]' : ''}`;
                    interfaceSelect.appendChild(option);
                });
            } else {
                const option = document.createElement('option');
                option.textContent = data.warning || 'No interfaces found';
                interfaceSelect.appendChild(option);
            }
        } catch (error) {
            console.error('Error fetching interfaces:', error);
            interfaceSelect.innerHTML = '<option>Error loading interfaces</option>';
        }
    }

    // Load interfaces when PCAP tool is opened
    document.querySelector('[data-route="network/pcap"]').addEventListener('click', () => {
        fetchInterfaces();
    });

    btnStartCapture.addEventListener('click', async () => {
        const iface = interfaceSelect.value;
        const filter = document.getElementById('capture-filter').value;

        try {
            const response = await fetch('/api/pcap/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface, filter })
            });
            const result = await response.json();

            if (result.success) {
                btnStartCapture.disabled = true;
                btnStopCapture.disabled = false;
                captureIndicator.classList.add('active');
                packetCounter = 0;
                packetTableBody.innerHTML = ''; // Clear table
                document.getElementById('pcap-stats').style.display = 'block';

                // Initialize socket if not already
                if (!socket) socket = io();

                // Listen for packets
                socket.on('live-packet', (packet) => {
                    packetCounter++;
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${packetCounter}</td>
                        <td>${new Date(packet.timestamp * 1000).toLocaleTimeString()}</td>
                        <td>${packet.src}</td>
                        <td>${packet.srcPort}</td>
                        <td>${packet.dst}</td>
                        <td>${packet.dstPort}</td>
                        <td><span class="protocol-badge ${packet.protocol.toLowerCase()}">${packet.protocol}</span></td>
                        <td>${packet.length}</td>
                        <td>${packet.flags ? `Flags: [${packet.flags}]` : ''}</td>
                    `;
                    packetTableBody.insertBefore(row, packetTableBody.firstChild);
                    if (packetTableBody.children.length > 100) {
                        packetTableBody.removeChild(packetTableBody.lastChild);
                    }
                });

                socket.on('capture-stats', (stats) => {
                    livePacketCount.textContent = stats.packets;
                    liveByteCount.textContent = formatBytes(stats.bytes);
                });
            } else {
                alert('Failed to start capture: ' + result.error);
            }
        } catch (error) {
            alert('Error starting capture: ' + error.message);
        }
    });

    btnStopCapture.addEventListener('click', async () => {
        try {
            const response = await fetch('/api/pcap/capture/stop', { method: 'POST' });
            const result = await response.json();

            if (result.success) {
                btnStartCapture.disabled = false;
                btnStopCapture.disabled = true;
                captureIndicator.classList.remove('active');
                if (socket) {
                    socket.off('live-packet');
                    socket.off('capture-stats');
                }
            }
        } catch (error) {
            console.error('Error stopping capture:', error);
        }
    });

    function formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    }

    // --- Username Onboarding ---
    const usernameModal = document.getElementById('username-modal');
    const usernameInput = document.getElementById('username-input');
    const btnSaveUsername = document.getElementById('btn-save-username');
    const userStatus = document.querySelector('.status-bar span:nth-child(2)');

    function updateUsernameDisplay() {
        const storedUsername = localStorage.getItem('cyber_username');
        if (storedUsername) {
            userStatus.textContent = `USER: ${storedUsername}`;
        }
    }

    // Check for username on load
    const storedUsername = localStorage.getItem('cyber_username');
    if (!storedUsername) {
        // Show modal
        usernameModal.classList.add('active');
        usernameInput.focus();
    } else {
        updateUsernameDisplay();
    }

    btnSaveUsername.addEventListener('click', () => {
        const username = usernameInput.value.trim().toUpperCase();
        if (username) {
            localStorage.setItem('cyber_username', username);
            updateUsernameDisplay();
            usernameModal.classList.remove('active');
        } else {
            usernameInput.style.borderColor = '#ff3333';
            setTimeout(() => {
                usernameInput.style.borderColor = 'var(--border-color)';
            }, 1000);
        }
    });

    // Allow Enter key to submit
    usernameInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            btnSaveUsername.click();
        }
    });

});
