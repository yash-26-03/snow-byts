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
        'hash/md5': 'md5',
        'hash/sha1': 'sha1',
        'hash/sha256': 'sha256',
        'hash/sha512': 'sha512',
        'virustotal/file-scan': 'vt-file',
        'virustotal/url-scan': 'vt-url',
        'virustotal/hash-lookup': 'vt-hash',
        'virustotal/ip-domain': 'vt-ip',
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

    // --- Terminal Integration ---
    let terminalInstance = null;
    let socket = null;
    let terminalInitialized = false;

    function initializeTerminal() {
        if (terminalInitialized) return;

        // Initialize socket connection
        socket = io();

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
            }
        });

        // Add fit addon
        const fitAddon = new FitAddon.FitAddon();
        terminalInstance.loadAddon(fitAddon);

        // Open terminal in container
        const container = document.getElementById('terminal-container');
        terminalInstance.open(container);
        fitAddon.fit();

        // Request terminal creation from server
        socket.emit('create-terminal');

        // Handle terminal output from server
        socket.on('terminal-output', (data) => {
            terminalInstance.write(data);
        });

        // Handle terminal input
        terminalInstance.onData((data) => {
            socket.emit('terminal-input', data);
        });

        // Handle window resize
        window.addEventListener('resize', () => {
            fitAddon.fit();
            socket.emit('terminal-resize', {
                cols: terminalInstance.cols,
                rows: terminalInstance.rows
            });
        });

        // Welcome message
        terminalInstance.writeln('\x1b[1;32m╔═══════════════════════════════════════════════════════════╗\x1b[0m');
        terminalInstance.writeln('\x1b[1;32m║         CYBER SECURITY TOOLS - WEB TERMINAL              ║\x1b[0m');
        terminalInstance.writeln('\x1b[1;32m╚═══════════════════════════════════════════════════════════╝\x1b[0m');
        terminalInstance.writeln('');
        terminalInstance.writeln('\x1b[1;33m⚠️  WARNING: Commands execute on the host system!\x1b[0m');
        terminalInstance.writeln('');

        terminalInitialized = true;
    }

    // Override navigateTo to handle terminal initialization
    const originalNavigateTo = navigateTo;
    navigateTo = function (route) {
        originalNavigateTo(route);

        // Initialize terminal when navigating to it
        if (route === 'terminal/shell') {
            setTimeout(() => {
                initializeTerminal();
            }, 100);
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
});
