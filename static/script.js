// Global state
let currentAnalysis = null;
let allResults = {};
let scanChecklist = {};
let logExpanded = true;

// Activity Log & Checklist Management
function addActivityLog(message, type = 'info') {
    const logContainer = document.getElementById('activityLogItems');
    const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    const logItem = document.createElement('div');
    logItem.className = `log-item log-${type}`;
    logItem.innerHTML = `
        <span class="log-timestamp">[${timestamp}]</span>
        <span class="log-message">${message}</span>
    `;
    
    // Prepend to top (reverse chronological with flex-direction: column-reverse)
    logContainer.insertBefore(logItem, logContainer.firstChild);
    
    // Limit log to 50 items
    const items = logContainer.querySelectorAll('.log-item');
    if (items.length > 50) {
        items[items.length - 1].remove();
    }
}

function toggleActivityLog() {
    const logContainer = document.getElementById('activityLogItems');
    const toggleBtn = document.getElementById('toggleLogBtn');
    
    logExpanded = !logExpanded;
    logContainer.setAttribute('data-expanded', logExpanded);
    toggleBtn.textContent = logExpanded ? '▼ Collapse' : '▶ Expand';
}

function initScanChecklist() {
    const categories = ['infrastructure', 'security', 'technology', 'content', 'performance'];
    scanChecklist = {};
    
    categories.forEach(cat => {
        scanChecklist[cat] = 'pending';
    });
    
    updateChecklistDisplay();
}

function updateChecklistDisplay() {
    const checklistContainer = document.getElementById('scanChecklistItems');
    checklistContainer.innerHTML = '';
    
    const categoryIcons = {
        'infrastructure': '🏗️',
        'security': '🔒',
        'technology': '⚙️',
        'content': '📄',
        'performance': '⚡'
    };
    
    const statusIcons = {
        'pending': '○',
        'running': '⏳',
        'done': '✓',
        'error': '✗'
    };
    
    Object.entries(scanChecklist).forEach(([cat, status]) => {
        const item = document.createElement('div');
        item.className = `checklist-item ${status}`;
        const icon = statusIcons[status];
        const catIcon = categoryIcons[cat] || '📍';
        const label = cat.charAt(0).toUpperCase() + cat.slice(1);
        item.innerHTML = `<span class="checklist-icon">${icon}</span><span>${catIcon} ${label}</span>`;
        checklistContainer.appendChild(item);
    });
}

function updateChecklistStatus(category, status) {
    if (scanChecklist.hasOwnProperty(category)) {
        scanChecklist[category] = status;
        updateChecklistDisplay();
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    initScanChecklist();
    addActivityLog('Scanner ready. Enter a domain to begin scanning.', 'info');
    
    document.getElementById('domainInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            // On Enter do nothing by default; user should click a specific scan button
            // runAllScans on Enter for convenience
            runAllScans();
        }
    });
});

// Scan category function
async function scanCategory(category) {
    const domainInput = document.getElementById('domainInput').value.trim();
    
    if (!domainInput) {
        showStatus('analysisStatus', 'Please enter a domain', 'error');
        return;
    }

    // Validate category
    const validCategories = ['infrastructure', 'security', 'technology', 'content', 'performance'];
    if (!validCategories.includes(category)) {
        showStatus('analysisStatus', 'Invalid category. Use: infrastructure, security, technology, content, performance', 'error');
        return;
    }

    showStatus('analysisStatus', `Running ${category.toUpperCase()} scan...`, 'loading');
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'flex';
    
    currentAnalysis = { domain: domainInput, category: category, scanId: Date.now() };
    allResults = {};

    try {
        const response = await fetch(`/api/category/${category}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ domain: domainInput })
        });

        if (!response.ok) {
            const errorData = await response.json();
            showStatus('analysisStatus', `Error: ${errorData.error || 'Unknown error'}`, 'error');
            return;
        }

        const data = await response.json();
        allResults = data;
        
        // Display results
        displayCategoryResults(category, data);
        showStatus('analysisStatus', `✓ ${category.toUpperCase()} scan completed successfully!`, 'success');
        
    } catch (error) {
        showStatus('analysisStatus', `Error: ${error.message}`, 'error');
        console.error('Scan error:', error);
    }
}

// Run a single specific scan (uses new backend route)
async function scanSpecific(category, scanName) {
    const domainInput = document.getElementById('domainInput').value.trim();
    if (!domainInput) {
        showStatus('analysisStatus', 'Please enter a domain', 'error');
        addActivityLog(`Scan attempted but no domain entered.`, 'error');
        return;
    }

    addActivityLog(`Starting scan: ${scanName} (${category})`, 'info');
    showStatus('analysisStatus', `Running ${scanName} (${category})...`, 'loading');
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'flex';
    currentAnalysis = { domain: domainInput, category: category, scanId: Date.now() };

    // Show progress modal
    showProgressModal();
    updateModalProgress(`Scanning ${scanName}...`, 0);

    try {
        const response = await fetch(`/api/scan/${category}/${scanName}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domainInput })
        });

        if (!response.ok) {
            const errorData = await response.json();
            showStatus('analysisStatus', `Error: ${errorData.error || 'Unknown error'}`, 'error');
            addActivityLog(`❌ ${scanName} failed: ${errorData.error || 'Unknown error'}`, 'error');
            hideProgressModal();
            return;
        }

        const data = await response.json();
        allResults = data;
        displaySingleResult(data);
        updateModalProgress(`${scanName} completed!`, 100);
        hideProgressModal();
        addActivityLog(`✓ ${scanName} scan completed successfully`, 'success');
        showStatus('analysisStatus', `✓ ${scanName.toUpperCase()} completed successfully!`, 'success');
    } catch (error) {
        showStatus('analysisStatus', `Error: ${error.message}`, 'error');
        addActivityLog(`❌ ${scanName} error: ${error.message}`, 'error');
        hideProgressModal();
        console.error('Scan error:', error);
    }
}

// Append category results without clearing previous results
function appendCategoryResults(category, data) {
    const container = document.getElementById('scanResultsContainer');

    // Create header for this scan
    const header = document.createElement('div');
    header.className = 'category-header';
    header.innerHTML = `
        <h2>${getCategoryIcon(category)} ${category.toUpperCase()} Scan Results</h2>
        <p class="domain-info">Domain: <strong>${data.domain}</strong></p>
    `;
    container.appendChild(header);

    if (category === 'infrastructure') {
        displayInfrastructure(data, container);
    } else if (category === 'security') {
        displaySecurity(data, container);
    } else if (category === 'technology') {
        displayTechnology(data, container);
    } else if (category === 'content') {
        displayContent(data, container);
    } else if (category === 'performance') {
        displayPerformance(data, container);
    }
}

// Run all category scans sequentially and display combined results
async function runAllScans() {
    const domainInput = document.getElementById('domainInput').value.trim();
    if (!domainInput) {
        showStatus('analysisStatus', 'Please enter a domain', 'error');
        addActivityLog(`Run All Scans attempted but no domain entered.`, 'error');
        return;
    }

    const categories = ['infrastructure', 'security', 'technology', 'content', 'performance'];
    showStatus('analysisStatus', 'Running all scans (this may take a while)...', 'loading');
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'flex';
    const container = document.getElementById('scanResultsContainer');
    container.innerHTML = '';

    // Show progress modal
    showProgressModal();
    initProgressList();
    initScanChecklist();
    
    addActivityLog(`🚀 Starting full reconnaissance on: ${domainInput}`, 'info');

    const combined = { domain: domainInput, category: 'Combined', results: {} };

    for (const cat of categories) {
        try {
            updateModalProgress(`Scanning ${cat}...`, (categories.indexOf(cat) / categories.length) * 100);
            // update UI: mark as running
            updateChecklistStatus(cat, 'running');
            updateCategoryStatus(cat, 'running');
            addActivityLog(`→ Starting ${cat} reconnaissance...`, 'info');

            const response = await fetch(`/api/category/${cat}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: domainInput })
            });

            if (!response.ok) {
                const err = await response.json();
                updateChecklistStatus(cat, 'error');
                updateCategoryStatus(cat, 'error', err.error || 'Failed');
                addActivityLog(`✗ ${cat} scan failed: ${err.error || 'Unknown error'}`, 'error');
                showStatus('analysisStatus', `Error during ${cat}: ${err.error || 'Unknown'}`, 'error');
                hideProgressModal();
                return;
            }

            const data = await response.json();
            combined.results[cat] = data;
            appendCategoryResults(cat, data);
            updateChecklistStatus(cat, 'done');
            updateCategoryStatus(cat, 'done');
            addActivityLog(`✓ ${cat} reconnaissance completed`, 'success');
            // small pause to allow UI updates
            await new Promise(r => setTimeout(r, 250));
        } catch (e) {
            updateChecklistStatus(cat, 'error');
            updateCategoryStatus(cat, 'error', e.message);
            addActivityLog(`✗ ${cat} error: ${e.message}`, 'error');
            showStatus('analysisStatus', `Error during ${cat}: ${e.message}`, 'error');
            hideProgressModal();
            return;
        }
    }

    // Add combined export button
    const exportBtn = document.createElement('button');
    exportBtn.className = 'btn btn-success';
    exportBtn.textContent = '📥 Export to Excel';
    exportBtn.onclick = () => exportResults(combined);
    container.appendChild(exportBtn);

    allResults = combined;
    updateModalProgress('All scans completed!', 100);
    hideProgressModal();
    addActivityLog(`🎉 All reconnaissance scans completed successfully!`, 'success');
    showStatus('analysisStatus', '✓ All scans completed', 'success');
}

// Progress UI helpers
function initProgressList() {
    const categories = ['infrastructure', 'security', 'technology', 'content', 'performance'];
    // Track progress state
    window.progressState = {
        total: categories.length * 5, // 5 scans per category
        completed: 0,
        running: 0,
        pending: categories.length * 5,
        failed: 0
    };
    updateProgressDisplay();
}

function updateCategoryStatus(category, status, message) {
    if (!window.progressState) return;
    
    // Update counts based on status
    if (status === 'running') {
        window.progressState.running += 1;
        window.progressState.pending -= 1;
    } else if (status === 'done') {
        window.progressState.completed += 1;
        window.progressState.running -= 1;
    } else if (status === 'error') {
        window.progressState.failed += 1;
        window.progressState.running -= 1;
    }
    
    updateProgressDisplay();
}

function updateProgressDisplay() {
    if (!window.progressState) return;
    
    const state = window.progressState;
    const total = state.total || 1;
    const percentage = Math.round((state.completed / total) * 100);
    
    // Update progress bar
    const progressBar = document.getElementById('progressBar');
    if (progressBar) {
        progressBar.style.width = percentage + '%';
    }
    
    // Update percentage text
    const percentageEl = document.getElementById('progressPercentage');
    if (percentageEl) {
        percentageEl.textContent = percentage + '%';
    }
    
    // Update stat counters
    const completedCount = document.getElementById('completedCount');
    if (completedCount) completedCount.textContent = state.completed;
    
    const runningCount = document.getElementById('runningCount');
    if (runningCount) runningCount.textContent = state.running;
    
    const pendingCount = document.getElementById('pendingCount');
    if (pendingCount) pendingCount.textContent = state.pending;
    
    const failedCount = document.getElementById('failedCount');
    if (failedCount) failedCount.textContent = state.failed;
}

// initialize progress panel on load
document.addEventListener('DOMContentLoaded', function() {
    initProgressList();
});

// Display a single-scan result
function displaySingleResult(data) {
    const container = document.getElementById('scanResultsContainer');
    container.innerHTML = '';

    const header = document.createElement('div');
    header.className = 'category-header';
    header.innerHTML = `
        <h2>🔎 ${data.category || 'Scan'} Result</h2>
        <p class="domain-info">Domain: <strong>${data.domain}</strong></p>
    `;
    container.appendChild(header);

    // find keys other than domain/category
    Object.keys(data).filter(k => k !== 'domain' && k !== 'category').forEach(key => {
        const card = createCard(key);
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data[key]); else card.innerHTML += formatObject(data[key]);
        container.appendChild(card);
    });

    const exportBtn = document.createElement('button');
    exportBtn.className = 'btn btn-success';
    exportBtn.textContent = '📥 Export to Excel';
    exportBtn.onclick = () => exportResults(data);
    container.appendChild(exportBtn);
}

// Display results based on category
function displayCategoryResults(category, data) {
    const container = document.getElementById('scanResultsContainer');
    
    // Clear previous results
    container.innerHTML = '';
    
    // Create header for this scan
    const header = document.createElement('div');
    header.className = 'category-header';
    header.innerHTML = `
        <h2>${getCategoryIcon(category)} ${category.toUpperCase()} Scan Results</h2>
        <p class="domain-info">Domain: <strong>${data.domain}</strong></p>
    `;
    container.appendChild(header);

    // Display category-specific results
    if (category === 'infrastructure') {
        displayInfrastructure(data, container);
    } else if (category === 'security') {
        displaySecurity(data, container);
    } else if (category === 'technology') {
        displayTechnology(data, container);
    } else if (category === 'content') {
        displayContent(data, container);
    } else if (category === 'performance') {
        displayPerformance(data, container);
    }

    // Export button
    const exportBtn = document.createElement('button');
    exportBtn.className = 'btn btn-success';
    exportBtn.textContent = '📥 Export to Excel';
    exportBtn.onclick = () => exportResults(data);
    container.appendChild(exportBtn);
}

function getCategoryIcon(category) {
    const icons = {
        'infrastructure': '🏗️',
        'security': '🔒',
        'technology': '⚙️',
        'content': '📄',
        'performance': '⚡'
    };
    return icons[category] || '📊';
}

// Display Infrastructure Results
function displayInfrastructure(data, container) {
    // DNS Records
    if (data['DNS Records']) {
        const card = createCard('📡 DNS Records');
        const dnsHtml = Object.entries(data['DNS Records']).map(([key, values]) => {
            if (Array.isArray(values) && values.length > 0) {
                return `<strong>${key}:</strong> ${values.join(', ')}`;
            }
            return '';
        }).filter(x => x).join('<br>');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += (dnsHtml || 'No DNS records found'); else card.innerHTML += (dnsHtml || 'No DNS records found');
        container.appendChild(card);
    }

    // WHOIS Info
    if (data['WHOIS'] && !data['WHOIS'].error) {
        const card = createCard('📋 WHOIS Information');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['WHOIS']); else card.innerHTML += formatObject(data['WHOIS']);
        container.appendChild(card);
    }

    // Port Scan
    if (data['Port Scan'] && data['Port Scan']['open_ports']) {
        const card = createCard('🔓 Open Ports');
        const ports = data['Port Scan']['open_ports'];
        const body = card.querySelector('.result-body');
        if (ports.length > 0) {
            if (body) body.innerHTML += ports.map(p => `<strong>${p.port}:</strong> ${p.service}`).join('<br>'); else card.innerHTML += ports.map(p => `<strong>${p.port}:</strong> ${p.service}`).join('<br>');
        } else {
            if (body) body.innerHTML += 'No open ports found'; else card.innerHTML += 'No open ports found';
        }
        container.appendChild(card);
    }

    // Geolocation
    if (data['Geolocation'] && Object.keys(data['Geolocation']).length > 0) {
        const card = createCard('📍 Geolocation');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['Geolocation']); else card.innerHTML += formatObject(data['Geolocation']);
        container.appendChild(card);
    }

    // CDN Detection
    if (data['CDN Detection']) {
        const card = createCard('☁️ CDN Detection');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['CDN Detection']); else card.innerHTML += formatObject(data['CDN Detection']);
        container.appendChild(card);
    }
}

// Display Security Results
function displaySecurity(data, container) {
    // Security Headers
    if (data['Security Headers']) {
        const card = createCard('🔒 Security Headers');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['Security Headers']); else card.innerHTML += formatObject(data['Security Headers']);
        container.appendChild(card);
    }

    // SSL Certificate
    if (data['SSL Certificate']) {
        const card = createCard('🔐 SSL Certificate');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['SSL Certificate']); else card.innerHTML += formatObject(data['SSL Certificate']);
        container.appendChild(card);
    }

    // WAF Detection
    if (data['WAF Detection'] && data['WAF Detection'].length > 0) {
        const card = createCard('🛡️ WAF Detection');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += data['WAF Detection'].join('<br>'); else card.innerHTML += data['WAF Detection'].join('<br>');
        container.appendChild(card);
    } else if (data['WAF Detection'] && data['WAF Detection'].length === 0) {
        const card = createCard('🛡️ WAF Detection');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += 'No WAF detected'; else card.innerHTML += 'No WAF detected';
        container.appendChild(card);
    }

    // Email Security
    if (data['Email Security']) {
        const card = createCard('📧 Email Security (SPF/DKIM/DMARC)');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['Email Security']); else card.innerHTML += formatObject(data['Email Security']);
        container.appendChild(card);
    }

    // HTTP Security
    if (data['HTTP Security']) {
        const card = createCard('🔐 HTTP Security Configuration');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['HTTP Security']); else card.innerHTML += formatObject(data['HTTP Security']);
        container.appendChild(card);
    }
}

// Display Technology Results
function displayTechnology(data, container) {
    // Detected Technologies
    if (data['Detected Technologies']) {
        const card = createCard('⚙️ Detected Technologies');
        const body = card.querySelector('.result-body');
        if (Array.isArray(data['Detected Technologies']) && data['Detected Technologies'].length > 0) {
            if (body) body.innerHTML += data['Detected Technologies'].join('<br>'); else card.innerHTML += data['Detected Technologies'].join('<br>');
        } else {
            if (body) body.innerHTML += 'No technologies detected'; else card.innerHTML += 'No technologies detected';
        }
        container.appendChild(card);
    }

    // Framework Versions
    if (data['Framework Versions']) {
        const card = createCard('📦 Framework Versions');
        const body = card.querySelector('.result-body');
        if (Object.keys(data['Framework Versions']).length > 0) {
            if (body) body.innerHTML += formatObject(data['Framework Versions']); else card.innerHTML += formatObject(data['Framework Versions']);
        } else {
            if (body) body.innerHTML += 'No framework versions detected'; else card.innerHTML += 'No framework versions detected';
        }
        container.appendChild(card);
    }

    // Metadata
    if (data['Metadata']) {
        const card = createCard('📝 Page Metadata');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['Metadata']); else card.innerHTML += formatObject(data['Metadata']);
        container.appendChild(card);
    }

    // HTTP Methods
    if (data['HTTP Methods']) {
        const card = createCard('🌐 HTTP Methods');
        const methods = Object.entries(data['HTTP Methods'])
            .map(([method, info]) => `<strong>${method}:</strong> ${info.status}`)
            .join('<br>');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += methods; else card.innerHTML += methods;
        container.appendChild(card);
    }
}

// Display Content Results
function displayContent(data, container) {
    // Links
    if (data['Links']) {
        const card = createCard('🔗 Links');
        const linksInfo = `Internal: ${data['Links']['internal_count']}<br>External: ${data['Links']['external_count']}`;
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += linksInfo; else card.innerHTML += linksInfo;
        if (data['Links']['internal_links'].length > 0) {
            if (body) body.innerHTML += '<br><strong>Sample Internal Links:</strong><br>' + data['Links']['internal_links'].slice(0, 5).join('<br>'); else card.innerHTML += '<br><strong>Sample Internal Links:</strong><br>' + data['Links']['internal_links'].slice(0, 5).join('<br>');
        }
        container.appendChild(card);
    }

    // Common Paths
    if (data['Common Paths']) {
        const card = createCard('📁 Common Paths Found');
        const body = card.querySelector('.result-body');
        if (Array.isArray(data['Common Paths']) && data['Common Paths'].length > 0) {
            const html = data['Common Paths'].map(p => `<strong>${p.path}:</strong> ${p.status}`).join('<br>');
            if (body) body.innerHTML += html; else card.innerHTML += html;
        } else {
            if (body) body.innerHTML += 'No common paths found'; else card.innerHTML += 'No common paths found';
        }
        container.appendChild(card);
    }

    // Robots.txt
    if (data['Robots.txt']) {
        const card = createCard('🤖 Robots.txt');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['Robots.txt']) || 'No robots.txt found'; else card.innerHTML += formatObject(data['Robots.txt']) || 'No robots.txt found';
        container.appendChild(card);
    }

    // Sitemap
    if (data['Sitemap.xml']) {
        const card = createCard('🗺️ Sitemap.xml');
        const sitemapInfo = `URLs found: ${data['Sitemap.xml']['count']}`;
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += sitemapInfo; else card.innerHTML += sitemapInfo;
        if (data['Sitemap.xml']['urls'].length > 0) {
            if (body) body.innerHTML += '<br><strong>Sample URLs:</strong><br>' + data['Sitemap.xml']['urls'].slice(0, 5).join('<br>'); else card.innerHTML += '<br><strong>Sample URLs:</strong><br>' + data['Sitemap.xml']['urls'].slice(0, 5).join('<br>');
        }
        container.appendChild(card);
    }

    // Secrets & Comments
    if (data['Secrets & Comments']) {
        const card = createCard('🔓 Secrets & Comments');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['Secrets & Comments']); else card.innerHTML += formatObject(data['Secrets & Comments']);
        container.appendChild(card);
    }
}

// Display Performance Results
function displayPerformance(data, container) {
    // Response Timing
    if (data['Response Timing']) {
        const card = createCard('⏱️ Response Timing');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['Response Timing']); else card.innerHTML += formatObject(data['Response Timing']);
        container.appendChild(card);
    }

    // Cookies
    if (data['Cookies']) {
        const card = createCard('🍪 Cookies');
        const body = card.querySelector('.result-body');
        if (Object.keys(data['Cookies']).length > 0) {
            if (body) body.innerHTML += formatObject(data['Cookies']); else card.innerHTML += formatObject(data['Cookies']);
        } else {
            if (body) body.innerHTML += 'No cookies found'; else card.innerHTML += 'No cookies found';
        }
        container.appendChild(card);
    }

    // DNS Propagation
    if (data['DNS Propagation']) {
        const card = createCard('🌍 DNS Propagation');
        const body = card.querySelector('.result-body');
        if (body) body.innerHTML += formatObject(data['DNS Propagation']); else card.innerHTML += formatObject(data['DNS Propagation']);
        container.appendChild(card);
    }
}

// Helper function to create a card
function createCard(title) {
    const card = document.createElement('div');
    card.className = 'card result-card';
    card.innerHTML = `
        <h3>
            <span class="card-title-text">${title}</span>
            <span class="result-actions" aria-hidden="false">
                <button class="btn small-btn" type="button" onclick="copyCardContent(this)" aria-label="Copy result">Copy</button>
                <button class="btn small-btn" type="button" onclick="toggleCollapse(this)" aria-label="Collapse result">Toggle</button>
            </span>
        </h3>
        <div class="result-body"></div>
    `;
    return card;
}

// Helper function to format objects
function formatObject(obj) {
    function escapeHtml(s) {
        return String(s).replace(/[&<>]/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]; });
    }

    if (obj === null || obj === undefined) return '<span>(empty)</span>';

    if (typeof obj !== 'object') return `<span>${escapeHtml(obj)}</span>`;

    // For objects and arrays show pretty-printed JSON inside a <pre>
    try {
        const pretty = JSON.stringify(obj, null, 2);
        return `<pre class="result-pre" tabindex="0">${escapeHtml(pretty)}</pre>`;
    } catch (e) {
        return `<span>${escapeHtml(String(obj))}</span>`;
    }
}

// Copy the closest card content to clipboard
function copyCardContent(btn) {
    try {
        const card = btn.closest('.card');
        if (!card) return;
        const body = card.querySelector('.result-body') || card;
        const text = body.innerText || card.innerText;
        
        // Check if clipboard API is available
        if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
                showCopySuccess(btn);
            }).catch((err) => {
                console.error('Clipboard copy failed:', err);
                fallbackCopy(text, btn);
            });
        } else {
            // Fallback for older browsers or secure context issues
            fallbackCopy(text, btn);
        }
    } catch (e) { 
        console.error('Copy error:', e);
        fallbackCopy('', btn);
    }
}

// Fallback copy function using textarea
function fallbackCopy(text, btn) {
    try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        const successful = document.execCommand('copy');
        document.body.removeChild(textarea);
        
        if (successful) {
            showCopySuccess(btn);
        } else {
            showCopyError(btn);
        }
    } catch (err) {
        console.error('Fallback copy failed:', err);
        showCopyError(btn);
    }
}

// Show copy success feedback
function showCopySuccess(btn) {
    const originalText = btn.textContent;
    btn.textContent = '✓ Copied!';
    btn.style.background = 'rgba(0,230,138,.25)';
    btn.style.color = 'var(--primary)';
    setTimeout(() => {
        btn.textContent = originalText;
        btn.style.background = '';
        btn.style.color = '';
    }, 1500);
}

// Show copy error feedback
function showCopyError(btn) {
    btn.textContent = '✗ Failed';
    setTimeout(() => btn.textContent = 'Copy', 1500);
}

// Toggle collapse on a card
function toggleCollapse(btn) {
    const card = btn.closest('.card');
    if (!card) return;
    card.classList.toggle('collapsed');
    const body = card.querySelector('.result-body');
    if (body) {
        if (card.classList.contains('collapsed')) {
            body.style.display = 'none';
            btn.textContent = 'Expand';
        } else {
            body.style.display = '';
            btn.textContent = 'Toggle';
        }
    }
}

// Export results to Excel file
function exportResults(data) {
    exportResults._retries = (exportResults._retries || 0) + 1;
    const maxRetries = 3;
    
    try {
        // Check if XLSX library is loaded
        if (typeof XLSX === 'undefined') {
            if (exportResults._retries < maxRetries) {
                console.warn(`XLSX library not loaded (attempt ${exportResults._retries}/${maxRetries}), retrying...`);
                showStatus('analysisStatus', `Loading Excel library (${exportResults._retries}/${maxRetries})...`, 'loading');
                setTimeout(() => exportResults(data), 1000);
                return;
            } else {
                console.warn('XLSX library failed to load, using fallback export');
                exportResults._retries = 0;
                exportPlainText(data);
                return;
            }
        }
        
        exportResults._retries = 0;
        
        const workbook = XLSX.utils.book_new();
        const flatData = flattenDataForExcel(data);
        
        // Create Summary Sheet
        const summarySheet = [
            ['SCAN SUMMARY'],
            ['Domain', data.domain || 'N/A'],
            ['Category', data.category || 'Combined'],
            ['Timestamp', new Date().toLocaleString()],
            [],
            ['QUICK STATS'],
        ];
        
        // Add stats if available
        if (data.results) {
            Object.entries(data.results).forEach(([cat, result]) => {
                summarySheet.push([cat, result.domain || 'N/A']);
            });
        }
        
        // Create detailed data sheets
        const sheets = {};
        sheets['Summary'] = XLSX.utils.aoa_to_sheet(summarySheet);
        
        // Add category sheets
        if (data.results) {
            Object.entries(data.results).forEach(([category, categoryData]) => {
                const categorySheet = createCategorySheet(category, categoryData);
                const sheetName = category.substring(0, 30); // Excel sheet name limit
                sheets[sheetName] = XLSX.utils.aoa_to_sheet(categorySheet);
            });
        } else {
            // Single result mode
            const detailedSheet = createDetailedDataSheet(data);
            sheets['Details'] = XLSX.utils.aoa_to_sheet(detailedSheet);
        }
        
        // Add all sheets to workbook
        Object.entries(sheets).forEach(([sheetName, sheet]) => {
            XLSX.utils.book_append_sheet(workbook, sheet, sheetName);
        });
        
        // Generate filename
        const domain = (data.domain || 'scan').replace(/[^a-z0-9.-]/gi, '_');
        const timestamp = new Date().toISOString().slice(0, 10);
        const filename = `BehindTheProxy_${domain}_${timestamp}.xlsx`;
        
        // Write file
        XLSX.writeFile(workbook, filename);
        
        showStatus('analysisStatus', `✓ Results exported to ${filename}`, 'success');
    } catch (error) {
        console.error('Export error:', error);
        // If XLSX is not available, offer plain text export as fallback
        if (error.message.includes('XLSX') || typeof XLSX === 'undefined') {
            exportPlainText(data);
        } else {
            showStatus('analysisStatus', `Error exporting results: ${error.message}`, 'error');
        }
    }
}

// Fallback plain text export
function exportPlainText(data) {
    try {
        const exportData = JSON.stringify(data, null, 2);
        const element = document.createElement('a');
        element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(exportData));
        const domain = (data && data.domain) ? data.domain.replace(/[^a-z0-9.-]/gi, '_') : 'scan';
        const name = `BehindTheProxy_${domain}_${new Date().toISOString().slice(0, 10)}.txt`;
        element.setAttribute('download', name);
        element.style.display = 'none';
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);
        showStatus('analysisStatus', `✓ Results exported as plain text to ${name}`, 'success');
    } catch (err) {
        console.error('Plain text export error:', err);
        showStatus('analysisStatus', 'Export failed. Please try again.', 'error');
    }
}

// Helper function to create category data for Excel
function createCategorySheet(category, data) {
    const sheet = [
        [`${category.toUpperCase()} RESULTS`],
        [],
        ['Domain', data.domain || 'N/A'],
        [],
    ];
    
    // Add all data from the category
    Object.entries(data).forEach(([key, value]) => {
        if (key !== 'domain' && key !== 'category') {
            sheet.push([]);
            sheet.push([`${key.toUpperCase()}`]);
            
            if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                Object.entries(value).forEach(([k, v]) => {
                    sheet.push([k, formatValueForExcel(v)]);
                });
            } else if (Array.isArray(value)) {
                value.forEach((item, idx) => {
                    sheet.push([`${key} [${idx + 1}]`, formatValueForExcel(item)]);
                });
            } else {
                sheet.push([key, formatValueForExcel(value)]);
            }
        }
    });
    
    return sheet;
}

// Helper function to create detailed data sheet
function createDetailedDataSheet(data) {
    const sheet = [
        ['Scan Results'],
        [],
        ['Domain', data.domain || 'N/A'],
        ['Timestamp', new Date().toLocaleString()],
        [],
        ['RESULTS'],
        [],
    ];
    
    Object.entries(data).forEach(([key, value]) => {
        if (key !== 'domain' && key !== 'category') {
            sheet.push([key]);
            
            if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                Object.entries(value).forEach(([k, v]) => {
                    sheet.push(['  ' + k, formatValueForExcel(v)]);
                });
            } else if (Array.isArray(value)) {
                value.forEach((item) => {
                    sheet.push(['  Item', formatValueForExcel(item)]);
                });
            } else {
                sheet.push(['  Value', formatValueForExcel(value)]);
            }
            sheet.push([]);
        }
    });
    
    return sheet;
}

// Format value for Excel (convert objects to readable strings)
function formatValueForExcel(value) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'object') {
        if (Array.isArray(value)) {
            return value.map(v => formatValueForExcel(v)).join('; ');
        }
        return JSON.stringify(value, null, 2);
    }
    return String(value);
}

// Flatten data structure for Excel
function flattenDataForExcel(data) {
    const flat = [];
    
    function flatten(obj, prefix = '') {
        Object.entries(obj).forEach(([key, value]) => {
            const fullKey = prefix ? `${prefix}.${key}` : key;
            
            if (value === null || value === undefined) {
                flat.push({ key: fullKey, value: '' });
            } else if (typeof value === 'object' && !Array.isArray(value)) {
                flatten(value, fullKey);
            } else if (Array.isArray(value)) {
                flat.push({ key: fullKey, value: value.join('; ') });
            } else {
                flat.push({ key: fullKey, value: String(value) });
            }
        });
    }
    
    flatten(data);
    return flat;
}

// Progress Modal Functions
let progressStartTime = null;
let progressTimer = null;

function showProgressModal() {
    const modal = document.getElementById('progressModal');
    if (modal) {
        modal.style.display = 'flex';
        progressStartTime = Date.now();
        updateProgressTimer();
        progressTimer = setInterval(updateProgressTimer, 1000);
    }
}

function hideProgressModal() {
    const modal = document.getElementById('progressModal');
    if (modal) {
        modal.style.display = 'none';
    }
    if (progressTimer) {
        clearInterval(progressTimer);
        progressTimer = null;
    }
}

function updateProgressTimer() {
    if (!progressStartTime) return;
    const elapsed = Math.floor((Date.now() - progressStartTime) / 1000);
    const timeEl = document.getElementById('scanTimeElapsed');
    if (timeEl) {
        timeEl.textContent = elapsed + 's';
    }
}

function updateModalProgress(message, percentage = null) {
    const msgEl = document.getElementById('progressMessage');
    if (msgEl) msgEl.textContent = message;
    
    if (percentage !== null) {
        const bar = document.getElementById('modalProgressBar');
        if (bar) {
            bar.style.width = percentage + '%';
        }
    }
}

// Show status message
function showStatus(elementId, message, type) {
    const element = document.getElementById(elementId);
    if (!element) return;
    element.textContent = message;
    element.className = `status-message show ${type}`;
    // Ensure screen readers get updates
    element.setAttribute('role', 'status');
    element.setAttribute('aria-live', 'polite');
}

// Reset analysis
function resetAnalysis() {
    document.getElementById('domainInput').value = '';
    document.getElementById('analysisStatus').textContent = '';
    document.getElementById('emptyState').style.display = 'flex';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('scanResultsContainer').innerHTML = '';
    allResults = {};
    currentAnalysis = null;
    hideProgressModal();
    initScanChecklist();
    addActivityLog('Analysis cleared. Ready for new scan.', 'info');
}
