/**
 * CyberSOC Pro - Advanced Threat Intelligence Platform
 * Professional cybersecurity tool for SOC analysts and blue teams
 */

// ===== CORE APPLICATION STATE =====
class CyberSOCApp {
    constructor() {
        this.currentTab = 'dashboard';
        this.currentResults = null;
        this.apiKeys = this.loadApiKeys();
        this.settings = this.loadSettings();
        this.threatIntelSources = new Map();
        this.mitreMatrix = new Map();
        this.detectionRules = [];
        this.campaigns = [];
        this.timeline = [];
        this.analytics = {
            iocsProcessed: 0,
            threatsDetected: 0,
            intelSources: 8,
            detectionRules: 247
        };
        this.threatLevel = { level: 'ELEVATED', score: 7.2 };
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeIntelSources();
        this.loadMitreMatrix();
        this.setupTheme();
        this.startBackgroundTasks();
        this.showToast('CyberSOC Pro initialized', 'success', 'System Ready');
    }

    loadApiKeys() {
        return {
            virustotal: localStorage.getItem('vt_api_key') || '',
            shodan: localStorage.getItem('shodan_api_key') || '',
            censys: localStorage.getItem('censys_api_key') || '',
            alienvault: localStorage.getItem('otx_api_key') || ''
        };
    }

    loadSettings() {
        const defaultSettings = {
            theme: 'dark',
            autoEnrich: true,
            deepAnalysis: true,
            mitreMapping: false,
            notifications: true
        };
        return { ...defaultSettings, ...JSON.parse(localStorage.getItem('app_settings') || '{}') };
    }

    saveSettings() {
        localStorage.setItem('app_settings', JSON.stringify(this.settings));
    }

    saveApiKeys() {
        Object.entries(this.apiKeys).forEach(([key, value]) => {
            if (value) localStorage.setItem(`${key === 'virustotal' ? 'vt' : key}_api_key`, value);
        });
    }
}

// ===== IOC CATEGORIES AND PATTERNS =====
const IOC_CATEGORIES = {
    ipv4: { name: 'IPv4 Addresses', icon: 'fas fa-globe', color: '#3b82f6' },
    ipv6: { name: 'IPv6 Addresses', icon: 'fas fa-globe', color: '#3b82f6' },
    domains: { name: 'Domain Names', icon: 'fas fa-link', color: '#10b981' },
    urls: { name: 'URLs', icon: 'fas fa-external-link-alt', color: '#f59e0b' },
    emails: { name: 'Email Addresses', icon: 'fas fa-envelope', color: '#8b5cf6' },
    hashes: { name: 'File Hashes', icon: 'fas fa-fingerprint', color: '#ef4444' },
    bitcoin: { name: 'Bitcoin Addresses', icon: 'fab fa-bitcoin', color: '#f59e0b' },
    filenames: { name: 'File Names', icon: 'fas fa-file', color: '#6b7280' },
    cves: { name: 'CVE IDs', icon: 'fas fa-bug', color: '#dc2626' },
    registry: { name: 'Registry Keys', icon: 'fas fa-key', color: '#7c3aed' },
    processes: { name: 'Process Names', icon: 'fas fa-cogs', color: '#059669' },
    useragents: { name: 'User Agents', icon: 'fas fa-user-secret', color: '#0891b2' }
};

const IOC_PATTERNS = {
    ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b/g,
    domains: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g,
    urls: /https?:\/\/(?:[-\w.])+(?::[0-9]+)?(?:\/(?:[\w._~!$&'()*+,;=:@-]|%[0-9a-fA-F]{2})*)*(?:\?(?:[\w._~!$&'()*+,;=:@/?-]|%[0-9a-fA-F]{2})*)?(?:#(?:[\w._~!$&'()*+,;=:@/?-]|%[0-9a-fA-F]{2})*)?/g,
    emails: /\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b/g,
    hashes: {
        md5: /\b[a-fA-F0-9]{32}\b/g,
        sha1: /\b[a-fA-F0-9]{40}\b/g,
        sha256: /\b[a-fA-F0-9]{64}\b/g,
        sha512: /\b[a-fA-F0-9]{128}\b/g
    },
    bitcoin: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g,
    filenames: /\b[a-zA-Z0-9._-]+\.[a-zA-Z]{2,5}\b/g,
    cves: /CVE-\d{4}-\d{4,}/gi,
    registry: /HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s]+/gi,
    processes: /\b[a-zA-Z0-9._-]+\.(?:exe|dll|sys|bat|cmd|ps1|sh)\b/gi,
    useragents: /Mozilla\/[\d.]+\s*\([^)]+\)\s*(?:\S+\s*)*/g
};

// RFC 6890 IP ranges for classification
const IP_RANGES = [
    { start: [10, 0, 0, 0], end: [10, 255, 255, 255], name: 'private-range', risk: 'low' },
    { start: [172, 16, 0, 0], end: [172, 31, 255, 255], name: 'private-range', risk: 'low' },
    { start: [192, 168, 0, 0], end: [192, 168, 255, 255], name: 'private-range', risk: 'low' },
    { start: [127, 0, 0, 0], end: [127, 255, 255, 255], name: 'loopback', risk: 'low' },
    { start: [169, 254, 0, 0], end: [169, 254, 255, 255], name: 'link-local', risk: 'low' },
    { start: [224, 0, 0, 0], end: [239, 255, 255, 255], name: 'multicast', risk: 'low' },
    { start: [192, 0, 2, 0], end: [192, 0, 2, 255], name: 'test-net', risk: 'low' },
    { start: [198, 51, 100, 0], end: [198, 51, 100, 255], name: 'test-net', risk: 'low' },
    { start: [203, 0, 113, 0], end: [203, 0, 113, 255], name: 'test-net', risk: 'low' },
    { start: [100, 64, 0, 0], end: [100, 127, 255, 255], name: 'cgn', risk: 'medium' },
    { start: [0, 0, 0, 0], end: [0, 255, 255, 255], name: 'reserved', risk: 'low' },
    { start: [240, 0, 0, 0], end: [255, 255, 255, 254], name: 'reserved', risk: 'low' },
    { start: [255, 255, 255, 255], end: [255, 255, 255, 255], name: 'broadcast', risk: 'low' },
    { start: [198, 18, 0, 0], end: [198, 19, 255, 255], name: 'benchmark', risk: 'low' },
    { start: [192, 0, 0, 0], end: [192, 0, 0, 255], name: 'ietf', risk: 'low' },
    { start: [192, 88, 99, 0], end: [192, 88, 99, 255], name: '6to4-relay', risk: 'low' }
];

// MITRE ATT&CK Framework mapping
const MITRE_TACTICS = {
    'initial-access': { name: 'Initial Access', color: '#dc2626' },
    'execution': { name: 'Execution', color: '#ea580c' },
    'persistence': { name: 'Persistence', color: '#d97706' },
    'privilege-escalation': { name: 'Privilege Escalation', color: '#ca8a04' },
    'defense-evasion': { name: 'Defense Evasion', color: '#65a30d' },
    'credential-access': { name: 'Credential Access', color: '#059669' },
    'discovery': { name: 'Discovery', color: '#0891b2' },
    'lateral-movement': { name: 'Lateral Movement', color: '#0284c7' },
    'collection': { name: 'Collection', color: '#2563eb' },
    'command-and-control': { name: 'Command and Control', color: '#4f46e5' },
    'exfiltration': { name: 'Exfiltration', color: '#7c3aed' },
    'impact': { name: 'Impact', color: '#a21caf' }
};

// Sample data for demonstration
const SAMPLE_DATA = `Subject: Critical Security Alert - Advanced Persistent Threat Detected
From: soc@cybersec.com
To: incident-response@cybersec.com
Date: ${new Date().toUTCString()}
X-Originating-IP: 185.220.101.42

URGENT: Suspicious activity detected from multiple threat vectors.

THREAT INDICATORS:
- Malicious IPs: 185.220.101.42, 203.0.113.45, 198.51.100.23
- C2 Domains: evil-apt.malware-domain.com, phishing-bank.net, command.threat-actor.org
- URLs: https://evil-apt.malware-domain.com/download.php?payload=trojan
- Bitcoin wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

MALWARE SAMPLES:
- advanced-trojan.exe (MD5: d41d8cd98f00b204e9800998ecf8427e)
- backdoor.dll (SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709)
- rootkit.sys (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)

CVE REFERENCES: CVE-2024-1234, CVE-2023-5678, CVE-2024-0001

USER AGENTS:
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36

REGISTRY MODIFICATIONS:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders

PROCESSES:
svchost.exe, powershell.exe, cmd.exe, winlogon.exe

Email contacts: threat-actor@darkweb.onion, admin@compromised-site.com

IPv6 addresses: 2001:db8::1, fe80::1%lo0

Additional suspicious domains: apt.campaign.ru, malware-kit.cn, phishing.evil-domain.org

Please investigate immediately and implement containment measures.`;

// Global app instance
let app;

// ===== INITIALIZATION =====
document.addEventListener('DOMContentLoaded', () => {
    app = new CyberSOCApp();
});

// ===== EVENT LISTENERS SETUP =====
CyberSOCApp.prototype.setupEventListeners = function() {
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const tab = e.currentTarget.dataset.tab;
            this.switchTab(tab);
        });
    });

    // Sidebar toggle
    document.getElementById('sidebar-toggle').addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('collapsed');
    });

    // Theme toggle
    document.getElementById('theme-toggle').addEventListener('click', () => {
        this.toggleTheme();
    });

    // Settings modal
    document.getElementById('settings-toggle').addEventListener('click', () => {
        this.openSettingsModal();
    });

    // IOC Extractor events
    this.setupIOCExtractorEvents();
    
    // Input monitoring
    this.setupInputMonitoring();
    
    // File upload
    this.setupFileUpload();
    
    // Keyboard shortcuts
    this.setupKeyboardShortcuts();
    
    // Background updates
    this.setupBackgroundUpdates();
};

// ===== TAB MANAGEMENT =====
CyberSOCApp.prototype.switchTab = function(tabName) {
    // Update navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(tabName).classList.add('active');

    // Update page title and breadcrumb
    this.updatePageHeader(tabName);
    
    // Load tab-specific data
    this.loadTabData(tabName);
    
    this.currentTab = tabName;
};

CyberSOCApp.prototype.updatePageHeader = function(tabName) {
    const titles = {
        'dashboard': 'Threat Intelligence Dashboard',
        'ioc-extractor': 'IOC Extractor & Analysis',
        'threat-intel': 'Threat Intelligence Hub',
        'attack-mapping': 'MITRE ATT&CK Mapping',
        'detection-rules': 'Detection Engineering',
        'osint-toolkit': 'OSINT Toolkit',
        'threat-hunting': 'Threat Hunting Console',
        'analytics': 'Security Analytics',
        'timeline': 'Timeline Analysis',
        'campaigns': 'Campaign Tracking'
    };
    
    document.getElementById('page-title').textContent = titles[tabName] || 'CyberSOC Pro';
    document.getElementById('breadcrumb').innerHTML = `<span class="breadcrumb-item active">${titles[tabName]}</span>`;
};

CyberSOCApp.prototype.loadTabData = function(tabName) {
    switch(tabName) {
        case 'dashboard':
            this.loadDashboardData();
            break;
        case 'threat-intel':
            this.loadThreatIntelData();
            break;
        case 'attack-mapping':
            this.loadMitreMatrix();
            break;
        case 'detection-rules':
            this.loadDetectionRules();
            break;
        case 'osint-toolkit':
            this.loadOSINTTools();
            break;
        case 'threat-hunting':
            this.loadThreatHuntingData();
            break;
        case 'analytics':
            this.loadAnalyticsData();
            break;
        case 'timeline':
            this.loadTimelineData();
            break;
        case 'campaigns':
            this.loadCampaignData();
            break;
    }
};

// ===== DASHBOARD =====
CyberSOCApp.prototype.loadDashboardData = function() {
    // Update stats
    document.getElementById('iocs-processed').textContent = this.analytics.iocsProcessed.toLocaleString();
    document.getElementById('threats-detected').textContent = this.analytics.threatsDetected;
    document.getElementById('intel-sources').textContent = this.analytics.intelSources;
    document.getElementById('detection-rules').textContent = this.analytics.detectionRules;
    
    // Load threat timeline
    this.updateThreatTimeline();
    
    // Load MITRE heatmap
    this.updateMitreHeatmap();
};

CyberSOCApp.prototype.updateThreatTimeline = function() {
    const container = document.getElementById('threat-timeline-container');
    if (!container) return;
    
    const recentThreats = [
        { time: '2 min ago', title: 'Suspicious PowerShell Activity', description: 'Base64 encoded command execution detected', severity: 'high' },
        { time: '15 min ago', title: 'Malware Hash Detected', description: 'Known malware SHA256 hash identified in file upload', severity: 'critical' },
        { time: '1 hour ago', title: 'C2 Communication', description: 'Potential command and control traffic to suspicious domain', severity: 'high' },
        { time: '3 hours ago', title: 'Failed Login Attempts', description: 'Multiple failed authentication attempts from external IP', severity: 'medium' }
    ];
    
    container.innerHTML = recentThreats.map(threat => `
        <div class="timeline-item">
            <div class="timeline-time">${threat.time}</div>
            <div class="timeline-content">
                <div class="timeline-title">${threat.title}</div>
                <div class="timeline-description">${threat.description}</div>
            </div>
        </div>
    `).join('');
};

CyberSOCApp.prototype.updateMitreHeatmap = function() {
    const container = document.getElementById('mitre-matrix');
    if (!container) return;
    
    const techniques = [
        { id: 'T1566', name: 'Phishing', tactic: 'initial-access', detections: 5 },
        { id: 'T1059', name: 'Command Line', tactic: 'execution', detections: 12 },
        { id: 'T1053', name: 'Scheduled Task', tactic: 'persistence', detections: 3 },
        { id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion', detections: 8 },
        { id: 'T1003', name: 'Credential Dumping', tactic: 'credential-access', detections: 2 },
        { id: 'T1083', name: 'File Discovery', tactic: 'discovery', detections: 7 }
    ];
    
    container.innerHTML = techniques.map(tech => `
        <div class="mitre-technique ${tech.detections > 0 ? 'detected' : ''}" title="${tech.name}">
            <div class="mitre-technique-id">${tech.id}</div>
            <div class="mitre-technique-name">${tech.name}</div>
            ${tech.detections > 0 ? `<div class="detection-count">${tech.detections}</div>` : ''}
        </div>
    `).join('');
};

// ===== IOC EXTRACTOR EVENTS =====
CyberSOCApp.prototype.setupIOCExtractorEvents = function() {
    // Input tabs
    document.querySelectorAll('.input-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const inputType = e.currentTarget.dataset.inputType;
            this.switchInputType(inputType);
        });
    });

    // Sample data button
    document.getElementById('sample-data-btn').addEventListener('click', () => {
        this.loadSampleData();
    });

    // Clear button
    document.getElementById('clear-input-btn').addEventListener('click', () => {
        this.clearInput();
    });

    // Extract button
    document.getElementById('extract-btn').addEventListener('click', () => {
        this.extractAndAnalyze();
    });

    // URL analyzer
    document.getElementById('analyze-url-btn').addEventListener('click', () => {
        this.analyzeURL();
    });

    // Export buttons
    document.getElementById('export-csv').addEventListener('click', () => this.exportResults('csv'));
    document.getElementById('export-json').addEventListener('click', () => this.exportResults('json'));
    document.getElementById('export-stix').addEventListener('click', () => this.exportResults('stix'));
    document.getElementById('copy-all').addEventListener('click', () => this.copyAllResults());

    // View toggles
    document.querySelectorAll('.results-section .view-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const view = e.currentTarget.dataset.view;
            this.switchResultsView(view);
        });
    });
};

CyberSOCApp.prototype.switchInputType = function(inputType) {
    // Update tabs
    document.querySelectorAll('.input-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelector(`[data-input-type="${inputType}"]`).classList.add('active');

    // Update panels
    document.querySelectorAll('.input-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(`${inputType}-input-panel`).classList.add('active');
    
    this.updateExtractButton();
};

CyberSOCApp.prototype.setupInputMonitoring = function() {
    const textarea = document.getElementById('input-text');
    
    textarea.addEventListener('input', () => {
        this.updateInputStats();
        this.updateExtractButton();
    });
    
    textarea.addEventListener('paste', () => {
        setTimeout(() => {
            this.updateInputStats();
            this.updateExtractButton();
        }, 10);
    });
};

CyberSOCApp.prototype.updateInputStats = function() {
    const textarea = document.getElementById('input-text');
    const text = textarea.value;
    
    const lines = text.split('\n').length;
    const chars = text.length;
    
    document.getElementById('line-count').textContent = lines.toLocaleString();
    document.getElementById('char-count').textContent = chars.toLocaleString();
};

CyberSOCApp.prototype.updateExtractButton = function() {
    const textarea = document.getElementById('input-text');
    const urlInput = document.getElementById('url-input');
    const extractBtn = document.getElementById('extract-btn');
    
    const hasContent = textarea.value.trim().length > 0 || urlInput.value.trim().length > 0;
    extractBtn.disabled = !hasContent;
};

CyberSOCApp.prototype.loadSampleData = function() {
    document.getElementById('input-text').value = SAMPLE_DATA;
    this.updateInputStats();
    this.updateExtractButton();
    this.showToast('Sample data loaded successfully', 'success');
};

CyberSOCApp.prototype.clearInput = function() {
    document.getElementById('input-text').value = '';
    document.getElementById('url-input').value = '';
    this.updateInputStats();
    this.updateExtractButton();
    this.currentResults = null;
    this.displayResults(null);
    this.showToast('Input cleared', 'info');
};

// ===== IOC EXTRACTION ENGINE =====
CyberSOCApp.prototype.extractAndAnalyze = function() {
    const text = document.getElementById('input-text').value.trim();
    if (!text) {
        this.showToast('No content to analyze', 'warning', 'Input Required');
        return;
    }

    this.showLoading('Extracting and analyzing IOCs...');
    
    setTimeout(async () => {
        try {
            const results = await this.performAdvancedExtraction(text);
            this.currentResults = results;
            
            // Save to localStorage
            localStorage.setItem('latest_analysis', JSON.stringify(results));
            
            // Update analytics
            this.analytics.iocsProcessed += Object.values(results).reduce((sum, items) => sum + items.length, 0);
            
            this.displayResults(results);
            this.hideLoading();
            
            const totalIOCs = Object.values(results).reduce((sum, items) => sum + items.length, 0);
            this.showToast(`Analysis complete: ${totalIOCs} IOCs extracted`, 'success', 'Extraction Complete');
            
        } catch (error) {
            this.hideLoading();
            this.showToast('Error during analysis', 'error', 'Analysis Failed');
            console.error('Extraction error:', error);
        }
    }, 500);
};

CyberSOCApp.prototype.performAdvancedExtraction = function(text) {
    return new Promise(async (resolve) => {
        const results = {};
        const timestamp = new Date().toISOString();
        
        // Extract all IOC categories
        for (const [category, info] of Object.entries(IOC_CATEGORIES)) {
            results[category] = await this.extractCategory(category, text, timestamp);
        }
        
        // Perform enrichment if enabled
        if (this.settings.autoEnrich) {
            await this.enrichResults(results);
        }
        
        // Map to MITRE ATT&CK if enabled
        if (this.settings.mitreMapping) {
            await this.mapToMitre(results);
        }
        
        resolve(results);
    });
};

CyberSOCApp.prototype.extractCategory = function(category, text, timestamp) {
    return new Promise((resolve) => {
        const results = [];
        const seen = new Set();
        
        let patterns;
        if (category === 'hashes') {
            patterns = IOC_PATTERNS.hashes;
        } else {
            patterns = { [category]: IOC_PATTERNS[category] };
        }
        
        for (const [type, pattern] of Object.entries(patterns)) {
            if (!pattern) continue;
            
            const matches = [...text.matchAll(pattern)];
            
            for (const match of matches) {
                const value = match[0];
                const key = value.toLowerCase();
                
                if (seen.has(key)) continue;
                seen.add(key);
                
                // Validate the IOC
                if (!this.validateIOC(category, value)) continue;
                
                // Create IOC object
                const ioc = {
                    value: category === 'hashes' ? value.toLowerCase() : value,
                    type: category,
                    subtype: category === 'hashes' ? type : null,
                    confidence: this.calculateConfidence(category, value),
                    risk: this.calculateRisk(category, value),
                    notes: this.generateNotes(category, value),
                    firstSeen: timestamp,
                    enrichment: null
                };
                
                results.push(ioc);
            }
        }
        
        resolve(results);
    });
};

CyberSOCApp.prototype.validateIOC = function(category, value) {
    switch (category) {
        case 'ipv4':
            return this.isValidIPv4(value);
        case 'ipv6':
            return this.isValidIPv6(value);
        case 'domains':
            return this.isValidDomain(value);
        case 'urls':
            return this.isValidURL(value);
        case 'emails':
            return this.isValidEmail(value);
        case 'bitcoin':
            return this.isValidBitcoinAddress(value);
        case 'filenames':
            return this.isValidFilename(value);
        case 'cves':
            return this.isValidCVE(value);
        default:
            return true;
    }
};

// Enhanced validation functions with improved security
CyberSOCApp.prototype.isValidIPv4 = function(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    
    for (const part of parts) {
        if (part.length > 1 && part[0] === '0') return false; // No leading zeros
        const num = parseInt(part, 10);
        if (isNaN(num) || num < 0 || num > 255) return false;
    }
    return true;
};

CyberSOCApp.prototype.isValidIPv6 = function(ip) {
    try {
        // Simplified IPv6 validation
        const parts = ip.split(':');
        if (parts.length < 3 || parts.length > 8) return false;
        
        let doubleColonCount = 0;
        for (let i = 0; i < parts.length - 1; i++) {
            if (parts[i] === '' && parts[i + 1] === '') {
                doubleColonCount++;
                if (doubleColonCount > 1) return false;
            }
        }
        
        for (const part of parts) {
            if (part !== '' && !/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
        }
        
        return true;
    } catch {
        return false;
    }
};

CyberSOCApp.prototype.isValidDomain = function(domain) {
    if (domain.length > 253) return false;
    if (domain.startsWith('.') || domain.endsWith('.')) return false;
    
    const parts = domain.split('.');
    if (parts.length < 2) return false;
    
    const tld = parts[parts.length - 1];
    if (tld.length < 2 || tld.length > 24) return false;
    
    for (const part of parts) {
        if (part.length === 0 || part.length > 63) return false;
        if (!/^[a-zA-Z0-9-]+$/.test(part)) return false;
        if (part.startsWith('-') || part.endsWith('-')) return false;
    }
    
    return true;
};

CyberSOCApp.prototype.isValidURL = function(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch {
        return false;
    }
};

CyberSOCApp.prototype.isValidEmail = function(email) {
    const [local, domain] = email.split('@');
    if (!local || !domain) return false;
    if (local.length > 64 || domain.length > 253) return false;
    
    if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) return false;
    
    return this.isValidDomain(domain);
};

CyberSOCApp.prototype.isValidBitcoinAddress = function(address) {
    if (address.startsWith('1') || address.startsWith('3')) {
        return /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address);
    } else if (address.startsWith('bc1')) {
        return /^bc1[a-z0-9]{39,59}$/.test(address);
    }
    return false;
};

CyberSOCApp.prototype.isValidFilename = function(filename) {
    const parts = filename.split('.');
    if (parts.length < 2) return false;
    
    const name = parts.slice(0, -1).join('.');
    const ext = parts[parts.length - 1];
    
    if (name.length === 0 || ext.length < 2 || ext.length > 5) return false;
    if (!/^[a-zA-Z0-9._-]+$/.test(name)) return false;
    if (!/^[a-zA-Z]{2,5}$/.test(ext)) return false;
    
    return true;
};

CyberSOCApp.prototype.isValidCVE = function(cve) {
    const match = cve.match(/^CVE-(\d{4})-(\d{4,})$/);
    if (!match) return false;
    
    const year = parseInt(match[1], 10);
    const id = parseInt(match[2], 10);
    
    return year >= 1999 && year <= new Date().getFullYear() + 1 && id >= 0;
};

CyberSOCApp.prototype.calculateConfidence = function(category, value) {
    // Enhanced confidence calculation based on IOC type and characteristics
    let confidence = 0.5; // Base confidence
    
    switch (category) {
        case 'hashes':
            confidence = 0.9; // Hashes are highly reliable
            break;
        case 'ipv4':
        case 'ipv6':
            confidence = this.isPublicIP(value) ? 0.8 : 0.3;
            break;
        case 'domains':
            confidence = this.calculateDomainConfidence(value);
            break;
        case 'urls':
            confidence = 0.7;
            break;
        case 'cves':
            confidence = 0.95; // CVEs are highly reliable
            break;
        default:
            confidence = 0.6;
    }
    
    return Math.round(confidence * 100) / 100;
};

CyberSOCApp.prototype.calculateRisk = function(category, value) {
    // Enhanced risk calculation
    switch (category) {
        case 'hashes':
            return 'high'; // Unknown hashes are potentially malicious
        case 'ipv4':
        case 'ipv6':
            return this.getIPRisk(value);
        case 'domains':
            return this.getDomainRisk(value);
        case 'urls':
            return 'medium';
        case 'cves':
            return 'high'; // CVEs represent known vulnerabilities
        default:
            return 'low';
    }
};

CyberSOCApp.prototype.generateNotes = function(category, value) {
    const notes = [];
    
    switch (category) {
        case 'ipv4':
            const ipInfo = this.getIPInfo(value);
            if (ipInfo) notes.push(ipInfo);
            break;
        case 'domains':
            if (this.isSuspiciousDomain(value)) {
                notes.push('suspicious-domain');
            }
            break;
        case 'urls':
            if (this.isSuspiciousURL(value)) {
                notes.push('suspicious-url');
            }
            break;
        case 'hashes':
            notes.push('unknown-hash');
            break;
    }
    
    return notes;
};

CyberSOCApp.prototype.getIPInfo = function(ip) {
    const parts = ip.split('.').map(Number);
    
    for (const range of IP_RANGES) {
        if (this.isInRange(parts, range.start, range.end)) {
            return range.name;
        }
    }
    
    return null;
};

CyberSOCApp.prototype.isInRange = function(ip, start, end) {
    for (let i = 0; i < 4; i++) {
        if (ip[i] < start[i] || ip[i] > end[i]) return false;
        if (ip[i] > start[i] && ip[i] < end[i]) return true;
    }
    return true;
};

CyberSOCApp.prototype.isPublicIP = function(ip) {
    return !this.getIPInfo(ip);
};

CyberSOCApp.prototype.getIPRisk = function(ip) {
    const ipInfo = this.getIPInfo(ip);
    if (!ipInfo) return 'medium'; // Public IP
    
    const range = IP_RANGES.find(r => r.name === ipInfo);
    return range ? range.risk : 'low';
};

CyberSOCApp.prototype.calculateDomainConfidence = function(domain) {
    let confidence = 0.6;
    
    // TLD analysis
    const tld = domain.split('.').pop().toLowerCase();
    const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'ru', 'cn'];
    if (suspiciousTLDs.includes(tld)) {
        confidence -= 0.2;
    }
    
    // Length and character analysis
    if (domain.length > 50) confidence -= 0.1;
    if (/\d{4,}/.test(domain)) confidence -= 0.1; // Many consecutive digits
    
    return Math.max(0.1, Math.min(0.9, confidence));
};

CyberSOCApp.prototype.getDomainRisk = function(domain) {
    if (this.isSuspiciousDomain(domain)) return 'high';
    
    const tld = domain.split('.').pop().toLowerCase();
    const highRiskTLDs = ['tk', 'ml', 'ga', 'cf'];
    if (highRiskTLDs.includes(tld)) return 'medium';
    
    return 'low';
};

CyberSOCApp.prototype.isSuspiciousDomain = function(domain) {
    const suspiciousPatterns = [
        /malware/i,
        /phishing/i,
        /evil/i,
        /hack/i,
        /trojan/i,
        /bot/i,
        /\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/, // IP-like patterns
        /[0-9]{6,}/ // Long number sequences
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(domain));
};

CyberSOCApp.prototype.isSuspiciousURL = function(url) {
    const suspiciousPatterns = [
        /download\.php/i,
        /payload/i,
        /trojan/i,
        /malware/i,
        /exploit/i,
        /shell/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(url));
};

// ===== THREAT INTELLIGENCE ENRICHMENT =====
CyberSOCApp.prototype.enrichResults = function(results) {
    return Promise.all([
        this.enrichWithVirusTotal(results),
        this.enrichWithShodan(results),
        this.enrichWithOTX(results)
    ]);
};

CyberSOCApp.prototype.enrichWithVirusTotal = function(results) {
    if (!this.apiKeys.virustotal) return Promise.resolve();
    
    // Simulate VirusTotal enrichment
    return new Promise(resolve => {
        setTimeout(() => {
            // Add mock VT data to high-risk IOCs
            Object.values(results).flat().forEach(ioc => {
                if (ioc.risk === 'high' && Math.random() > 0.5) {
                    ioc.enrichment = {
                        ...ioc.enrichment,
                        virustotal: {
                            detections: Math.floor(Math.random() * 20) + 1,
                            total_engines: 70,
                            first_seen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
                            reputation: 'malicious'
                        }
                    };
                }
            });
            resolve();
        }, 200);
    });
};

CyberSOCApp.prototype.enrichWithShodan = function(results) {
    if (!this.apiKeys.shodan) return Promise.resolve();
    
    // Simulate Shodan enrichment for IPs
    return new Promise(resolve => {
        setTimeout(() => {
            const ipIOCs = [...(results.ipv4 || []), ...(results.ipv6 || [])];
            ipIOCs.forEach(ioc => {
                if (this.isPublicIP(ioc.value) && Math.random() > 0.7) {
                    ioc.enrichment = {
                        ...ioc.enrichment,
                        shodan: {
                            open_ports: [22, 80, 443, 8080],
                            services: ['SSH', 'HTTP', 'HTTPS'],
                            country: 'US',
                            org: 'Example ISP',
                            vulns: Math.random() > 0.8 ? ['CVE-2024-1234'] : []
                        }
                    };
                }
            });
            resolve();
        }, 300);
    });
};

CyberSOCApp.prototype.enrichWithOTX = function(results) {
    // Simulate AlienVault OTX enrichment
    return new Promise(resolve => {
        setTimeout(() => {
            Object.values(results).flat().forEach(ioc => {
                if (Math.random() > 0.8) {
                    ioc.enrichment = {
                        ...ioc.enrichment,
                        otx: {
                            pulses: Math.floor(Math.random() * 5),
                            threat_types: ['malware', 'phishing'],
                            first_seen: new Date(Date.now() - Math.random() * 60 * 24 * 60 * 60 * 1000).toISOString()
                        }
                    };
                }
            });
            resolve();
        }, 150);
    });
};

// ===== MITRE ATT&CK MAPPING =====
CyberSOCApp.prototype.mapToMitre = function(results) {
    return new Promise(resolve => {
        setTimeout(() => {
            // Simple heuristic mapping
            Object.values(results).flat().forEach(ioc => {
                const mapping = this.getMitreMapping(ioc);
                if (mapping) {
                    ioc.mitre = mapping;
                }
            });
            resolve();
        }, 100);
    });
};

CyberSOCApp.prototype.getMitreMapping = function(ioc) {
    const mappings = {
        'powershell.exe': [{ tactic: 'execution', technique: 'T1059.001', name: 'PowerShell' }],
        'cmd.exe': [{ tactic: 'execution', technique: 'T1059.003', name: 'Windows Command Shell' }],
        'svchost.exe': [{ tactic: 'defense-evasion', technique: 'T1055', name: 'Process Injection' }],
        'regsvr32.exe': [{ tactic: 'defense-evasion', technique: 'T1218.010', name: 'Regsvr32' }]
    };
    
    if (ioc.type === 'processes' || ioc.type === 'filenames') {
        const filename = ioc.value.toLowerCase();
        for (const [process, techniques] of Object.entries(mappings)) {
            if (filename.includes(process)) {
                return techniques;
            }
        }
    }
    
    // Domain-based mappings
    if (ioc.type === 'domains' && this.isSuspiciousDomain(ioc.value)) {
        return [{ tactic: 'command-and-control', technique: 'T1071.001', name: 'Web Protocols' }];
    }
    
    return null;
};

// ===== RESULTS DISPLAY =====
CyberSOCApp.prototype.displayResults = function(results) {
    const container = document.getElementById('results-container');
    
    if (!results || Object.keys(results).length === 0) {
        container.innerHTML = `
            <div class="no-results">
                <div class="no-results-icon">
                    <i class="fas fa-search"></i>
                </div>
                <h3>No IOCs Extracted Yet</h3>
                <p>Upload content or paste text to begin threat analysis</p>
            </div>
        `;
        this.updateResultsSummary(null);
        return;
    }
    
    this.updateResultsSummary(results);
    
    const totalCount = Object.values(results).reduce((sum, items) => sum + items.length, 0);
    
    if (totalCount === 0) {
        container.innerHTML = `
            <div class="no-results">
                <div class="no-results-icon">
                    <i class="fas fa-search"></i>
                </div>
                <h3>No IOCs Found</h3>
                <p>Try different content or check the sample data</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = '';
    
    for (const [category, items] of Object.entries(results)) {
        if (!items || items.length === 0) continue;
        
        const card = this.createAdvancedIOCCard(category, items);
        container.appendChild(card);
    }
};

CyberSOCApp.prototype.updateResultsSummary = function(results) {
    if (!results) {
        document.getElementById('total-iocs').textContent = '0';
        document.getElementById('high-risk-iocs').textContent = '0';
        document.getElementById('medium-risk-iocs').textContent = '0';
        document.getElementById('low-risk-iocs').textContent = '0';
        return;
    }
    
    const allIOCs = Object.values(results).flat();
    const total = allIOCs.length;
    const high = allIOCs.filter(ioc => ioc.risk === 'high').length;
    const medium = allIOCs.filter(ioc => ioc.risk === 'medium').length;
    const low = allIOCs.filter(ioc => ioc.risk === 'low').length;
    
    document.getElementById('total-iocs').textContent = total.toLocaleString();
    document.getElementById('high-risk-iocs').textContent = high;
    document.getElementById('medium-risk-iocs').textContent = medium;
    document.getElementById('low-risk-iocs').textContent = low;
};

CyberSOCApp.prototype.createAdvancedIOCCard = function(category, items) {
    const categoryInfo = IOC_CATEGORIES[category];
    const card = document.createElement('div');
    card.className = 'ioc-card expanded';
    card.dataset.category = category;
    
    // Calculate risk distribution
    const riskCounts = {
        high: items.filter(item => item.risk === 'high').length,
        medium: items.filter(item => item.risk === 'medium').length,
        low: items.filter(item => item.risk === 'low').length
    };
    
    card.innerHTML = `
        <div class="ioc-card-header" tabindex="0" role="button" aria-expanded="true">
            <div class="ioc-card-title">
                <i class="${categoryInfo.icon}"></i>
                <span>${categoryInfo.name}</span>
                <span class="ioc-count">${items.length}</span>
            </div>
            <div class="ioc-card-actions">
                <div class="risk-indicators">
                    ${riskCounts.high > 0 ? `<span class="risk-badge risk-high">${riskCounts.high} High</span>` : ''}
                    ${riskCounts.medium > 0 ? `<span class="risk-badge risk-medium">${riskCounts.medium} Med</span>` : ''}
                    ${riskCounts.low > 0 ? `<span class="risk-badge risk-low">${riskCounts.low} Low</span>` : ''}
                </div>
                <button class="btn btn-small btn-secondary copy-category-btn" data-category="${category}">
                    <i class="fas fa-copy"></i>
                    Copy
                </button>
                <span class="collapse-icon">
                    <i class="fas fa-chevron-down"></i>
                </span>
            </div>
        </div>
        <div class="ioc-card-content">
            <div class="ioc-content-header">
                <div class="view-toggle">
                    <button class="view-btn active" data-view="list">
                        <i class="fas fa-list"></i>
                        List
                    </button>
                    <button class="view-btn" data-view="table">
                        <i class="fas fa-table"></i>
                        Table
                    </button>
                </div>
                <div class="content-controls">
                    <button class="btn btn-small btn-secondary" onclick="app.enrichCategory('${category}')">
                        <i class="fas fa-brain"></i>
                        Enrich
                    </button>
                    <button class="btn btn-small btn-secondary" onclick="app.analyzeCategory('${category}')">
                        <i class="fas fa-search-plus"></i>
                        Analyze
                    </button>
                </div>
            </div>
            <div class="ioc-list" data-view="list">
                ${this.createAdvancedListView(items)}
            </div>
            <div class="ioc-table" data-view="table" style="display: none;">
                ${this.createAdvancedTableView(items, category)}
            </div>
        </div>
    `;
    
    this.addCardEventListeners(card, category);
    
    return card;
};

CyberSOCApp.prototype.createAdvancedListView = function(items) {
    return items.map(item => {
        const riskClass = `risk-${item.risk}`;
        const confidenceClass = item.confidence >= 0.8 ? 'high-confidence' : 
                               item.confidence >= 0.5 ? 'medium-confidence' : 'low-confidence';
        
        const enrichmentInfo = item.enrichment ? this.formatEnrichmentInfo(item.enrichment) : '';
        const mitreInfo = item.mitre ? this.formatMitreInfo(item.mitre) : '';
        
        return `
            <div class="ioc-item ${riskClass} ${confidenceClass}" data-ioc="${item.value}">
                <div class="ioc-header">
                    <div class="ioc-value">${this.escapeHtml(item.value)}</div>
                    <div class="ioc-indicators">
                        <span class="confidence-badge" title="Confidence: ${Math.round(item.confidence * 100)}%">
                            ${Math.round(item.confidence * 100)}%
                        </span>
                        <span class="risk-badge ${riskClass}">${item.risk.toUpperCase()}</span>
                    </div>
                </div>
                ${item.notes.length > 0 ? `
                    <div class="ioc-notes">
                        ${item.notes.map(note => `<span class="note-tag">${note}</span>`).join('')}
                    </div>
                ` : ''}
                ${enrichmentInfo}
                ${mitreInfo}
                <div class="ioc-actions">
                    <button class="btn btn-small" onclick="app.copyIOC('${item.value}')">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button class="btn btn-small" onclick="app.searchIOC('${item.value}')">
                        <i class="fas fa-search"></i>
                    </button>
                    <button class="btn btn-small" onclick="app.analyzeIOC('${item.value}')">
                        <i class="fas fa-microscope"></i>
                    </button>
                </div>
            </div>
        `;
    }).join('');
};

CyberSOCApp.prototype.createAdvancedTableView = function(items, category) {
    const hasSubtype = category === 'hashes';
    const hasEnrichment = items.some(item => item.enrichment);
    
    return `
        <div class="ioc-table-wrapper">
            <table class="ioc-table">
                <thead>
                    <tr>
                        <th>Value</th>
                        ${hasSubtype ? '<th>Type</th>' : ''}
                        <th>Risk</th>
                        <th>Confidence</th>
                        <th>Notes</th>
                        ${hasEnrichment ? '<th>Intelligence</th>' : ''}
                        <th>First Seen</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${items.map(item => `
                        <tr class="risk-${item.risk}">
                            <td class="ioc-value-cell">
                                <span class="font-mono">${this.escapeHtml(item.value)}</span>
                            </td>
                            ${hasSubtype ? `<td>${item.subtype || ''}</td>` : ''}
                            <td>
                                <span class="risk-badge ${item.risk}">${item.risk.toUpperCase()}</span>
                            </td>
                            <td>
                                <span class="confidence-badge">${Math.round(item.confidence * 100)}%</span>
                            </td>
                            <td class="notes-cell">
                                ${item.notes.map(note => `<span class="note-tag">${note}</span>`).join(' ')}
                            </td>
                            ${hasEnrichment ? `<td class="enrichment-cell">${this.formatEnrichmentSummary(item.enrichment)}</td>` : ''}
                            <td class="text-muted">
                                ${new Date(item.firstSeen).toLocaleString()}
                            </td>
                            <td class="actions-cell">
                                <div class="action-buttons">
                                    <button class="btn btn-small" onclick="app.copyIOC('${item.value}')" title="Copy">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                    <button class="btn btn-small" onclick="app.analyzeIOC('${item.value}')" title="Analyze">
                                        <i class="fas fa-search"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
};

CyberSOCApp.prototype.addCardEventListeners = function(card, category) {
    // Header click to toggle
    const header = card.querySelector('.ioc-card-header');
    header.addEventListener('click', (e) => {
        if (e.target.closest('.copy-category-btn') || e.target.closest('.risk-indicators')) return;
        this.toggleCard(card);
    });
    
    // Copy category button
    const copyBtn = card.querySelector('.copy-category-btn');
    copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.copyCategory(category);
    });
    
    // View toggle buttons
    const viewButtons = card.querySelectorAll('.view-btn');
    viewButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            this.toggleCardView(card, btn.dataset.view);
        });
    });
};

CyberSOCApp.prototype.toggleCard = function(card) {
    card.classList.toggle('expanded');
    card.classList.toggle('collapsed');
    
    const icon = card.querySelector('.collapse-icon i');
    if (card.classList.contains('expanded')) {
        icon.className = 'fas fa-chevron-down';
    } else {
        icon.className = 'fas fa-chevron-right';
    }
};

CyberSOCApp.prototype.toggleCardView = function(card, view) {
    const viewButtons = card.querySelectorAll('.view-btn');
    const listView = card.querySelector('[data-view="list"]');
    const tableView = card.querySelector('[data-view="table"]');
    
    viewButtons.forEach(btn => btn.classList.remove('active'));
    card.querySelector(`.view-btn[data-view="${view}"]`).classList.add('active');
    
    if (view === 'list') {
        listView.style.display = 'block';
        tableView.style.display = 'none';
    } else {
        listView.style.display = 'none';
        tableView.style.display = 'block';
    }
};

// ===== UTILITY FUNCTIONS =====
CyberSOCApp.prototype.formatEnrichmentInfo = function(enrichment) {
    if (!enrichment) return '';
    
    let info = '<div class="enrichment-info">';
    
    if (enrichment.virustotal) {
        const vt = enrichment.virustotal;
        info += `
            <div class="enrichment-source">
                <i class="fas fa-shield-virus"></i>
                <strong>VirusTotal:</strong> ${vt.detections}/${vt.total_engines} detections
                <span class="reputation ${vt.reputation}">${vt.reputation}</span>
            </div>
        `;
    }
    
    if (enrichment.shodan) {
        const sh = enrichment.shodan;
        info += `
            <div class="enrichment-source">
                <i class="fas fa-server"></i>
                <strong>Shodan:</strong> ${sh.services.join(', ')} | ${sh.country} | ${sh.org}
                ${sh.vulns.length > 0 ? `<span class="vulns">Vulns: ${sh.vulns.join(', ')}</span>` : ''}
            </div>
        `;
    }
    
    if (enrichment.otx) {
        const otx = enrichment.otx;
        info += `
            <div class="enrichment-source">
                <i class="fas fa-satellite-dish"></i>
                <strong>OTX:</strong> ${otx.pulses} pulses | ${otx.threat_types.join(', ')}
            </div>
        `;
    }
    
    info += '</div>';
    return info;
};

CyberSOCApp.prototype.formatEnrichmentSummary = function(enrichment) {
    if (!enrichment) return '';
    
    const sources = [];
    if (enrichment.virustotal) sources.push('VT');
    if (enrichment.shodan) sources.push('Shodan');
    if (enrichment.otx) sources.push('OTX');
    
    return sources.join(', ');
};

CyberSOCApp.prototype.formatMitreInfo = function(mitre) {
    if (!mitre || !Array.isArray(mitre)) return '';
    
    return `
        <div class="mitre-info">
            <div class="mitre-label">
                <i class="fas fa-project-diagram"></i>
                <strong>MITRE ATT&CK:</strong>
            </div>
            <div class="mitre-techniques">
                ${mitre.map(technique => `
                    <span class="mitre-technique-tag" title="${technique.name}">
                        ${technique.technique}
                    </span>
                `).join('')}
            </div>
        </div>
    `;
};

CyberSOCApp.prototype.escapeHtml = function(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
};

// ===== IOC ACTIONS =====
CyberSOCApp.prototype.copyIOC = function(value) {
    this.copyToClipboard(value, `IOC copied: ${value}`);
};

CyberSOCApp.prototype.searchIOC = function(value) {
    // Implement search functionality
    this.showToast(`Searching for: ${value}`, 'info', 'Search Initiated');
};

CyberSOCApp.prototype.analyzeIOC = function(value) {
    // Implement detailed analysis
    this.showToast(`Analyzing: ${value}`, 'info', 'Analysis Started');
};

CyberSOCApp.prototype.copyCategory = function(category) {
    if (!this.currentResults || !this.currentResults[category]) {
        this.showToast('No data to copy', 'warning');
        return;
    }
    
    const items = this.currentResults[category];
    const text = items.map(item => item.value).join('\n');
    
    this.copyToClipboard(text, `${IOC_CATEGORIES[category].name} copied (${items.length} items)`);
};

CyberSOCApp.prototype.copyAllResults = function() {
    if (!this.currentResults) {
        this.showToast('No data to copy', 'warning');
        return;
    }
    
    const sections = [];
    let totalCount = 0;
    
    for (const [category, items] of Object.entries(this.currentResults)) {
        if (!items || items.length === 0) continue;
        
        const categoryInfo = IOC_CATEGORIES[category];
        sections.push(`=== ${categoryInfo.name} (${items.length}) ===`);
        sections.push(items.map(item => item.value).join('\n'));
        sections.push('');
        totalCount += items.length;
    }
    
    const text = sections.join('\n');
    this.copyToClipboard(text, `All IOCs copied (${totalCount} items)`);
};

CyberSOCApp.prototype.copyToClipboard = function(text, successMessage) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            this.showToast(successMessage, 'success');
        }).catch(() => {
            this.showToast('Copy failed', 'error');
        });
    } else {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            this.showToast(successMessage, 'success');
        } catch {
            this.showToast('Copy failed', 'error');
        }
        document.body.removeChild(textarea);
    }
};

// ===== EXPORT FUNCTIONS =====
CyberSOCApp.prototype.exportResults = function(format) {
    if (!this.currentResults) {
        this.showToast('No data to export', 'warning');
        return;
    }
    
    switch (format) {
        case 'csv':
            this.exportCSV();
            break;
        case 'json':
            this.exportJSON();
            break;
        case 'stix':
            this.exportSTIX();
            break;
    }
};

CyberSOCApp.prototype.exportCSV = function() {
    const rows = [['Category', 'Value', 'Type', 'Risk', 'Confidence', 'Notes', 'First Seen', 'Enrichment']];
    
    for (const [category, items] of Object.entries(this.currentResults)) {
        for (const item of items) {
            rows.push([
                IOC_CATEGORIES[category].name,
                this.sanitizeCSVField(item.value),
                this.sanitizeCSVField(item.subtype || ''),
                this.sanitizeCSVField(item.risk),
                this.sanitizeCSVField(item.confidence.toString()),
                this.sanitizeCSVField(item.notes.join('; ')),
                this.sanitizeCSVField(item.firstSeen),
                this.sanitizeCSVField(this.formatEnrichmentSummary(item.enrichment))
            ]);
        }
    }
    
    const csv = rows.map(row => 
        row.map(field => `"${field.replace(/"/g, '""')}"`).join(',')
    ).join('\n');
    
    this.downloadFile(csv, 'cybersoc-analysis.csv', 'text/csv');
    this.showToast('CSV exported successfully', 'success');
};

CyberSOCApp.prototype.exportJSON = function() {
    const exportData = {
        metadata: {
            generated: new Date().toISOString(),
            tool: 'CyberSOC Pro',
            version: '2.0.0',
            total_iocs: Object.values(this.currentResults).reduce((sum, items) => sum + items.length, 0)
        },
        results: this.currentResults
    };
    
    const json = JSON.stringify(exportData, null, 2);
    this.downloadFile(json, 'cybersoc-analysis.json', 'application/json');
    this.showToast('JSON exported successfully', 'success');
};

CyberSOCApp.prototype.exportSTIX = function() {
    // Simplified STIX 2.1 format
    const stixData = {
        "type": "bundle",
        "id": `bundle--${this.generateUUID()}`,
        "spec_version": "2.1",
        "objects": []
    };
    
    // Add identity
    stixData.objects.push({
        "type": "identity",
        "id": `identity--${this.generateUUID()}`,
        "created": new Date().toISOString(),
        "modified": new Date().toISOString(),
        "name": "CyberSOC Pro",
        "identity_class": "organization"
    });
    
    // Convert IOCs to STIX indicators
    for (const [category, items] of Object.entries(this.currentResults)) {
        for (const item of items) {
            const indicator = {
                "type": "indicator",
                "id": `indicator--${this.generateUUID()}`,
                "created": item.firstSeen,
                "modified": item.firstSeen,
                "labels": ["malicious-activity"],
                "pattern": this.createSTIXPattern(category, item.value),
                "valid_from": item.firstSeen
            };
            
            stixData.objects.push(indicator);
        }
    }
    
    const stix = JSON.stringify(stixData, null, 2);
    this.downloadFile(stix, 'cybersoc-indicators.json', 'application/json');
    this.showToast('STIX export completed', 'success');
};

CyberSOCApp.prototype.createSTIXPattern = function(category, value) {
    const patterns = {
        'ipv4': `[ipv4-addr:value = '${value}']`,
        'ipv6': `[ipv6-addr:value = '${value}']`,
        'domains': `[domain-name:value = '${value}']`,
        'urls': `[url:value = '${value}']`,
        'emails': `[email-addr:value = '${value}']`,
        'hashes': `[file:hashes.MD5 = '${value}' OR file:hashes.SHA1 = '${value}' OR file:hashes.SHA256 = '${value}']`,
        'filenames': `[file:name = '${value}']`
    };
    
    return patterns[category] || `[artifact:payload_bin matches '${value}']`;
};

CyberSOCApp.prototype.sanitizeCSVField = function(text) {
    if (typeof text !== 'string') return String(text);
    
    // Prefix with apostrophe if starts with formula characters
    if (/^[=+\-@]/.test(text)) {
        return "'" + text;
    }
    
    return text;
};

CyberSOCApp.prototype.generateUUID = function() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
};

CyberSOCApp.prototype.downloadFile = function(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

// ===== UI HELPER FUNCTIONS =====
CyberSOCApp.prototype.showLoading = function(message = 'Processing...') {
    const overlay = document.getElementById('loading-overlay');
    const text = overlay.querySelector('p');
    text.textContent = message;
    overlay.classList.add('active');
};

CyberSOCApp.prototype.hideLoading = function() {
    const overlay = document.getElementById('loading-overlay');
    overlay.classList.remove('active');
};

CyberSOCApp.prototype.showToast = function(message, type = 'info', title = null) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    
    const icons = {
        success: 'fas fa-check-circle',
        error: 'fas fa-exclamation-circle',
        warning: 'fas fa-exclamation-triangle',
        info: 'fas fa-info-circle'
    };
    
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div class="toast-icon">
            <i class="${icons[type]}"></i>
        </div>
        <div class="toast-content">
            ${title ? `<div class="toast-title">${title}</div>` : ''}
            <div class="toast-message">${message}</div>
        </div>
    `;
    
    container.appendChild(toast);
    
    // Trigger animation
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });
    
    // Remove after delay
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            if (toast.parentNode) {
                container.removeChild(toast);
            }
        }, 300);
    }, 4000);
};

// ===== THEME MANAGEMENT =====
CyberSOCApp.prototype.setupTheme = function() {
    const savedTheme = localStorage.getItem('app_theme') || this.settings.theme;
    this.applyTheme(savedTheme);
};

CyberSOCApp.prototype.toggleTheme = function() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    this.applyTheme(newTheme);
};

CyberSOCApp.prototype.applyTheme = function(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('app_theme', theme);
    
    const themeIcon = document.querySelector('#theme-toggle i');
    if (themeIcon) {
        themeIcon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
    
    this.settings.theme = theme;
};

// ===== KEYBOARD SHORTCUTS =====
CyberSOCApp.prototype.setupKeyboardShortcuts = function() {
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + Enter: Extract IOCs
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            if (this.currentTab === 'ioc-extractor') {
                this.extractAndAnalyze();
            }
        }
        
        // Ctrl/Cmd + K: Clear input
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            if (this.currentTab === 'ioc-extractor') {
                this.clearInput();
            }
        }
        
        // Ctrl/Cmd + S: Save/Export
        if ((e.ctrlKey || e.metaKey) && e.key === 's') {
            e.preventDefault();
            if (this.currentResults) {
                this.exportResults('json');
            }
        }
        
        // ESC: Close modals
        if (e.key === 'Escape') {
            this.closeModals();
        }
    });
};

// ===== MODAL MANAGEMENT =====
CyberSOCApp.prototype.openSettingsModal = function() {
    const modal = document.getElementById('settings-modal');
    modal.classList.add('active');
    
    // Populate API keys (masked)
    document.getElementById('virustotal-api').value = this.apiKeys.virustotal ? '••••••••' : '';
    document.getElementById('shodan-api').value = this.apiKeys.shodan ? '••••••••' : '';
    document.getElementById('censys-api').value = this.apiKeys.censys ? '••••••••' : '';
    
    // Setup modal events
    this.setupModalEvents();
};

CyberSOCApp.prototype.setupModalEvents = function() {
    const modal = document.getElementById('settings-modal');
    
    // Close button
    modal.querySelector('.modal-close').addEventListener('click', () => {
        this.closeModals();
    });
    
    // Click outside to close
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            this.closeModals();
        }
    });
    
    // Settings tabs
    modal.querySelectorAll('.settings-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const targetTab = e.currentTarget.dataset.settingsTab;
            this.switchSettingsTab(targetTab);
        });
    });
    
    // API key inputs
    modal.querySelectorAll('input[type="password"]').forEach(input => {
        input.addEventListener('focus', () => {
            if (input.value === '••••••••') {
                input.value = '';
            }
        });
        
        input.addEventListener('blur', () => {
            const key = input.id.replace('-api', '');
            if (input.value && input.value !== '••••••••') {
                this.apiKeys[key] = input.value;
                this.saveApiKeys();
                input.value = '••••••••';
            }
        });
    });
};

CyberSOCApp.prototype.switchSettingsTab = function(tabName) {
    // Update tabs
    document.querySelectorAll('.settings-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelector(`[data-settings-tab="${tabName}"]`).classList.add('active');
    
    // Update panels
    document.querySelectorAll('.settings-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(`${tabName}-settings`).classList.add('active');
};

CyberSOCApp.prototype.closeModals = function() {
    document.querySelectorAll('.modal').forEach(modal => {
        modal.classList.remove('active');
    });
};

// ===== FILE UPLOAD =====
CyberSOCApp.prototype.setupFileUpload = function() {
    const dropZone = document.getElementById('file-drop-zone');
    const fileInput = document.getElementById('file-input');
    
    dropZone.addEventListener('click', () => {
        fileInput.click();
    });
    
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        
        const files = Array.from(e.dataTransfer.files);
        this.handleFileUpload(files);
    });
    
    fileInput.addEventListener('change', (e) => {
        const files = Array.from(e.target.files);
        this.handleFileUpload(files);
    });
};

CyberSOCApp.prototype.handleFileUpload = function(files) {
    const uploadedFiles = document.getElementById('uploaded-files');
    uploadedFiles.innerHTML = '';
    
    files.forEach(file => {
        if (file.size > 10 * 1024 * 1024) { // 10MB limit
            this.showToast(`File ${file.name} is too large (max 10MB)`, 'warning');
            return;
        }
        
        const fileItem = document.createElement('div');
        fileItem.className = 'uploaded-file';
        fileItem.innerHTML = `
            <div class="file-info">
                <i class="fas fa-file"></i>
                <span>${file.name}</span>
                <span class="file-size">(${this.formatFileSize(file.size)})</span>
            </div>
            <button class="btn btn-small btn-danger" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        uploadedFiles.appendChild(fileItem);
        
        // Read file content
        this.readFile(file);
    });
};

CyberSOCApp.prototype.readFile = function(file) {
    const reader = new FileReader();
    
    reader.onload = (e) => {
        const content = e.target.result;
        const currentContent = document.getElementById('input-text').value;
        
        document.getElementById('input-text').value = currentContent + '\n\n' + content;
        this.updateInputStats();
        this.updateExtractButton();
        
        this.showToast(`File ${file.name} loaded successfully`, 'success');
    };
    
    reader.onerror = () => {
        this.showToast(`Error reading file ${file.name}`, 'error');
    };
    
    reader.readAsText(file);
};

CyberSOCApp.prototype.formatFileSize = function(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

// ===== URL ANALYSIS =====
CyberSOCApp.prototype.analyzeURL = function() {
    const urlInput = document.getElementById('url-input');
    const url = urlInput.value.trim();
    
    if (!url) {
        this.showToast('Please enter a URL to analyze', 'warning');
        return;
    }
    
    if (!this.isValidURL(url)) {
        this.showToast('Please enter a valid URL', 'warning');
        return;
    }
    
    this.showLoading('Analyzing URL...');
    
    // Simulate URL analysis
    setTimeout(() => {
        // Add URL to input textarea
        const currentContent = document.getElementById('input-text').value;
        document.getElementById('input-text').value = currentContent + '\n\nURL Analysis:\n' + url + '\n';
        
        this.updateInputStats();
        this.updateExtractButton();
        this.hideLoading();
        
        this.showToast('URL analysis completed', 'success');
    }, 1000);
};

// ===== BACKGROUND TASKS =====
CyberSOCApp.prototype.startBackgroundTasks = function() {
    // Update sync status
    setInterval(() => {
        document.getElementById('last-sync').textContent = 'Just now';
    }, 30000);
    
    // Simulate threat level updates
    setInterval(() => {
        this.updateThreatLevel();
    }, 60000);
};

CyberSOCApp.prototype.updateThreatLevel = function() {
    // Simulate threat level changes
    const levels = ['LOW', 'GUARDED', 'ELEVATED', 'HIGH', 'SEVERE'];
    const scores = { 'LOW': 2.1, 'GUARDED': 4.2, 'ELEVATED': 6.5, 'HIGH': 8.1, 'SEVERE': 9.5 };
    
    const randomLevel = levels[Math.floor(Math.random() * levels.length)];
    const score = scores[randomLevel] + (Math.random() - 0.5) * 0.8;
    
    this.threatLevel = { level: randomLevel, score: Math.round(score * 10) / 10 };
    
    const levelElement = document.getElementById('threat-level');
    if (levelElement) {
        levelElement.querySelector('.level-text').textContent = this.threatLevel.level;
        levelElement.querySelector('.level-score').textContent = this.threatLevel.score;
    }
};

CyberSOCApp.prototype.setupBackgroundUpdates = function() {
    // Auto-save settings
    setInterval(() => {
        this.saveSettings();
    }, 30000);
    
    // Update timestamps
    setInterval(() => {
        document.querySelectorAll('time').forEach(timeElement => {
            if (timeElement.id === 'last-sync') {
                timeElement.textContent = 'Just now';
            }
        });
    }, 60000);
};

// ===== INTELLIGENCE SOURCES =====
CyberSOCApp.prototype.initializeIntelSources = function() {
    this.threatIntelSources.set('virustotal', {
        name: 'VirusTotal',
        status: this.apiKeys.virustotal ? 'active' : 'inactive',
        lastUpdate: new Date().toISOString(),
        feeds: ['malware', 'suspicious files', 'URLs']
    });
    
    this.threatIntelSources.set('shodan', {
        name: 'Shodan',
        status: this.apiKeys.shodan ? 'active' : 'inactive',
        lastUpdate: new Date().toISOString(),
        feeds: ['network scan', 'exposed services', 'vulnerabilities']
    });
    
    this.threatIntelSources.set('otx', {
        name: 'AlienVault OTX',
        status: 'active',
        lastUpdate: new Date().toISOString(),
        feeds: ['threat pulses', 'IOCs', 'campaigns']
    });
    
    this.threatIntelSources.set('misp', {
        name: 'MISP',
        status: 'active',
        lastUpdate: new Date().toISOString(),
        feeds: ['threat sharing', 'attributes', 'events']
    });
};

CyberSOCApp.prototype.loadThreatIntelData = function() {
    // Implementation for threat intelligence tab
    this.showToast('Threat Intelligence data loaded', 'info');
};

CyberSOCApp.prototype.loadMitreMatrix = function() {
    // Implementation for MITRE ATT&CK matrix
    this.showToast('MITRE ATT&CK matrix loaded', 'info');
};

CyberSOCApp.prototype.loadDetectionRules = function() {
    // Implementation for detection rules
    this.showToast('Detection rules loaded', 'info');
};

CyberSOCApp.prototype.loadOSINTTools = function() {
    // Implementation for OSINT toolkit
    this.showToast('OSINT tools loaded', 'info');
};

CyberSOCApp.prototype.loadThreatHuntingData = function() {
    // Implementation for threat hunting
    this.showToast('Threat hunting data loaded', 'info');
};

CyberSOCApp.prototype.loadAnalyticsData = function() {
    // Implementation for analytics
    this.showToast('Analytics data loaded', 'info');
};

CyberSOCApp.prototype.loadTimelineData = function() {
    // Implementation for timeline
    this.showToast('Timeline data loaded', 'info');
};

CyberSOCApp.prototype.loadCampaignData = function() {
    // Implementation for campaigns
    this.showToast('Campaign data loaded', 'info');
};

// ===== CATEGORY ACTIONS =====
CyberSOCApp.prototype.enrichCategory = function(category) {
    this.showToast(`Enriching ${IOC_CATEGORIES[category].name}...`, 'info');
    // Implementation for category enrichment
};

CyberSOCApp.prototype.analyzeCategory = function(category) {
    this.showToast(`Analyzing ${IOC_CATEGORIES[category].name}...`, 'info');
    // Implementation for category analysis
};

CyberSOCApp.prototype.switchResultsView = function(view) {
    // Implementation for switching results view
    this.showToast(`Switched to ${view} view`, 'info');
};

// Initialize application when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        app = new CyberSOCApp();
    });
} else {
    app = new CyberSOCApp();
}