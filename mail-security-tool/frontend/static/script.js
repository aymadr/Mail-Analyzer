/**
 * sec-ops Frontend Logic - Professional SOC Edition
 * Optimized for performance, clean animations, and operational clarity
 */

// Tab Configuration
const tabConfig = {
    dashboard: { title: "Dashboard Sécurité", desc: "Bienvenue dans SecAnalyze - Choisissez une analyse pour commencer" },
    email: { title: "Inspecteur d'Email", desc: "Parse automatiquement les en-têtes SPF, DKIM, DMARC et analyse les IPs" },
    attachment: { title: "Sandbox Pièce Jointe", desc: "Calcul de Hash (SHA256, MD5) & Vérification Virustotal + Hybrid Analysis" },
    url: { title: "Scanner d'URL", desc: "Vérification réputation VirusTotal, Scamdoc et empreinte URLScan" },
    ip: { title: "Threat Intel IP", desc: "Consultation croisée VirusTotal & AbuseIPDB" },
    history: { title: "Historique des Analyses", desc: "Archives des analyses enregistrées dans la DB locale avec filtres" }
};

// DOM Cache for performance
const domCache = {};
function getElement(id) {
    if (!domCache[id]) domCache[id] = document.getElementById(id);
    return domCache[id];
}

// Utility: escape HTML for safe insertion into innerHTML
function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initDragAndDrop('emailDropZone', 'emailFile', 'emailFileName');
    initDragAndDrop('attachDropZone', 'attachmentFile', 'attachFileName');
    
    // Set initial header for dashboard
    document.getElementById('active-tab-title').innerHTML = tabConfig.dashboard.title;
    document.getElementById('active-tab-desc').innerHTML = tabConfig.dashboard.desc;
    
    // Load dashboard on startup
    loadDashboard();
});

// Function to programmatically switch tabs
function switchTab(tabName) {
    const navItem = document.querySelector(`[data-tab="${tabName}"]`);
    if(navItem) navItem.click();
}

// Navigation / Tabs - Optimized for SOC operations
function initTabs() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.dataset.tab;
            
            // Rapid state update
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            
            // Update header immediately
            getElement('active-tab-title').textContent = tabConfig[target].title;
            getElement('active-tab-desc').textContent = tabConfig[target].desc;
            
            // Panel transition: clean fade
            document.querySelectorAll('.view-panel').forEach(p => {
                p.classList.remove('active', 'fade-in');
                p.classList.add('hidden');
            });
            const targetPanel = getElement(target);
            targetPanel.classList.remove('hidden');
            void targetPanel.offsetWidth;
            targetPanel.classList.add('active', 'fade-in');

            // Load data if needed
            if(target === 'history') loadHistory();
            if(target === 'dashboard') loadDashboard();
        });
    });
}

// Custom Drag and Drop
function initDragAndDrop(zoneId, inputId, labelId) {
    const dropZone = document.getElementById(zoneId);
    const fileInput = document.getElementById(inputId);
    const fileLabel = document.getElementById(labelId);

    if(!dropZone) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if(files.length) {
            fileInput.files = files;
            updateFileName();
        }
    });

    fileInput.addEventListener('change', updateFileName);

    function updateFileName() {
        if(fileInput.files.length > 0) {
            fileLabel.innerHTML = `<i class="fa-solid fa-file-check"></i> Fichier: ${fileInput.files[0].name}`;
            fileLabel.style.color = 'var(--success)';
        } else {
            fileLabel.innerHTML = '';
        }
    }
}

// ------------------------------------------------------------------
// API CALLS & FORM SUBMISSIONS
// ------------------------------------------------------------------

// 1. Email Submit
getElement('emailForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = getElement('emailFile').files[0];
    if (!file) return showToast('error', 'Invalid Input', 'Select an email file.');
    
    const formData = new FormData();
    formData.append('file', file);
    
    showLoader('emailResult');
    try {
        const res = await fetch('/api/analyze/email', { method: 'POST', body: formData });
        const data = await res.json();
        if (res.ok) {
            renderEmailResult(data);
            showToast('success', 'Email Analyzed', 'Analysis complete');
        } else throw new Error(data.error || 'Server error');
    } catch (err) {
        showError('emailResult');
        showToast('error', 'Analysis Failed', err.message);
    }
});

// 2. Attachment Submit
document.getElementById('attachmentForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await submitAttachment('analysis');
});

const attachmentHashBtn = document.getElementById('attachHashBtn');
if (attachmentHashBtn) {
    attachmentHashBtn.addEventListener('click', async () => {
        await submitAttachment('hash');
    });
}

async function submitAttachment(mode) {
    const file = getElement('attachmentFile').files[0];
    const hashInput = getElement('attachmentHashInput');
    const attachmentHash = (hashInput?.value || '').trim();

    if (mode === 'analysis') {
        if (!file) return showToast('error', 'Invalid Input', 'Select a file.');

        const formData = new FormData();
        formData.append('file', file);

        showLoader('attachmentResult');
        try {
            const res = await fetch('/api/analyze/attachment', { method: 'POST', body: formData });
            const data = await res.json();
            if (res.ok) {
                renderAttachmentResult(data);
                showToast('success', 'File Analyzed', 'Hash computed & verified');
            } else throw new Error(data.error || 'Server error');
        } catch (err) {
            showError('attachmentResult');
            showToast('error', 'Analysis Failed', err.message);
        }
        return;
    }

    if (!attachmentHash) {
        return showToast('error', 'Invalid Input', 'Paste a hash value.');
    }

    showLoader('attachmentResult');
    try {
        const res = await fetch('/api/analyze/attachment/hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_hash: attachmentHash })
        });
        const data = await res.json();
        if (res.ok) {
            renderAttachmentResult(data);
            showToast('success', 'Hash Verified', 'Reputation checked');
        } else throw new Error(data.error || 'Server error');
    } catch (err) {
        showError('attachmentResult');
        showToast('error', 'Analysis Failed', err.message);
    }
}

// URL & IP Analysis - Optimized
getElement('urlForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = getElement('urlInput').value.trim();
    
    if (!url) return showToast('error', 'Invalid Input', 'Enter a URL.');
    
    showLoader('urlResult');
    try {
        const res = await fetch('/api/analyze/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        if (res.ok) {
            renderUrlResult(data);
            showToast('success', 'URL Scanned', 'Reputation loaded');
        } else throw new Error(data.error || 'Server error');
    } catch (err) {
        showError('urlResult');
        showToast('error', 'Scan Failed', err.message);
    }
});

getElement('ipForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = getElement('ipInput').value.trim();
    
    if (!ip) return showToast('error', 'Invalid Input', 'Enter an IP address.');
    
    showLoader('ipResult');
    try {
        const res = await fetch('/api/analyze/ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if (res.ok) {
            renderIpResult(data);
            showToast('success', 'IP Analyzed', 'Threat intel loaded');
        } else throw new Error(data.error || 'Server error');
    } catch (err) {
        showError('ipResult');
        showToast('error', 'Analysis Failed', err.message);
    }
});

// 5. History Loading - Optimized
async function loadHistory() {
    const list = getElement('historyList');
    list.innerHTML = '<div class="loader-container"><div class="spinner"></div><p style="color: var(--primary); font-family: var(--font-mono); font-size: 0.85rem; margin:16px 0 0 0;">LOADING</p></div>';
    try {
        const res = await fetch('/api/history');
        const data = await res.json();
        
        if (data.length === 0) {
            list.innerHTML = '<div style="text-align:center; padding: 60px 20px; color: var(--text-muted);"><i class="fa-solid fa-inbox" style="font-size:2.5rem; margin-bottom:16px; display:block; opacity:0.5;"></i><p style="margin:0; font-size:0.95rem;">No analysis history</p></div>';
            return;
        }

        const typeMeta = {
            email: { icon: 'fa-envelope', label: 'Email' },
            attachment: { icon: 'fa-file-shield', label: 'File' },
            ip: { icon: 'fa-network-wired', label: 'IP' },
            url: { icon: 'fa-link', label: 'URL' }
        };

        let html = '';
        data.forEach(item => {
            const meta = typeMeta[item.type] || { icon: 'fa-circle-info', label: item.type || 'Analysis' };
            const date = new Date(item.date);
            const dateStr = date.toLocaleDateString('en-US') + ' ' + date.toLocaleTimeString('en-US', {hour: '2-digit', minute: '2-digit'});
            html += `
                <div class="history-item">
                    <div class="h-info">
                        <h4 style="margin:0 0 6px 0; font-size:0.95rem; font-weight:600;"><i class="fa-solid ${meta.icon}" style="margin-right:8px; color:var(--primary);"></i>${meta.label} - ${item.title || 'Untitled'}</h4>
                        <p style="margin:0; font-size:0.8rem; color:var(--text-muted);">${item.detail || 'No details'}</p>
                    </div>
                    <div class="h-date" style="font-size:0.75rem; color:var(--text-muted); white-space:nowrap;">${dateStr}</div>
                </div>
            `;
        });
        list.innerHTML = html;
    } catch (error) {
        list.innerHTML = `<div style="padding:40px; text-align:center; color:var(--danger);"><i class="fa-solid fa-exclamation-circle" style="font-size:2rem; margin-bottom:12px; display:block;"></i><p style="margin:0; font-size:0.9rem;">Failed to load history</p></div>`;
    }
}

// 6. Dashboard - Professional Operations View
async function loadDashboard() {
    const panel = getElement('dashboardSummary');
    panel.innerHTML = '<div class="loader-container"><div class="spinner"></div><p style="color: var(--primary); font-family: var(--font-mono); font-size: 0.85rem; margin:16px 0 0 0;">LOADING STATISTICS</p></div>';

    try {
        const res = await fetch('/api/dashboard');
        const data = await res.json();

        const totals = data.totals || {};
        const latest = data.latest_email || {};
        const recent = data.recent || [];

        let html = `
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item"><span class="stat-label">EMAILS ANALYZED</span><span class="stat-value" style="font-size:1.6rem;">${totals.emails || 0}</span></div>
                    <div class="stat-item"><span class="stat-label">FILES SCANNED</span><span class="stat-value" style="font-size:1.6rem;">${totals.attachments || 0}</span></div>
                    <div class="stat-item"><span class="stat-label">IPS ANALYZED</span><span class="stat-value" style="font-size:1.6rem;">${totals.ips || 0}</span></div>
                    <div class="stat-item"><span class="stat-label">URLS VERIFIED</span><span class="stat-value" style="font-size:1.6rem;">${totals.urls || 0}</span></div>
                </div>
            </div>
        `;

        if (latest.sender || latest.subject) {
            html += `
                <div class="result-card" style="margin-top:20px;">
                    <div class="result-header"><i class="fa-solid fa-envelope"></i> Last Email</div>
                    <div class="result-body">
                        <div class="stat-item">
                            <span class="stat-label">FROM</span>
                            <span class="stat-value" style="font-size:0.95rem; word-break:break-all;">${latest.sender || 'Unknown'}</span>
                        </div>
                        <div class="stat-item" style="margin-top:12px;">
                            <span class="stat-label">SUBJECT</span>
                            <span class="stat-value" style="font-size:0.95rem; word-break:break-all;">${latest.subject || 'No Subject'}</span>
                        </div>
                        <div class="stat-item" style="margin-top:12px;">
                            <span class="stat-label">DATE</span>
                            <span class="stat-value" style="font-size:0.9rem; color:var(--text-muted);">${latest.date ? new Date(latest.date).toLocaleString() : 'N/A'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        if (recent.length > 0) {
            html += '<div style="margin-top:20px;"><h3 style="margin:0 0 12px 0; font-size:0.95rem; color:var(--primary); font-weight:600; text-transform:uppercase; letter-spacing:1px;">Recent Activity</h3>';
            recent.forEach(item => {
                const dateStr = new Date(item.date).toLocaleString();
                html += `
                    <div class="history-item">
                        <div class="h-info">
                            <h4 style="margin:0 0 4px 0; font-size:0.9rem;"><i class="fa-solid fa-envelope" style="margin-right:8px; color:var(--primary);"></i>${item.sender || 'Unknown'}</h4>
                            <p style="margin:0; font-size:0.8rem; color:var(--text-muted);">${item.subject || 'No Subject'}</p>
                        </div>
                        <div class="h-date" style="font-size:0.75rem;">${dateStr}</div>
                    </div>
                `;
            });
            html += '</div>';
        }

        panel.innerHTML = html;
    } catch (err) {
        panel.innerHTML = '<div style="padding:48px 32px; text-align:center; color:var(--danger);"><i class="fa-solid fa-exclamation-circle" style="font-size:2rem; margin-bottom:12px; display:block;"></i><p style="margin:0; font-size:0.9rem;">Failed to load dashboard</p></div>';
    }
}


// ------------------------------------------------------------------
// RENDERERS (Stylized HTML injects)
// ------------------------------------------------------------------

function renderEmailResult(data) {
    const el = document.getElementById('emailResult');
    const eInfo = data.email || {};
    const senderContact = parseEmailContact(eInfo.from || '');
    
    let html = `
        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-envelope-open"></i> Metadonnées</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item"><span class="stat-label">EXPÉDITEUR</span><span class="stat-value">${senderContact.name || 'N/A'}</span><div class="text-sm text-muted" style="margin-top:6px; word-break:break-all;">${senderContact.email || 'Email non trouvé'}</div></div>
                    <div class="stat-item"><span class="stat-label">DATE</span><span class="stat-value">${eInfo.date || 'N/A'}</span></div>
                    <div class="stat-item"><span class="stat-label">SUJET</span><span class="stat-value">${eInfo.subject || 'N/A'}</span></div>
                </div>
            </div>
        </div>

        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-crosshairs"></i> Éléments d'Investigation Rapide</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-label">DOMAINE EXPÉDITEUR</span>
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span class="stat-value font-mono" id="copyDomain">${eInfo.spf?.domain || eInfo.dkim?.domain || eInfo.dmarc?.domain || 'N/A'}</span>
                            ${(eInfo.spf?.domain || eInfo.dkim?.domain || eInfo.dmarc?.domain) ? `<button class="btn btn-icon" onclick="copyToClipboard('${eInfo.spf?.domain || eInfo.dkim?.domain || eInfo.dmarc?.domain}')" title="Copier le domaine"><i class="fa-regular fa-copy"></i></button>` : ''}
                        </div>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">ADRESSE IP SOURCE</span>
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span class="stat-value font-mono" id="copyIp">${eInfo.spf?.ip || (data.ips && data.ips.length > 0 ? data.ips[0].ip : 'N/A')}</span>
                            ${(eInfo.spf?.ip || (data.ips && data.ips.length > 0)) ? `<button class="btn btn-icon" onclick="copyToClipboard('${eInfo.spf?.ip || data.ips[0].ip}')" title="Copier l'IP"><i class="fa-regular fa-copy"></i></button>` : ''}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-shield-halved"></i> Vérifications de Sécurité</div>
            <div class="result-body">
                <div class="stats-grid">
                    ${buildSecurityBadge('SPF', eInfo.spf?.status, 
                        (eInfo.spf?.domain ? `Domaine: ${eInfo.spf.domain}<br>` : '') + 
                        (eInfo.spf?.ip ? `IP: ${eInfo.spf.ip}<br>` : '') + 
                        (eInfo.spf?.record || '')
                    )}
                    ${buildSecurityBadge('DKIM', eInfo.dkim?.status, 
                        (eInfo.dkim?.domain ? `Domaine: ${eInfo.dkim.domain}<br>` : '') + 
                        (eInfo.dkim?.algorithm ? `Algo: ${eInfo.dkim.algorithm}` : '')
                    )}
                    ${buildSecurityBadge('DMARC', eInfo.dmarc?.status, 
                        (eInfo.dmarc?.domain ? `Domaine: ${eInfo.dmarc.domain}<br>` : '') + 
                        (eInfo.dmarc?.policy ? `Politique: ${eInfo.dmarc.policy}` : '')
                    )}
                </div>
            </div>
        </div>
    `;

    if (data.scamdoc) {
        const scamdoc = data.scamdoc || {};
        const senderResult = scamdoc.sender || {};
        const mxSenderResult = scamdoc.sender_mxtoolbox || {};
        const scamUrls = scamdoc.urls || [];
        const senderDomain = scamdoc.sender_domain || eInfo?.from || 'N/A';
        const mxRecords = Array.isArray(mxSenderResult.records?.mx) ? mxSenderResult.records.mx : [];
        const dnsHasMx = !!mxSenderResult.has_mx;
        const dnsHasSpf = !!mxSenderResult.has_spf;
        const dnsHasDkim = !!mxSenderResult.has_dkim;
        const dnsHasDmarc = !!mxSenderResult.has_dmarc;

        html += `<div class="result-card">
            <div class="result-header"><i class="fa-solid fa-user-secret"></i> Scamdoc / MXToolbox - Expéditeur</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-label">SCAMDOC RÉPUTATION</span>
                        <div class="text-sm text-muted" style="margin-bottom:8px; word-break:break-all;">${scamdoc.sender_email || 'N/A'}</div>
                        ${buildScamdocBox(senderResult)}
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">MXTOOLBOX DNS DU DOMAINE EXPÉDITEUR</span>
                        ${mxSenderResult.error ? `<div class="api-error-box">${mxSenderResult.error}</div>` : `
                            <div style="margin-top:15px; text-align:center;">
                                <span class="badge badge-neutral">${senderDomain}</span>
                                <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:12px; text-align:left; font-size:0.9rem;">
                                    <div><span style="color:var(--text-muted);">MX:</span> <strong>${dnsHasMx ? `OUI (${mxRecords.length})` : 'NON'}</strong></div>
                                    <div><span style="color:var(--text-muted);">SPF:</span> <strong>${dnsHasSpf ? 'OUI' : 'NON'}</strong></div>
                                    <div><span style="color:var(--text-muted);">DKIM:</span> <strong>${dnsHasDkim ? 'OUI' : 'NON'}</strong></div>
                                    <div><span style="color:var(--text-muted);">DMARC:</span> <strong>${dnsHasDmarc ? 'OUI' : 'NON'}</strong></div>
                                </div>
                                ${dnsHasMx && mxRecords.length > 0 ? `
                                    <div style="margin-top:12px; font-size:0.82rem; color:var(--text-muted); text-align:left;">
                                        ${mxRecords.slice(0, 3).map(r => `${escapeHtml(r.Hostname || r.hostname || 'N/A')} (${escapeHtml(r['IP Address'] || r['IP address'] || r.ip || 'N/A')})`).join('<br>')}
                                    </div>
                                ` : `<p class="text-sm text-muted" style="margin-top:10px;">Aucun MX record trouvé pour ce domaine.</p>`}
                                ${buildSourceLinks([
                                    { label: 'MXToolbox MX', url: mxSenderResult.links?.mx, icon: 'fa-up-right-from-square' },
                                    { label: 'MXToolbox SPF', url: mxSenderResult.links?.spf, icon: 'fa-up-right-from-square' },
                                    { label: 'MXToolbox DKIM', url: mxSenderResult.links?.dkim, icon: 'fa-up-right-from-square' },
                                    { label: 'MXToolbox DMARC', url: mxSenderResult.links?.dmarc, icon: 'fa-up-right-from-square' }
                                ])}
                            </div>
                        `}
                    </div>
                </div>
            </div>
        </div>`;

        if (scamUrls.length > 0) {
            html += `<details class="result-card result-collapsible">
                <summary class="result-header"><i class="fa-solid fa-user-secret"></i> Scamdoc sur URLs extraites</summary>
                <div class="result-body">`;

            scamUrls.forEach(entry => {
                html += `<div class="stat-item" style="margin-bottom:12px;">
                    <div class="text-sm text-muted" style="word-break:break-all; margin-bottom:8px;">${entry.url || 'N/A'}</div>
                    ${buildScamdocBox(entry.result || {})}
                </div>`;
            });

            html += `</div></details>`;
        }

        if (senderResult.public_url || senderResult.detail_url) {
            html += buildSourceLinks([
                { label: 'Ouvrir Scamdoc', url: senderResult.detail_url || senderResult.public_url, icon: 'fa-up-right-from-square' }
            ]);
        }
    }

    if(data.urls && data.urls.extracted && data.urls.extracted.length > 0) {
        const urlSummary = data.urls.summary || {};
        const groupedDomains = data.urls.grouped_domains || [];
        const redirects = data.urls.redirects || [];

        html += `<div class="result-card">
            <div class="result-header"><i class="fa-solid fa-link"></i> Intelligence URL Locale</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item"><span class="stat-label">URLS TROUVÉES</span><span class="stat-value">${urlSummary.total_found || data.urls.extracted.length}</span></div>
                    <div class="stat-item"><span class="stat-label">URLS UNIQUES</span><span class="stat-value">${urlSummary.unique_urls || 0}</span></div>
                    <div class="stat-item"><span class="stat-label">REDIRECTIONS TESTÉES</span><span class="stat-value">${urlSummary.redirects_checked || 0}</span></div>
                </div>
            </div>
        </div>`;

        html += `<details class="result-card result-collapsible">
            <summary class="result-header"><i class="fa-solid fa-sitemap"></i> Regroupement Par Domaine</summary>
            <div class="result-body">`;

        if(groupedDomains.length === 0) {
            html += `<div class="stat-item">Aucun domaine regroupable détecté.</div>`;
        } else {
            groupedDomains.forEach(group => {
                html += `<div class="stat-item mb-3" style="margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:8px;">
                        <strong class="font-mono text-primary">${group.domain || 'unknown'}</strong>
                        <span class="badge badge-suspicious">${group.count || 0} URL(s)</span>
                    </div>
                    <div style="font-size:0.8rem; color:var(--text-muted); word-break:break-all;">
                        ${(group.urls || []).slice(0, 3).join('<br>')}
                    </div>
                </div>`;
            });
        }
        html += `</div></details>`;

        html += `<details class="result-card result-collapsible">
            <summary class="result-header"><i class="fa-solid fa-list"></i> URLs Extraites et Normalisées</summary>
            <div class="result-body">`;

        data.urls.extracted.forEach(item => {
            html += `<div class="stat-item mb-3" style="margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:8px;">
                    <span class="badge badge-neutral">${item.source || 'unknown'}</span>
                    <span class="text-sm text-muted">${item.root_domain || item.domain || 'N/A'}</span>
                </div>
                <div style="font-size:0.8rem; color:var(--text-muted); word-break:break-all; margin-bottom:4px;">
                    Brut: ${item.original || 'N/A'}
                </div>
                <div style="word-break:break-all;">
                    <a href="${item.normalized}" target="_blank" class="text-primary">${item.normalized}</a>
                </div>
            </div>`;
        });

        html += `</div></details>`;

        html += `<details class="result-card result-collapsible">
            <summary class="result-header"><i class="fa-solid fa-route"></i> Chaînes de Redirection (sans clic)</summary>
            <div class="result-body">`;

        if(redirects.length === 0) {
            html += `<div class="stat-item">Aucune URL à résoudre.</div>`;
        } else {
            redirects.forEach(item => {
                const chain = item.chain || [];
                const hasError = !!item.error;
                const chainHtml = chain.map(step => `<div style="word-break:break-all; margin-bottom:4px;">${step}</div>`).join('');

                html += `<div class="stat-item mb-4" style="margin-bottom:14px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:10px;">
                        <span class="badge ${hasError ? 'badge-suspicious' : (item.redirected ? 'badge-malicious' : 'badge-clean')}">
                            ${hasError ? 'Erreur' : (item.redirected ? 'Redirection détectée' : 'Direct')}
                        </span>
                        ${item.status_code ? `<span class="text-sm text-muted">HTTP ${item.status_code}</span>` : ''}
                    </div>
                    ${hasError ? `<div class="api-error-box">${item.error}</div>` : `<div style="font-size:0.85rem; color:var(--text-muted);">${chainHtml}</div>`}
                    <div style="margin-top:8px; display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                        <span class="text-sm">Final:</span>
                        <a href="${item.final_url}" target="_blank" class="text-primary" style="word-break:break-all;">${item.final_url}</a>
                    </div>
                </div>`;
            });
        }

        html += `</div></details>`;
    }

    if(data.ips && data.ips.length > 0) {
        html += `<details class="result-card result-collapsible">
            <summary class="result-header"><i class="fa-solid fa-network-wired"></i> Analyse des Routages (IPs)</summary>
            <div class="result-body">`;
            
        data.ips.forEach(ipItem => {
            const ip = ipItem.ip;
            const vt = ipItem.virustotal || {};
            const ab = ipItem.abuseipdb || {};

            let vtStats = vt.error ? `<div class="api-error-box">${vt.error}</div>` : buildVtStats(vt.last_analysis_stats || {});
            let abStats = ab.error ? `<div class="api-error-box">${ab.error}</div>` : `<div style="margin-top:10px;"><span class="badge ${ab.abuse_confidence_score > 50 ? 'badge-malicious' : 'badge-clean'}">AbuseScore: ${ab.abuse_confidence_score}%</span></div>`;

            html += `
                <div class="stat-item mb-4" style="margin-bottom: 15px;">
                    <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-color); padding-bottom:8px; margin-bottom:10px;">
                        <strong class="font-mono text-primary"><i class="fa-solid fa-server mr-2"></i>${ip}</strong>
                        <span class="text-muted text-sm">${vt.country || ''} - ${vt.asn || ''}</span>
                    </div>
                    <div>${vtStats}</div>
                    <div>${abStats}</div>
                </div>
            `;
        });
        html += `</div></details>`;
    }

    // Affiche les pièces jointes si présentes
    if(data.attachments && data.attachments.length > 0) {
        html += `<div class="result-card">
            <div class="result-header"><i class="fa-solid fa-paperclip"></i> Pièces Jointes Détectées</div>
            <div class="result-body">`;

        data.attachments.forEach(att => {
            html += `
                <div class="stat-item mb-4" style="margin-bottom: 20px;">
                    <div style="margin-bottom: 12px;">
                        <strong><i class="fa-solid fa-file"></i> ${att.filename}</strong>
                        <span class="text-muted text-sm" style="display: block; margin-top: 4px;">Taille: ${formatBytes(att.size)}</span>
                    </div>
                    
                    <div class="stat-item mb-2">
                        <span class="stat-label">SHA256</span>
                        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                            <span class="stat-value mono" style="font-size: 0.85em; word-break: break-all;">${att.sha256 || 'N/A'}</span>
                            ${att.sha256 ? `<button class="btn btn-icon" onclick="copyToClipboard('${att.sha256}')" title="Copier SHA256"><i class="fa-regular fa-copy"></i></button>` : ''}
                        </div>
                    </div>
                    <div class="stat-item mb-2">
                        <span class="stat-label">SHA1</span>
                        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                            <span class="stat-value mono" style="font-size: 0.85em; word-break: break-all;">${att.sha1 || 'N/A'}</span>
                            ${att.sha1 ? `<button class="btn btn-icon" onclick="copyToClipboard('${att.sha1}')" title="Copier SHA1"><i class="fa-regular fa-copy"></i></button>` : ''}
                        </div>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">MD5</span>
                        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                            <span class="stat-value mono" style="font-size: 0.85em; word-break: break-all;">${att.md5 || 'N/A'}</span>
                            ${att.md5 ? `<button class="btn btn-icon" onclick="copyToClipboard('${att.md5}')" title="Copier MD5"><i class="fa-regular fa-copy"></i></button>` : ''}
                        </div>
                    </div>
                </div>
            `;
        });

        html += `</div></div>`;
    }

    el.innerHTML = html;
    showToast('success', 'Analyse Terminée', 'Rapport généré avec succès');
}

function copyToClipboard(text) {
    if(!text || text === 'N/A') return;
    navigator.clipboard.writeText(text).then(() => {
        showToast('success', 'Copié !', `${text} copié dans le presse-papier`);
    }).catch(err => {
        showToast('error', 'Erreur', 'Impossible de copier');
    });
}

function parseEmailContact(rawValue) {
    const value = (rawValue || '').trim();
    if(!value || value === 'N/A') {
        return { name: 'N/A', email: '' };
    }

    const angleMatch = value.match(/^(.*)<([^>]+)>$/);
    if (angleMatch) {
        const name = angleMatch[1].trim().replace(/^"|"$/g, '');
        const email = angleMatch[2].trim();
        return {
            name: name || email,
            email: email
        };
    }

    const emailMatch = value.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
    if (emailMatch) {
        const email = emailMatch[0].trim();
        return {
            name: email,
            email: email
        };
    }

    return {
        name: value,
        email: ''
    };
}

function renderAttachmentResult(data) {
    const el = document.getElementById('attachmentResult');
    const mode = data.mode || 'analysis';
    const f = data.file || {};
    const vt = data.virustotal || {};
    const ha = data.hybrid_analysis || {};
    const apiStatus = data.api_status || {};

    if (mode === 'hash') {
        const inputHash = data.input_hash || data.hash || 'N/A';
        const hashType = data.hash_type || 'hash';
        let html = `
            <div class="result-card">
                <div class="result-header"><i class="fa-solid fa-fingerprint"></i> Hash collé</div>
                <div class="result-body">
                    <div class="stats-grid">
                        <div class="stat-item"><span class="stat-label">TYPE</span><span class="stat-value">${hashType.toUpperCase()}</span></div>
                        <div class="stat-item"><span class="stat-label">HASH</span><span class="stat-value mono" style="word-break:break-all;">${inputHash}</span></div>
                    </div>
                </div>
            </div>
        `;

        // Afficher les messages d'alerte pour les APIs non configurées
        if (!apiStatus.virustotal_available) {
            showToast('warning', 'VirusTotal non configuré', 'La clé API VirusTotal n\'est pas définie. Configurez-la pour activer cette vérification.');
        }
        if (!apiStatus.hybrid_analysis_available) {
            showToast('warning', 'Hybrid Analysis non configuré', 'La clé API Hybrid Analysis n\'est pas définie. Configurez-la pour activer cette vérification.');
        }

        if (vt) {
            html += `<div class="result-card">
                <div class="result-header"><i class="fa-solid fa-bug"></i> Vérification VirusTotal</div>
                <div class="result-body">`;

            if (vt.error) {
                // Si API non disponible, afficher un message spécifique
                if (!apiStatus.virustotal_available) {
                    html += `<div style="padding:15px; background-color:rgba(255,193,7,0.1); border:1px solid var(--warning); border-radius:var(--radius); color:var(--warning);">
                        <strong><i class="fa-solid fa-exclamation-triangle"></i> API non configurée</strong>
                        <p style="margin-top:8px; font-size:0.9em;">Clé API VirusTotal manquante ou invalide. Cette vérification n'a pas pu être exécutée.</p>
                    </div>`;
                } else {
                    html += `<div class="api-error-box">${vt.error}</div>`;
                }
            } else {
                html += `
                    <div style="margin-bottom:10px;">
                        ${buildVerdictBox(vt.verdict, buildVtStats(vt.stats))}
                    </div>
                    ${vt.url ? `<div style="margin-top:10px;"><a href="${vt.url}" target="_blank" class="text-primary">Ouvrir le rapport VirusTotal</a></div>` : ''}
                `;
            }

            html += `</div></div>`;
        }

        if (ha && Object.keys(ha).length > 0) {
            html += `<div class="result-card">
                <div class="result-header"><i class="fa-solid fa-flask-vial"></i> Hybrid Analysis</div>
                <div class="result-body">
                    <div class="stat-item">`;

            if (ha.error) {
                // Si API non disponible, afficher un message spécifique
                if (!apiStatus.hybrid_analysis_available) {
                    html += `<div style="padding:15px; background-color:rgba(255,193,7,0.1); border:1px solid var(--warning); border-radius:var(--radius); color:var(--warning);">
                        <strong><i class="fa-solid fa-exclamation-triangle"></i> API non configurée</strong>
                        <p style="margin-top:8px; font-size:0.9em;">Clé API Hybrid Analysis manquante ou invalide. Cette vérification n'a pas pu être exécutée.</p>
                    </div>`;
                } else {
                    html += `<div class="api-error-box">${ha.error}</div>`;
                }
            } else {
                html += `
                    <div style="display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:10px;">
                        <span class="badge ${ha.verdict ? 'badge-' + ha.verdict.toLowerCase() : 'badge-neutral'}">${(ha.verdict || 'UNKNOWN').toUpperCase()}</span>
                        ${ha.sha256 ? `<span class="text-muted text-sm mono" style="word-break:break-all;">${ha.sha256.substring(0, 16)}...</span>` : ''}
                    </div>
                    ${ha.threat_level !== undefined ? `<div style="margin-top:8px;"><strong>Niveau de menace:</strong> ${ha.threat_level}</div>` : ''}
                    ${ha.summary ? `<div style="margin-top:8px; color:var(--text-muted);">${ha.summary}</div>` : ''}
                    ${ha.report_url ? `<div style="margin-top:10px;"><a href="${ha.report_url}" target="_blank" class="btn btn-primary" style="display:inline-block;"><i class="fa-solid fa-up-right-from-square"></i> Voir le rapport</a></div>` : ''}
                    ${ha.report_url ? buildSourceLinks([{ label: 'Ouvrir Hybrid Analysis', url: ha.report_url, icon: 'fa-up-right-from-square' }]) : ''}
                `;
            }

            html += `</div></div></div>`;
        }

        el.innerHTML = html;
        const toastMsg = (!apiStatus.virustotal_available || !apiStatus.hybrid_analysis_available) 
            ? 'Hash analysé (certaines APIs non configurées)'
            : 'Hash analysé';
        showToast('success', toastMsg, 'Vérification complétée.');
        return;
    }
    
    let html = `
        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-file-code"></i> Empreinte Cryptographique</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item"><span class="stat-label">NOM</span><span class="stat-value">${f.file_name || 'N/A'}</span></div>
                    <div class="stat-item"><span class="stat-label">TAILLE</span><span class="stat-value font-mono">${formatBytes(f.file_size)}</span></div>
                </div>
                <div class="stat-item mb-2">
                    <span class="stat-label">SHA256</span>
                    <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                        <span class="stat-value mono">${f.sha256 || 'N/A'}</span>
                        ${f.sha256 ? `<button class="btn btn-icon" onclick="copyToClipboard('${f.sha256}')" title="Copier SHA256"><i class="fa-regular fa-copy"></i></button>` : ''}
                    </div>
                </div>
                <div class="stat-item mb-2">
                    <span class="stat-label">SHA1</span>
                    <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                        <span class="stat-value mono">${f.sha1 || 'N/A'}</span>
                        ${f.sha1 ? `<button class="btn btn-icon" onclick="copyToClipboard('${f.sha1}')" title="Copier SHA1"><i class="fa-regular fa-copy"></i></button>` : ''}
                    </div>
                </div>
                <div class="stat-item">
                    <span class="stat-label">MD5</span>
                    <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                        <span class="stat-value mono">${f.md5 || 'N/A'}</span>
                        ${f.md5 ? `<button class="btn btn-icon" onclick="copyToClipboard('${f.md5}')" title="Copier MD5"><i class="fa-regular fa-copy"></i></button>` : ''}
                    </div>
                </div>
            </div>
        </div>
    `;

    // Afficher les avertissements si les APIs ne sont pas configurées
    if (!apiStatus.virustotal_available || !apiStatus.hybrid_analysis_available) {
        let warnings = [];
        if (!apiStatus.virustotal_available) warnings.push('VirusTotal');
        if (!apiStatus.hybrid_analysis_available) warnings.push('Hybrid Analysis');
        
        html += `<div style="padding:15px; background-color:rgba(255,193,7,0.1); border:1px solid var(--warning); border-radius:var(--radius); color:var(--warning); margin-bottom:15px;">
            <strong><i class="fa-solid fa-exclamation-triangle"></i> APIs non configurées</strong>
            <p style="margin-top:8px; font-size:0.9em;">${warnings.join(', ')} ne sont pas configurés. Les vérifications correspondantes ne seront pas exécutées.</p>
        </div>`;
    }

    const vtHashes = [
        { type: 'sha256', label: 'SHA256', value: f.sha256 },
        { type: 'sha1', label: 'SHA1', value: f.sha1 },
        { type: 'md5', label: 'MD5', value: f.md5 },
    ].filter(item => item.value);

    if (vtHashes.length > 0) {
        html += `<div class="result-card">
            <div class="result-header"><i class="fa-solid fa-bug"></i> Vérification VirusTotal des Hashs</div>
            <div class="result-body">`;

        vtHashes.forEach(item => {
            const result = vt[item.type] || {};
            html += `<div class="stat-item mb-4" style="margin-bottom:15px;">
                <div style="display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap; border-bottom:1px solid var(--border-color); padding-bottom:8px; margin-bottom:10px;">
                    <strong class="font-mono text-primary">${item.label}</strong>
                    <span class="text-muted text-sm mono" style="word-break:break-all;">${item.value}</span>
                </div>`;

            if (result.error) {
                if (!apiStatus.virustotal_available) {
                    html += `<div style="padding:12px; background-color:rgba(255,193,7,0.1); border:1px solid var(--warning); border-radius:var(--radius); color:var(--warning); font-size:0.9em;">
                        <strong><i class="fa-solid fa-exclamation-circle"></i> API non configurée</strong>
                        <p style="margin-top:6px;">Clé API VirusTotal manquante ou invalide. Cette vérification n'a pas pu être exécutée.</p>
                    </div>`;
                } else {
                    html += `<div class="api-error-box">${result.error}</div>`;
                }
            } else {
                html += `
                    <div style="margin-bottom:10px;">
                        ${buildVerdictBox(result.verdict, buildVtStats(result.stats))}
                    </div>
                    ${result.url ? `<div style="margin-top:10px;"><a href="${result.url}" target="_blank" class="text-primary"><i class="fa-solid fa-up-right-from-square"></i> Vérifier sur VirusTotal</a></div>` : ''}
                `;
            }

            html += `</div>`;
        });

        html += `</div></div>`;
    }

    // DISABLED: Any.Run API requires paid plan
    // if (data.anyrun) {
    //     const anyrunStatus = (anyrun.status || (anyrun.error ? 'ERROR' : 'UNKNOWN')).toUpperCase();
    //     html += `<div class="result-card">
    //         <div class="result-header"><i class="fa-solid fa-flask-vial"></i> Any.Run</div>
    // ...
    // }

    if (data.hybrid_analysis) {
        const ha = data.hybrid_analysis || {};
        const haStatus = (ha.state || ha.verdict || (ha.error ? 'ERROR' : 'UNKNOWN')).toUpperCase();
        let haHtml = `<div class="result-card">
            <div class="result-header"><i class="fa-solid fa-flask-vial"></i> Hybrid Analysis Sandbox</div>
            <div class="result-body">
                <div class="stat-item">
                    <div style="display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:10px;">
                        <span class="badge ${ha.error ? 'badge-suspicious' : (ha.verdict ? 'badge-' + ha.verdict.toLowerCase() : 'badge-neutral')}">${haStatus}</span>
                        ${ha.sha256 ? '<span class="text-muted text-sm mono" style="word-break:break-all;">' + ha.sha256.substring(0, 16) + '...</span>' : ''}
                    </div>`;
        
        if (ha.error) {
            if (!apiStatus.hybrid_analysis_available) {
                haHtml += '<div style="padding:12px; background-color:rgba(255,193,7,0.1); border:1px solid var(--warning); border-radius:var(--radius); color:var(--warning); font-size:0.9em;"><strong><i class="fa-solid fa-exclamation-circle"></i> API non configurée</strong><p style="margin-top:6px;">Clé API Hybrid Analysis manquante ou invalide. Cette vérification n\'a pas pu être exécutée.</p></div>';
            } else {
                haHtml += '<div class="api-error-box">' + ha.error + '</div>';
            }
        }
        
        if (ha.verdict) {
            haHtml += '<div style="margin-top:8px;"><strong>Verdict:</strong> ' + ha.verdict + '</div>';
        }
        if (ha.threat_level !== undefined) {
            haHtml += '<div style="margin-top:8px;"><strong>Niveau de menace:</strong> ' + ha.threat_level + '</div>';
        }
        if (ha.report_url) {
            haHtml += '<div style="margin-top:10px;"><a href="' + ha.report_url + '" target="_blank" class="btn btn-primary" style="display:inline-block;"><i class="fa-solid fa-up-right-from-square"></i> Voir le rapport</a></div>';
        }
        
        haHtml += `</div>
            </div>
        </div>`;
        html += haHtml;
    }

    el.innerHTML = html;
    const toastMsg = (!apiStatus.virustotal_available || !apiStatus.hybrid_analysis_available) 
        ? 'Analyse complétée (certaines APIs non configurées)'
        : 'Sandbox OK';
    showToast('success', toastMsg, 'Hashes calculés et analysés.');
}

function renderUrlResult(data) {
    const el = document.getElementById('urlResult');
    const ha = data.hybrid_analysis || {};
    
    let html = `
        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-link"></i> Cible: ${data.url}</div>
            <div class="result-body">
                <div class="stats-grid">
    `;

    // VirusTotal
    if(data.virustotal) {
        html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-bug"></i> VirusTotal</span>`;
        if(data.virustotal.error) html += `<div class="api-error-box">${data.virustotal.error}</div>`;
        else if (data.virustotal.status === 'QUEUED') {
            html += `<div style="margin-top:15px; text-align:center;">
                <span class="badge badge-neutral">En attente</span>
                <p class="text-sm text-muted" style="margin-top:10px;">${data.virustotal.message || 'Analyse URL en cours sur VirusTotal.'}</p>
            </div>`;
        }
        else {
            html += `<div style="margin-top:15px; text-align:center;">
                <span class="badge badge-${(data.virustotal.verdict||'').toLowerCase()}">${data.virustotal.verdict}</span>
                ${buildVtStats(data.virustotal.stats)}
            </div>`;
        }
        html += `${data.virustotal.detail_url ? buildSourceLinks([{ label: 'Ouvrir VirusTotal', url: data.virustotal.detail_url, icon: 'fa-up-right-from-square' }]) : ''}`;
        html += `</div>`;
    }

    // URLScan
    if(data.urlscan) {
        html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-camera"></i> URLScan.io</span>`;
        if(data.urlscan.error) html += `<div class="api-error-box">${data.urlscan.error}</div>`;
        else if(data.urlscan.ready) {
            html += `<div style="margin-top:15px; text-align:center;">
                <span class="badge badge-clean"><i class="fa-solid fa-check"></i> Rapport Prêt</span>
                <p style="margin-top:12px;">
                    <a href="${data.urlscan.result_url}" target="_blank" class="btn btn-primary" style="display:inline-block; margin-top:8px;">
                        <i class="fa-solid fa-external-link"></i> Voir le Rapport
                    </a>
                </p>
            </div>`;
        }
        else {
            const scanId = data.urlscan.scan_id || 'unknown';
            html += `<div style="margin-top:15px; text-align:center;">
                <span class="badge badge-neutral"><i class="fa-solid fa-hourglass-end"></i> Rapport indisponible</span>
                <p class="text-sm text-muted" style="margin-top:10px; font-family:var(--font-mono); font-size:0.8rem;">ID: ${scanId}</p>
                <p class="text-sm" style="margin-top:8px; color:var(--text-muted);">Le rapport n'était pas prêt après 60s. <a href="${data.urlscan.result_url}" target="_blank" style="color:var(--primary);">Réessayer ici</a></p>
            </div>`;
        }
        html += `</div>`;
    }

    // Scamdoc / ScamPredictor
    if(data.scamdoc) {
        html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-user-secret"></i> Scamdoc</span>`;
        html += buildScamdocBox(data.scamdoc);
        html += `${data.scamdoc.detail_url ? buildSourceLinks([{ label: 'Ouvrir Scamdoc', url: data.scamdoc.detail_url, icon: 'fa-up-right-from-square' }]) : ''}`;
        html += `</div>`;
    }

    if(data.hybrid_analysis) {
        const ha = data.hybrid_analysis || {};
        html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-flask-vial"></i> Hybrid Analysis</span>`;
        if(ha.error) {
            html += `<div class="api-error-box">${ha.error}</div>`;
        } else {
            html += `<div style="margin-top:15px; text-align:center;">
                <span class="badge badge-${(ha.verdict || 'neutral').toLowerCase()}">${(ha.verdict || 'UNKNOWN').toUpperCase()}</span>
                ${ha.threat_level !== undefined ? `<p class="text-sm text-muted" style="margin-top:10px;">Niveau de menace: <strong>${ha.threat_level}</strong></p>` : ''}
                ${ha.message ? `<p class="text-sm text-muted" style="margin-top:10px;">${ha.message}</p>` : ''}
                ${ha.report_url ? `<p style="margin-top:12px;"><a href="${ha.report_url}" target="_blank" class="btn btn-primary"><i class="fa-solid fa-external-link"></i> Voir le rapport Hybrid Analysis</a></p>` : ''}
            </div>`;
        }
        html += `</div>`;
    }

    html += `</div></div></div>`;
    el.innerHTML = html;
    showToast('success', 'URL Scannée', 'Informations récupérées');
}

function renderIpResult(data) {
    const el = document.getElementById('ipResult');
    const vt = data.virustotal || {};
    const ab = data.abuseipdb || {};
    const mxPtr = data.mxtoolbox_ptr || {};
    const mxRbl = data.mxtoolbox_rbl || {};

    let html = `
        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-location-dot"></i> IP: <span class="font-mono text-primary ml-2">${data.ip}</span></div>
            <div class="result-body">
                <div class="stats-grid">
    `;

    // MXToolbox PTR
    html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-network-wired"></i> MXToolbox PTR</span>`;
    if(mxPtr.error) html += `<div class="api-error-box">${mxPtr.error}</div>`;
    else if(mxPtr.hostname) {
        html += `<div style="margin-top:15px; text-align:center;">
            <span class="badge badge-clean"><i class="fa-solid fa-check"></i> Reverse DNS</span>
            <p style="margin-top:12px; word-break:break-all; font-family:var(--font-mono); font-size:0.9rem;">${mxPtr.hostname}</p>
        </div>`;
    } else {
        html += `<div style="margin-top:15px; text-align:center; color:var(--text-muted);">
            <span class="badge badge-neutral">Non trouvé</span>
        </div>`;
    }
    html += `${mxPtr.url ? buildSourceLinks([{ label: 'Ouvrir MXToolbox PTR', url: mxPtr.url, icon: 'fa-up-right-from-square' }]) : ''}`;
    html += `</div>`;

    // MXToolbox RBL
    html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-ban"></i> MXToolbox RBL</span>`;
    if(mxRbl.error) html += `<div class="api-error-box">${mxRbl.error}</div>`;
    else if (mxRbl.unavailable) {
        html += `<div style="margin-top:15px; text-align:center; color:var(--text-muted);">
            <span class="badge badge-neutral">Indisponible</span>
            <p class="text-sm text-muted" style="margin-top:8px;">${mxRbl.status || 'MXToolbox RBL indisponible'}</p>
        </div>`;
    } else {
        const isBlacklisted = mxRbl.blacklisted === true;
        const badgeType = isBlacklisted ? 'danger' : 'clean';
        const badgeText = isBlacklisted ? 'LISTÉE' : 'NON LISTÉE';
        html += `<div style="margin-top:15px; text-align:center;">
            <span class="badge badge-${badgeType}">${badgeText}</span>
            <p class="text-sm text-muted" style="margin-top:8px;">${mxRbl.status || 'Status inconnu'}</p>
        </div>`;
    }
    html += `${mxRbl.url ? buildSourceLinks([{ label: 'Ouvrir MXToolbox RBL', url: mxRbl.url, icon: 'fa-up-right-from-square' }]) : ''}`;
    html += `</div>`;

    // AbuseIPDB
    html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-triangle-exclamation"></i> AbuseIPDB</span>`;
    if(ab.error) html += `<div class="api-error-box">${ab.error}</div>`;
    else {
        const score = ab.abuse_confidence_score || 0;
        const color = score > 20 ? 'var(--danger)' : 'var(--success)';
        html += `
            <div style="text-align:center; padding: 20px 0;">
                <div style="font-size:3rem; font-weight:700; color:${color}; line-height:1;">${score}%</div>
                <div style="font-size:0.8rem; color:var(--text-muted); margin-top:5px;">Confidence Score</div>
                <div style="margin-top:15px; font-size:0.85rem;">Signalements: <strong>${ab.total_reports}</strong></div>
            </div>
        `;
    }
    html += `${ab.url ? buildSourceLinks([{ label: 'Ouvrir AbuseIPDB', url: ab.url, icon: 'fa-up-right-from-square' }]) : ''}`;
    html += `</div>`;

    // VirusTotal
    html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-bug"></i> VirusTotal</span>`;
    if(vt.error) html += `<div class="api-error-box">${vt.error}</div>`;
    else {
        html += `<div style="text-align:center; padding-top:10px;">
            <p class="text-sm mb-2">${vt.country || 'Pays Inconnu'} - ASN: ${vt.asn || 'N/A'}</p>
            ${buildVtStats(vt.last_analysis_stats || {})}
        </div>`;
    }
    html += `${vt.url ? buildSourceLinks([{ label: 'Ouvrir VirusTotal', url: vt.url, icon: 'fa-up-right-from-square' }]) : ''}`;
    html += `</div>`;

    html += `</div></div></div>`;
    el.innerHTML = html;
    showToast('success', 'Threat Intel', 'Données de réputation chargées');
}

// ------------------------------------------------------------------
// HELPER FUNCTIONS
// ------------------------------------------------------------------

// UI Feedback - SOC Professional Style
function showLoader(containerId) {
    getElement(containerId).innerHTML = `
        <div class="loader-container">
            <div class="spinner"></div>
            <p style="color: var(--primary); font-family: var(--font-mono); font-size: 0.85rem; letter-spacing:1px; margin:16px 0 0 0;">ANALYZING</p>
        </div>
    `;
}

function showError(containerId) {
    getElement(containerId).innerHTML = `
        <div style="padding:48px 32px; text-align:center; color: var(--danger);">
            <i class="fa-solid fa-triangle-exclamation" style="font-size:2.5rem; margin-bottom:16px; display:block;"></i>
            <p style="font-size:0.95rem; margin:0; font-weight:500;">Analysis Failed</p>
            <p style="font-size:0.8rem; color:var(--text-muted); margin:8px 0 0 0;">Please check your input and try again</p>
        </div>
    `;
}

function showToast(type, title, msg) {
    const container = getElement('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = { success: 'fa-circle-check', error: 'fa-shield-virus', info: 'fa-circle-info' };
    const icon = icons[type] || icons.info;
    
    toast.innerHTML = `
        <div class="toast-icon"><i class="fa-solid ${icon}"></i></div>
        <div class="toast-content">
            <h4 style="margin:0; font-size:0.9rem; font-weight:600;">${title}</h4>
            <p style="margin:4px 0 0 0; font-size:0.8rem; opacity:0.9;">${msg}</p>
        </div>
    `;
    
    container.appendChild(toast);
    
    const hideTimer = setTimeout(() => {
        toast.style.animation = 'fadeOut 0.25s cubic-bezier(0.4, 0, 0.2, 1) forwards';
        setTimeout(() => toast.remove(), 250);
    }, 3500);
    
    // Cancel auto-hide on hover
    toast.addEventListener('mouseenter', () => clearTimeout(hideTimer));
}

function formatBytes(bytes) {
    if(!bytes) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function buildSecurityBadge(label, status, detail) {
    let statCls = 'badge-neutral';
    if(status) {
        if(status.toLowerCase().includes('pass') || status.toLowerCase().includes('present')) statCls = 'badge-clean';
        else if(status.toLowerCase().includes('fail') || status.toLowerCase().includes('none')) statCls = 'badge-suspicious';
    }
    return `
        <div class="stat-item">
            <span class="stat-label">${label}</span>
            <span class="badge ${statCls} mb-2 inline-block">${status || 'N/A'}</span>
            <div style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted); word-break: break-all;">
                ${detail || 'Aucune donnée'}
            </div>
        </div>
    `;
}

function buildVtStats(stats) {
    if(!stats) return '';
    return `
        <div class="vt-stats-row">
            <div class="vt-stat c-danger"><span class="num">${stats.malicious || 0}</span><span class="txt">Malicious</span></div>
            <div class="vt-stat c-warning"><span class="num">${stats.suspicious || 0}</span><span class="txt">Suspicious</span></div>
            <div class="vt-stat c-success"><span class="num">${stats.undetected || 0}</span><span class="txt">Clean</span></div>
        </div>
    `;
}

function buildVerdictBox(verdict, statsHtml) {
    verdict = verdict || 'UNKNOWN';
    const vLower = verdict.toLowerCase();
    const cleanCls = vLower === 'clean' ? 'verdict-clean' : (vLower === 'malicious' ? 'verdict-malicious' : 'verdict-suspicious');
    
    let icon = 'fa-shield';
    if(vLower==='clean') icon = 'fa-shield-halved';
    if(vLower==='malicious') icon = 'fa-biohazard';

    return `
        <div class="verdict-box ${cleanCls}">
            <i class="fa-solid ${icon} verdict-icon"></i>
            <h3 style="margin-bottom:10px; font-family:var(--font-heading);">${verdict}</h3>
            ${statsHtml}
        </div>
    `;
}

function buildScamdocBox(result) {
    result = result || {};
    if (result.status === 'UNAVAILABLE') {
        return `<div style="text-align:center; padding-top:8px;">
            <span class="badge badge-neutral">INDISPONIBLE</span>
            <div style="margin-top:10px; font-size:0.85rem; color:var(--text-muted);">
                Scamdoc n'a pas répondu via l'API RapidAPI.
            </div>
            ${result.public_url ? `<div style="margin-top:10px;"><a href="${result.public_url}" target="_blank" class="text-primary">Ouvrir Scamdoc</a></div>` : ''}
        </div>`;
    }
    if (result.error) {
        const errorText = (result.error || '').toLowerCase();
        if (errorText.includes('timed out')) {
            return `<div style="text-align:center; padding-top:8px;">
                <span class="badge badge-neutral">EN COURS</span>
                <div style="margin-top:10px; font-size:0.85rem; color:var(--text-muted);">
                    Scamdoc met du temps à répondre. Réessaie dans quelques secondes.
                </div>
            </div>`;
        }
        if (errorText.includes('indisponible')) {
            return `<div style="text-align:center; padding-top:8px;">
                <span class="badge badge-neutral">INDISPONIBLE</span>
                <div style="margin-top:10px; font-size:0.85rem; color:var(--text-muted);">
                    Scamdoc n'a pas pu être interrogé pour cet élément.
                </div>
            </div>`;
        }
        return `<div class="api-error-box">${result.error}</div>`;
    }

    const verdict = (result.verdict || 'UNKNOWN').toUpperCase();
    const badgeClass = verdict === 'MALICIOUS'
        ? 'badge-malicious'
        : (verdict === 'SUSPICIOUS' ? 'badge-suspicious' : (verdict === 'CLEAN' ? 'badge-clean' : 'badge-neutral'));

    const trust = result.trust_score;
    const risk = result.risk_score;

    return `
        <div style="text-align:center; padding-top:8px;">
            <span class="badge ${badgeClass}">${verdict}</span>
            <div style="margin-top:10px; font-size:0.85rem; color:var(--text-muted);">
                <div>Trust Score: ${trust !== null && trust !== undefined ? Math.round(trust) + '%' : 'N/A'}</div>
                <div>Risk Score: ${risk !== null && risk !== undefined ? Math.round(risk) + '%' : 'N/A'}</div>
            </div>
            ${result.detail_url ? `<div style="margin-top:10px;"><a href="${result.detail_url}" target="_blank" class="text-primary">Voir détails</a></div>` : ''}
        </div>
    `;
}

function buildSourceLinks(items) {
    const validItems = (items || []).filter(item => item && item.url);
    if (validItems.length === 0) return '';

    return `
        <div style="display:flex; flex-wrap:wrap; gap:8px; margin-top:12px;">
            ${validItems.map(item => `
                <a href="${item.url}" target="_blank" class="badge badge-neutral" style="text-decoration:none; display:inline-flex; align-items:center; gap:6px;">
                    ${item.icon ? `<i class="fa-solid ${item.icon}"></i>` : ''}
                    ${escapeHtml(item.label || 'Voir la source')}
                </a>
            `).join('')}
        </div>
    `;
}

// Load Dashboard
function loadDashboard() {
    const dashboardSummary = document.getElementById('dashboardSummary');
    if(!dashboardSummary) return;
    
    dashboardSummary.innerHTML = `
        <div class="loader-container">
            <div class="spinner"></div>
            <p style="color: var(--primary); font-family: var(--font-mono); font-size: 0.9rem;">[ CHARGEMENT DES STATISTIQUES... ]</p>
        </div>
    `;
    
    fetch('/api/dashboard')
        .then(res => res.json())
        .then(data => {
            const totals = data.totals || {emails: 0, attachments: 0, ips: 0, urls: 0};
            const latestEmail = data.latest_email || {};
            
            let html = `
                <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:15px; margin-bottom:30px;">
                    <div style="padding:20px; background:rgba(147, 112, 219, 0.1); border-radius:8px; border:1px solid rgba(147, 112, 219, 0.3); text-align:center;">
                        <i class="fa-solid fa-envelope" style="font-size:2rem; color:#9370DB; margin-bottom:10px;"></i>
                        <div style="font-size:2rem; font-weight:700; color:var(--text-primary);">${totals.emails}</div>
                        <div style="font-size:0.85rem; color:var(--text-muted); margin-top:5px;">Emails Analysés</div>
                    </div>
                    
                    <div style="padding:20px; background:rgba(52, 152, 219, 0.1); border-radius:8px; border:1px solid rgba(52, 152, 219, 0.3); text-align:center;">
                        <i class="fa-solid fa-file" style="font-size:2rem; color:#3498DB; margin-bottom:10px;"></i>
                        <div style="font-size:2rem; font-weight:700; color:var(--text-primary);">${totals.attachments}</div>
                        <div style="font-size:0.85rem; color:var(--text-muted); margin-top:5px;">Fichiers Scannés</div>
                    </div>
                    
                    <div style="padding:20px; background:rgba(46, 204, 113, 0.1); border-radius:8px; border:1px solid rgba(46, 204, 113, 0.3); text-align:center;">
                        <i class="fa-solid fa-link" style="font-size:2rem; color:#2ECC71; margin-bottom:10px;"></i>
                        <div style="font-size:2rem; font-weight:700; color:var(--text-primary);">${totals.urls}</div>
                        <div style="font-size:0.85rem; color:var(--text-muted); margin-top:5px;">URLs Vérifiées</div>
                    </div>
                    
                    <div style="padding:20px; background:rgba(230, 126, 34, 0.1); border-radius:8px; border:1px solid rgba(230, 126, 34, 0.3); text-align:center;">
                        <i class="fa-solid fa-server" style="font-size:2rem; color:#E67E22; margin-bottom:10px;"></i>
                        <div style="font-size:2rem; font-weight:700; color:var(--text-primary);">${totals.ips}</div>
                        <div style="font-size:0.85rem; color:var(--text-muted); margin-top:5px;">IPs Analysées</div>
                    </div>
                </div>
            `;
            
            // Latest Email Info
            if(latestEmail.sender || latestEmail.subject) {
                html += `
                    <div style="padding:15px; background:rgba(255,255,255,0.05); border-radius:8px; border-left:4px solid var(--primary); margin-bottom:15px;">
                        <p style="font-size:0.85rem; color:var(--text-muted); margin:0 0 5px 0;">📧 Dernier Email</p>
                        <p style="font-size:0.9rem; color:var(--text-primary); margin:0 0 3px 0; word-break:break-all;"><strong>${latestEmail.sender || 'N/A'}</strong></p>
                        <p style="font-size:0.85rem; color:var(--text-muted); margin:0; word-break:break-all;">${latestEmail.subject || 'N/A'}</p>
                        <p style="font-size:0.8rem; color:var(--text-muted); margin:5px 0 0 0;">${latestEmail.date || 'N/A'}</p>
                    </div>
                `;
            }
            
            dashboardSummary.innerHTML = html;
        })
        .catch(err => {
            console.error('Dashboard load error:', err);
            dashboardSummary.innerHTML = `
                <div style="text-align:center; padding:40px; color:var(--danger);">
                    <i class="fa-solid fa-triangle-exclamation" style="font-size:2rem; margin-bottom:10px;"></i>
                    <p>Erreur lors du chargement du résumé</p>
                </div>
            `;
        });
}

// Custom Dropdown Functions
let currentHistoryFilter = '';

function toggleHistoryFilter(e) {
    e.preventDefault();
    const menu = document.getElementById('historyFilterMenu');
    menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
}

function selectHistoryFilter(value) {
    currentHistoryFilter = value;
    const btn = document.querySelector('#historyFilterDropdown .dropdown-btn');
    const menu = document.getElementById('historyFilterMenu');
    
    // Update button text
    const items = {
        '': 'Tous les types',
        'email': '📧 Emails',
        'attachment': '📁 Fichiers',
        'url': '🔗 URLs',
        'ip': '🖥️ IPs'
    };
    btn.innerHTML = `${items[value]} <i class="fa-solid fa-chevron-down"></i>`;
    menu.style.display = 'none';
    
    loadHistory();
}

// Debounce utility for input optimization
function debounce(func, delay) {
    let timeoutId;
    return function(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func(...args), delay);
    };
}

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('historyFilterDropdown');
    if(dropdown && !dropdown.contains(e.target)) {
        document.getElementById('historyFilterMenu').style.display = 'none';
    }
});

// Load History
function loadHistory() {
    const historyList = document.getElementById('historyList');
    const filterValue = currentHistoryFilter;
    
    if(!historyList) return;
    
    historyList.innerHTML = `
        <div class="loader-container">
            <div class="spinner"></div>
            <p style="color: var(--primary); font-family: var(--font-mono); font-size: 0.9rem;">[ CHARGEMENT DE L'HISTORIQUE... ]</p>
        </div>
    `;
    
    fetch('/api/history?limit=50')
        .then(res => res.json())
        .then(data => {
            if(!data || data.length === 0) {
                historyList.innerHTML = `
                    <div style="text-align:center; padding:40px; color:var(--text-muted);">
                        <i class="fa-solid fa-inbox" style="font-size:2rem; margin-bottom:10px; opacity:0.5;"></i>
                        <p>Aucune analyse enregistrée</p>
                        <p style="font-size:0.9rem;">Vos analyses apparaîtront ici</p>
                    </div>
                `;
                return;
            }
            
            // Filter by type if selected
            let filtered = data;
            if(filterValue) {
                filtered = data.filter(item => {
                    const itemType = (item.analysis_type || item.type || '').toLowerCase();
                    // Check if attachment/file types match
                    if(filterValue === 'attachment' && (itemType.includes('attachment') || itemType.includes('file'))) return true;
                    return itemType.includes(filterValue.toLowerCase());
                });
            }
            
            if(filtered.length === 0) {
                historyList.innerHTML = `
                    <div style="text-align:center; padding:40px; color:var(--text-muted);">
                        <p>Aucune analyse trouvée pour ce filtre</p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            
            filtered.forEach(item => {
                const analysisType = (item.analysis_type || item.type || 'unknown').toLowerCase();
                const target = item.target || item.title || item.email || item.ip || item.url || item.file_hash || 'N/A';
                const detail = item.detail || item.subject || item.hash_type || '';
                const verdict = item.verdict || (item.data && item.data.verdict) || 'N/A';
                const timestamp = item.timestamp || item.date || 'N/A';
                
                let icon = 'circle';
                let typeLabel = 'Analyse';
                if(analysisType.includes('email')) {
                    icon = 'envelope';
                    typeLabel = '📧 Email';
                } else if(analysisType.includes('attachment') || analysisType.includes('file')) {
                    icon = 'file';
                    typeLabel = '📁 Fichier';
                } else if(analysisType.includes('url')) {
                    icon = 'link';
                    typeLabel = '🔗 URL';
                } else if(analysisType.includes('ip')) {
                    icon = 'server';
                    typeLabel = '🖥️ IP';
                }
                
                let badgeClass = 'badge-neutral';
                if(verdict && verdict.toUpperCase() === 'MALICIOUS') badgeClass = 'badge-danger';
                else if(verdict && verdict.toUpperCase() === 'SUSPICIOUS') badgeClass = 'badge-warning';
                else if(verdict && verdict.toUpperCase() === 'CLEAN') badgeClass = 'badge-success';
                
                // Build display text with better formatting for files
                let displayText = target;
                let secondLine = '';
                
                if(analysisType.includes('attachment') || analysisType.includes('file')) {
                    // For files: show truncated hash
                    const maxHashLength = 20;
                    let displayHash = target;
                    if(target.length > maxHashLength) {
                        displayHash = target.substring(0, 10) + '...' + target.substring(target.length - 10);
                    }
                    displayText = displayHash;
                    if(detail) {
                        secondLine = `<span style="font-size:0.75rem; color:var(--text-dimmed); text-transform:uppercase; letter-spacing:0.5px;">${detail}</span>`;
                    }
                } else if(detail && detail !== 'URL' && detail !== 'IP' && detail !== 'Email') {
                    displayText = `${target}`;
                    secondLine = `<span style="font-size:0.8rem; color:var(--text-muted); opacity:0.8;">${detail}</span>`;
                }
                
                html += `
                    <div style="padding:15px; border-bottom:1px solid rgba(255,255,255,0.1); display:flex; justify-content:space-between; align-items:flex-start; gap:20px;">
                        <div style="flex:1; min-width:0;">
                            <div style="display:flex; align-items:center; gap:10px; margin-bottom:6px;">
                                <strong>${typeLabel}</strong>
                            </div>
                            <p style="font-size:0.85rem; color:var(--primary); margin:0 0 4px 0; word-break:break-all; font-family:var(--font-mono); font-weight:500;">${displayText}</p>
                            ${secondLine ? `<div style="margin-bottom:4px;">${secondLine}</div>` : ''}
                            <p style="font-size:0.8rem; color:var(--text-muted); margin:0; opacity:0.7;">${timestamp}</p>
                        </div>
                        <span class="badge ${badgeClass}" style="white-space:nowrap; flex-shrink:0; font-size:0.85rem;">
                            ${verdict.toUpperCase()}
                        </span>
                    </div>
                `;
            });
            
            historyList.innerHTML = html;
        })
        .catch(err => {
            console.error('History load error:', err);
            historyList.innerHTML = `
                <div style="text-align:center; padding:40px; color:var(--danger);">
                    <i class="fa-solid fa-triangle-exclamation" style="font-size:2rem; margin-bottom:10px;"></i>
                    <p>Erreur lors du chargement de l'historique</p>
                </div>
            `;
        });
}
