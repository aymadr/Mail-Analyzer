/**
 * sec-ops Frontend Logic
 */

// Tab Configuration logic
const tabConfig = {
    email: { title: "Inspecteur d'Email", desc: "Parse automatiquement les en-têtes SPF, DKIM, DMARC et analyse les IPs" },
    attachment: { title: "Sandbox Pièce Jointe", desc: "Calcul de Hash (SHA256, MD5) & Vérification Virustotal" },
    url: { title: "Scanner d'URL", desc: "Vérification réputation VirusTotal et empreinte URLScan" },
    ip: { title: "Threat Intel IP", desc: "Consultation croisée VirusTotal & AbuseIPDB" },
    history: { title: "Historique & Logs", desc: "Archives des analyses enregistrées dans la DB locale" }
};

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initDragAndDrop('emailDropZone', 'emailFile', 'emailFileName');
    initDragAndDrop('attachDropZone', 'attachmentFile', 'attachFileName');
});

// Navigation / Tabs
function initTabs() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.dataset.tab;
            
            // UI Active State
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            
            // Header Text update
            document.getElementById('active-tab-title').innerHTML = tabConfig[target].title;
            document.getElementById('active-tab-desc').innerHTML = tabConfig[target].desc;
            
            // Hide all panels, show target
            document.querySelectorAll('.view-panel').forEach(p => {
                p.classList.remove('active', 'fade-in');
                p.classList.add('hidden');
            });
            const targetPanel = document.getElementById(target);
            targetPanel.classList.remove('hidden');
            // Trigger reflow for animation
            void targetPanel.offsetWidth; 
            targetPanel.classList.add('active', 'fade-in');

            // Load history dynamically
            if(target === 'history') loadHistory();
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
document.getElementById('emailForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = document.getElementById('emailFile').files[0];
    if (!file) return showToast('error', 'Erreur', 'Veuillez sélectionner un fichier email.');
    
    const formData = new FormData();
    formData.append('file', file);
    
    showLoader('emailResult');
    try {
        const res = await fetch('/api/analyze/email', { method: 'POST', body: formData });
        const data = await res.json();
        if (res.ok) renderEmailResult(data);
        else throw new Error(data.error || 'Erreur serveur');
    } catch (err) {
        showError('emailResult');
        showToast('error', 'Échec de l\'analyse', err.message);
    }
});

// 2. Attachment Submit
document.getElementById('attachmentForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = document.getElementById('attachmentFile').files[0];
    if (!file) return showToast('error', 'Erreur', 'Veuillez sélectionner un fichier.');
    
    const formData = new FormData();
    formData.append('file', file);
    
    showLoader('attachmentResult');
    try {
        const res = await fetch('/api/analyze/attachment', { method: 'POST', body: formData });
        const data = await res.json();
        if (res.ok) renderAttachmentResult(data);
        else throw new Error(data.error || 'Erreur serveur');
    } catch (err) {
        showError('attachmentResult');
        showToast('error', 'Échec de l\'analyse', err.message);
    }
});

// 3. URL Submit
document.getElementById('urlForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('urlInput').value;
    
    showLoader('urlResult');
    try {
        const res = await fetch('/api/analyze/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        if (res.ok) renderUrlResult(data);
        else throw new Error(data.error || 'Erreur serveur');
    } catch (err) {
        showError('urlResult');
        showToast('error', 'Échec de l\'analyse', err.message);
    }
});

// 4. IP Submit
document.getElementById('ipForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = document.getElementById('ipInput').value;
    
    showLoader('ipResult');
    try {
        const res = await fetch('/api/analyze/ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if (res.ok) renderIpResult(data);
        else throw new Error(data.error || 'Erreur serveur');
    } catch (err) {
        showError('ipResult');
        showToast('error', 'Échec de l\'analyse', err.message);
    }
});

// 5. History
async function loadHistory() {
    const list = document.getElementById('historyList');
    list.innerHTML = '<div class="loader-container"><div class="spinner"></div><p>Chargement des logs...</p></div>';
    try {
        const res = await fetch('/api/history');
        const data = await res.json();
        
        if (data.length === 0) {
            list.innerHTML = '<div style="text-align:center; padding: 40px; color: var(--text-muted);"><i class="fa-solid fa-ghost text-4xl mb-4"></i><p>Aucune analyse en base de données.</p></div>';
            return;
        }

        let html = '';
        data.forEach(item => {
            const dateStr = new Date(item.date).toLocaleString('fr-FR');
            html += `
                <div class="history-item">
                    <div class="h-info">
                        <h4><i class="fa-solid fa-envelope mr-2"></i>${item.sender || 'Sender Inconnu'}</h4>
                        <p>${item.subject || 'Sans Sujet'}</p>
                    </div>
                    <div class="h-date">${dateStr}</div>
                </div>
            `;
        });
        list.innerHTML = html;
    } catch (error) {
        list.innerHTML = `<div class="api-error-box"><i class="fa-solid fa-triangle-exclamation"></i> Impossible de charger l'historique</div>`;
    }
}


// ------------------------------------------------------------------
// RENDERERS (Stylized HTML injects)
// ------------------------------------------------------------------

function renderEmailResult(data) {
    const el = document.getElementById('emailResult');
    const eInfo = data.email || {};
    
    let html = `
        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-envelope-open"></i> Metadonnées</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item"><span class="stat-label">EXPÉDITEUR</span><span class="stat-value">${eInfo.from || 'N/A'}</span></div>
                    <div class="stat-item"><span class="stat-label">DESTINATAIRE</span><span class="stat-value">${eInfo.to || 'N/A'}</span></div>
                    <div class="stat-item"><span class="stat-label">DATE</span><span class="stat-value">${eInfo.date || 'N/A'}</span></div>
                    <div class="stat-item"><span class="stat-label">SUJET</span><span class="stat-value">${eInfo.subject || 'N/A'}</span></div>
                </div>
            </div>
        </div>

        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-shield-halved"></i> Vérifications de Sécurité</div>
            <div class="result-body">
                <div class="stats-grid">
                    ${buildSecurityBadge('SPF', eInfo.spf?.status, eInfo.spf?.record)}
                    ${buildSecurityBadge('DKIM', eInfo.dkim?.status, eInfo.dkim?.domain)}
                    ${buildSecurityBadge('DMARC', eInfo.dmarc?.status, eInfo.dmarc?.policy)}
                </div>
            </div>
        </div>
    `;

    if(data.ips && data.ips.length > 0) {
        html += `<div class="result-card">
            <div class="result-header"><i class="fa-solid fa-network-wired"></i> Analyse des Routages (IPs)</div>
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
        html += `</div></div>`;
    }

    el.innerHTML = html;
    showToast('success', 'Analyse Terminée', 'Rapport généré avec succès');
}

function renderAttachmentResult(data) {
    const el = document.getElementById('attachmentResult');
    const f = data.file || {};
    
    let html = `
        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-file-code"></i> Empreinte Cryptographique</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item"><span class="stat-label">NOM</span><span class="stat-value">${f.file_name}</span></div>
                    <div class="stat-item"><span class="stat-label">TAILLE</span><span class="stat-value font-mono">${formatBytes(f.file_size)}</span></div>
                </div>
                <div class="stat-item mb-2"><span class="stat-label">SHA256</span><span class="stat-value mono">${f.sha256}</span></div>
                <div class="stat-item"><span class="stat-label">MD5</span><span class="stat-value mono">${f.md5}</span></div>
            </div>
        </div>
    `;

    if (data.virustotal && data.virustotal.sha256) {
        const vt = data.virustotal.sha256;
        if(vt.error) {
            html += `<div class="result-card"><div class="result-header"><i class="fa-solid fa-bug"></i> VirusTotal</div><div class="result-body"><div class="api-error-box">${vt.error}</div></div></div>`;
        } else {
            html += `
                <div class="result-card">
                    <div class="result-header"><i class="fa-solid fa-bug"></i> VirusTotal Scan</div>
                    <div class="result-body">
                        ${buildVerdictBox(vt.verdict, buildVtStats(vt.stats))}
                    </div>
                </div>
            `;
        }
    }

    el.innerHTML = html;
    showToast('success', 'Sandbox OK', 'Hashs calculés et analysés.');
}

function renderUrlResult(data) {
    const el = document.getElementById('urlResult');
    
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
        else {
            html += `<div style="margin-top:15px; text-align:center;">
                <span class="badge badge-${(data.virustotal.verdict||'').toLowerCase()}">${data.virustotal.verdict}</span>
                ${buildVtStats(data.virustotal.stats)}
            </div>`;
        }
        html += `</div>`;
    }

    // URLScan
    if(data.urlscan) {
        html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-camera"></i> URLScan.io</span>`;
        if(data.urlscan.error) html += `<div class="api-error-box">${data.urlscan.error}</div>`;
        else {
            html += `<div style="margin-top:15px; text-align:center;">
                <span class="badge badge-clean">Scan Envoyé</span><br><br>
                <a href="${data.urlscan.result_url}" target="_blank" class="btn btn-outline" style="font-size:0.8rem; padding: 5px 10px;">Voir le rapport</a>
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

    let html = `
        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-location-dot"></i> IP: <span class="font-mono text-primary ml-2">${data.ip}</span></div>
            <div class="result-body">
                <div class="stats-grid">
    `;

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
    html += `</div>`;

    html += `</div></div></div>`;
    el.innerHTML = html;
    showToast('success', 'Threat Intel', 'Données de réputation chargées');
}

// ------------------------------------------------------------------
// HELPER FUNCTIONS
// ------------------------------------------------------------------

function showLoader(containerId) {
    document.getElementById(containerId).innerHTML = `
        <div class="loader-container">
            <div class="spinner"></div>
            <p style="color: var(--primary); font-family: var(--font-mono); font-size: 0.9rem;">[ EN COURS D'ANALYSE... ]</p>
        </div>
    `;
}

function showError(containerId) {
    document.getElementById(containerId).innerHTML = `
        <div style="padding:40px; text-align:center; color: var(--danger);">
            <i class="fa-solid fa-triangle-exclamation text-4xl mb-4"></i>
            <p>Une erreur critique est survenue lors de l'analyse.</p>
        </div>
    `;
}

function showToast(type, title, msg) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon = 'fa-circle-info';
    if(type === 'success') icon = 'fa-circle-check';
    if(type === 'error') icon = 'fa-shield-virus';
    
    toast.innerHTML = `
        <div class="toast-icon"><i class="fa-solid ${icon}"></i></div>
        <div class="toast-content">
            <h4>${title}</h4>
            <p>${msg}</p>
        </div>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'fadeOutRight 0.3s cubic-bezier(0.4, 0, 0.2, 1) forwards';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
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
