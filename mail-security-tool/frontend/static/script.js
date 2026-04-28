/**
 * sec-ops Frontend Logic
 */

// Tab Configuration logic
const tabConfig = {
    dashboard: { title: "Dashboard Sécurité", desc: "Bienvenue dans SecAnalyze - Choisissez une analyse pour commencer" },
    email: { title: "Inspecteur d'Email", desc: "Parse automatiquement les en-têtes SPF, DKIM, DMARC et analyse les IPs" },
    attachment: { title: "Sandbox Pièce Jointe", desc: "Calcul de Hash (SHA256, MD5) & Vérification Virustotal + Any.Run si activé" },
    url: { title: "Scanner d'URL", desc: "Vérification réputation VirusTotal, Scamdoc et empreinte URLScan" },
    ip: { title: "Threat Intel IP", desc: "Consultation croisée VirusTotal & AbuseIPDB" },
    text: { title: "Analyse de Texte", desc: "Détecte les patterns de phishing: formules, fautes, URLs suspectes" },
    history: { title: "Historique des Analyses", desc: "Archives des analyses enregistrées dans la DB locale avec filtres" }
};

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
    
    // Form event listeners
    document.getElementById('textForm').addEventListener('submit', analyzeText);
});

// Function to programmatically switch tabs
function switchTab(tabName) {
    const navItem = document.querySelector(`[data-tab="${tabName}"]`);
    if(navItem) navItem.click();
}

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

        const typeMeta = {
            email: { icon: 'fa-envelope', label: 'Email' },
            attachment: { icon: 'fa-file-shield', label: 'Pièce jointe' },
            ip: { icon: 'fa-network-wired', label: 'IP' },
            url: { icon: 'fa-link', label: 'URL' }
        };

        let html = '';
        data.forEach(item => {
            const meta = typeMeta[item.type] || { icon: 'fa-circle-info', label: item.type || 'Analyse' };
            const dateStr = new Date(item.date).toLocaleString('fr-FR');
            html += `
                <div class="history-item">
                    <div class="h-info">
                        <h4><i class="fa-solid ${meta.icon} mr-2"></i>${meta.label} - ${item.title || 'Sans titre'}</h4>
                        <p>${item.detail || 'Aucun détail'}</p>
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

// 6. Dashboard
async function loadDashboard() {
    const panel = document.getElementById('dashboardSummary');
    panel.innerHTML = '<div class="loader-container"><div class="spinner"></div><p>Chargement du rapport...</p></div>';

    try {
        const res = await fetch('/api/dashboard');
        const data = await res.json();

        const totals = data.totals || {};
        const latest = data.latest_email || {};
        const recent = data.recent || [];

        let html = `
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item"><span class="stat-label">EMAILS ANALYSÉS</span><span class="stat-value">${totals.emails || 0}</span></div>
                    <div class="stat-item"><span class="stat-label">PIÈCES JOINTES</span><span class="stat-value">${totals.attachments || 0}</span></div>
                    <div class="stat-item"><span class="stat-label">IPS ANALYSÉES</span><span class="stat-value">${totals.ips || 0}</span></div>
                    <div class="stat-item"><span class="stat-label">URLS ANALYSÉES</span><span class="stat-value">${totals.urls || 0}</span></div>
                </div>
                <div class="stat-item" style="margin-top:12px;">
                    <span class="stat-label">DERNIER EMAIL ANALYSÉ</span>
                    <div class="stat-value">${latest.sender || 'N/A'}</div>
                    <div style="font-size:0.85rem; color:var(--text-muted); margin-top:4px;">${latest.subject || 'N/A'}</div>
                </div>
            </div>
        `;

        if (recent.length > 0) {
            html += '<div class="history-header"><h3><i class="fa-solid fa-clock"></i> Activité récente</h3></div>';
            recent.forEach(item => {
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
        }

        panel.innerHTML = html;
    } catch (err) {
        panel.innerHTML = '<div class="api-error-box"><i class="fa-solid fa-triangle-exclamation"></i> Impossible de charger le dashboard</div>';
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
        const scamUrls = scamdoc.urls || [];

        html += `<div class="result-card">
            <div class="result-header"><i class="fa-solid fa-user-secret"></i> Scamdoc / ScamPredictor</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-label">EXPÉDITEUR</span>
                        <div class="text-sm text-muted" style="margin-bottom:8px; word-break:break-all;">${scamdoc.sender_email || 'N/A'}</div>
                        ${buildScamdocBox(senderResult)}
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
    const f = data.file || {};
    const vt = data.virustotal || {};
    const anyrun = data.anyrun || {};
    
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
                html += `<div class="api-error-box">${result.error}</div>`;
            } else {
                html += `
                    <div style="margin-bottom:10px;">
                        ${buildVerdictBox(result.verdict, buildVtStats(result.stats))}
                    </div>
                `;
            }

            html += `</div>`;
        });

        html += `</div></div>`;
    }

    if (data.anyrun) {
        const anyrunStatus = (anyrun.status || (anyrun.error ? 'ERROR' : 'UNKNOWN')).toUpperCase();
        html += `<div class="result-card">
            <div class="result-header"><i class="fa-solid fa-flask-vial"></i> Any.Run</div>
            <div class="result-body">
                <div class="stat-item">
                    <div style="display:flex; justify-content:space-between; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:10px;">
                        <span class="badge ${anyrun.error ? 'badge-suspicious' : 'badge-neutral'}">${anyrunStatus}</span>
                        ${anyrun.task_id ? `<span class="text-muted text-sm mono">Task: ${anyrun.task_id}</span>` : ''}
                    </div>
                    ${anyrun.error ? `<div class="api-error-box">${anyrun.error}</div>` : ''}
                    ${anyrun.report_url ? `<div style="margin-top:10px;"><a href="${anyrun.report_url}" target="_blank" class="btn btn-primary" style="display:inline-block;"><i class="fa-solid fa-up-right-from-square"></i> Ouvrir le rapport</a></div>` : ''}
                </div>
            </div>
        </div>`;
    }

    el.innerHTML = html;
    showToast('success', 'Sandbox OK', 'Hashs calculés et analysés.');
}

function renderUrlResult(data) {
    const el = document.getElementById('urlResult');
    const anyrun = data.anyrun || {};
    
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
        html += `</div>`;
    }

    // URLScan
    if(data.urlscan) {
        html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-camera"></i> URLScan.io</span>`;
        if(data.urlscan.error) html += `<div class="api-error-box">${data.urlscan.error}</div>`;
        else if(data.urlscan.ready) {
            // Rapport prêt, afficher le lien direct
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
            // Rapport pas prêt (timeout)
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
        html += `</div>`;
    }

    if(data.anyrun) {
        html += `<div class="stat-item"><span class="stat-label"><i class="fa-solid fa-flask-vial"></i> Any.Run</span>`;
        if(anyrun.error) {
            html += `<div class="api-error-box">${anyrun.error}</div>`;
        } else {
            html += `
                <div style="margin-top:15px; text-align:center;">
                    <span class="badge badge-neutral">${(anyrun.status || 'UNKNOWN').toUpperCase()}</span>
                    ${anyrun.task_id ? `<p class="text-sm text-muted" style="margin-top:10px;">Task: <span class="mono">${anyrun.task_id}</span></p>` : ''}
                    ${anyrun.report_url ? `<p style="margin-top:12px;"><a href="${anyrun.report_url}" target="_blank" class="btn btn-primary" style="display:inline-block;"><i class="fa-solid fa-up-right-from-square"></i> Voir le rapport Any.Run</a></p>` : ''}
                </div>
            `;
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

function buildScamdocBox(result) {
    result = result || {};
    if (result.error) {
        if ((result.error || '').toLowerCase().includes('timed out')) {
            return `<div style="text-align:center; padding-top:8px;">
                <span class="badge badge-neutral">EN COURS</span>
                <div style="margin-top:10px; font-size:0.85rem; color:var(--text-muted);">
                    Scamdoc met du temps à répondre. Réessaie dans quelques secondes.
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
