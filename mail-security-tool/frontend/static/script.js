// Tab Navigation
document.querySelectorAll('.tab-button').forEach(button => {
    button.addEventListener('click', () => {
        const tabId = button.dataset.tab;
        
        // Remove active class from all buttons and contents
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        // Add active class to clicked button and corresponding content
        button.classList.add('active');
        document.getElementById(tabId).classList.add('active');
    });
});

// Email Analysis
document.getElementById('emailForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = document.getElementById('emailFile').files[0];
    
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    
    showLoading('emailResult');
    
    try {
        const response = await fetch('/api/analyze/email', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayEmailResult(data);
        } else {
            showError('emailResult', data.error || 'Erreur lors de l\'analyse');
        }
    } catch (error) {
        showError('emailResult', error.message);
    }
});

// Attachment Analysis
document.getElementById('attachmentForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = document.getElementById('attachmentFile').files[0];
    
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    
    showLoading('attachmentResult');
    
    try {
        const response = await fetch('/api/analyze/attachment', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayAttachmentResult(data);
        } else {
            showError('attachmentResult', data.error || 'Erreur lors de l\'analyse');
        }
    } catch (error) {
        showError('attachmentResult', error.message);
    }
});

// URL Analysis
document.getElementById('urlForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('urlInput').value;
    
    showLoading('urlResult');
    
    try {
        const response = await fetch('/api/analyze/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayUrlResult(data);
        } else {
            showError('urlResult', data.error || 'Erreur lors de l\'analyse');
        }
    } catch (error) {
        showError('urlResult', error.message);
    }
});

// IP Analysis
document.getElementById('ipForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = document.getElementById('ipInput').value;
    
    showLoading('ipResult');
    
    try {
        const response = await fetch('/api/analyze/ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayIpResult(data);
        } else {
            showError('ipResult', data.error || 'Erreur lors de l\'analyse');
        }
    } catch (error) {
        showError('ipResult', error.message);
    }
});

// Load History on Tab Click
document.querySelector('[data-tab="history"]').addEventListener('click', loadHistory);

// Display Functions
function displayEmailResult(data) {
    const container = document.getElementById('emailResult');
    
    let html = '<div class="report">';
    
    // Email Info
    if (data.email) {
        html += `
            <div class="report-section">
                <h3>📧 Informations Email</h3>
                <div class="email-info">
                    <p><span class="label">De:</span> ${data.email.from || 'N/A'}</p>
                    <p><span class="label">À:</span> ${data.email.to || 'N/A'}</p>
                    <p><span class="label">Sujet:</span> ${data.email.subject || 'N/A'}</p>
                    <p><span class="label">Date:</span> ${data.email.date || 'N/A'}</p>
                </div>
            </div>
        `;
    }
    
    // SPF
    if (data.email.spf) {
        html += `
            <div class="report-section">
                <h3>🔐 SPF</h3>
                <div class="email-info">
                    <p><span class="label">Statut:</span> ${data.email.spf.status || 'N/A'}</p>
                    <p><span class="label">Record:</span> ${data.email.spf.record || 'N/A'}</p>
                </div>
            </div>
        `;
    }
    
    // DKIM
    if (data.email.dkim) {
        html += `
            <div class="report-section">
                <h3>🔑 DKIM</h3>
                <div class="email-info">
                    <p><span class="label">Statut:</span> ${data.email.dkim.status || 'N/A'}</p>
                    <p><span class="label">Domaine:</span> ${data.email.dkim.domain || 'N/A'}</p>
                    <p><span class="label">Algorithme:</span> ${data.email.dkim.algorithm || 'N/A'}</p>
                </div>
            </div>
        `;
    }
    
    // DMARC
    if (data.email.dmarc) {
        html += `
            <div class="report-section">
                <h3>🛡️ DMARC</h3>
                <div class="email-info">
                    <p><span class="label">Statut:</span> ${data.email.dmarc.status || 'N/A'}</p>
                    <p><span class="label">Politique:</span> ${data.email.dmarc.policy || 'N/A'}</p>
                </div>
            </div>
        `;
    }
    
    // IPs
    if (data.ips && data.ips.length > 0) {
        html += '<div class="report-section"><h3>🌐 Analyse des IPs</h3>';
        data.ips.forEach(ipData => {
            if (ipData.virustotal && !ipData.virustotal.error) {
                const verdict = ipData.virustotal.verdict || 'UNKNOWN';
                const verdictClass = `verdict-${verdict.toLowerCase()}`;
                
                html += `
                    <div class="ip-info ${verdictClass}">
                        <p><span class="label">IP:</span> ${ipData.ip}</p>
                        <p><span class="label">Pays:</span> ${ipData.virustotal.country || 'N/A'}</p>
                        <p><span class="label">ASN:</span> ${ipData.virustotal.asn || 'N/A'}</p>
                        <span class="verdict-badge badge-${verdict.toLowerCase()}">${verdict}</span>
                    </div>
                `;
            }
        });
        html += '</div>';
    }
    
    html += '</div>';
    container.innerHTML = html;
}

function displayAttachmentResult(data) {
    const container = document.getElementById('attachmentResult');
    
    let html = '<div class="report">';
    
    // File Info
    if (data.file) {
        html += `
            <div class="report-section">
                <h3>📄 Informations Fichier</h3>
                <div class="file-info">
                    <p><span class="label">Nom:</span> ${data.file.file_name}</p>
                    <p><span class="label">Taille:</span> ${formatBytes(data.file.file_size)}</p>
                </div>
            </div>
        `;
    }
    
    // Hashes
    if (data.file) {
        html += `
            <div class="report-section">
                <h3>🔑 Hashes</h3>
                <div class="file-info">
                    <p><span class="label">MD5:</span><br><code style="word-break: break-all; color: #667eea;">${data.file.md5}</code></p>
                    <p><span class="label">SHA1:</span><br><code style="word-break: break-all; color: #667eea;">${data.file.sha1}</code></p>
                    <p><span class="label">SHA256:</span><br><code style="word-break: break-all; color: #667eea;">${data.file.sha256}</code></p>
                </div>
            </div>
        `;
    }
    
    // VirusTotal Results
    if (data.virustotal) {
        html += '<div class="report-section"><h3>🦠 VirusTotal</h3>';
        Object.entries(data.virustotal).forEach(([hashType, result]) => {
            if (!result.error) {
                const verdict = result.verdict || 'UNKNOWN';
                const verdictClass = `verdict-${verdict.toLowerCase()}`;
                const stats = result.stats || {};
                
                html += `
                    <div class="verdict-box ${verdictClass}">
                        <p><span class="label">${hashType.toUpperCase()}:</span></p>
                        <div class="stats-grid">
                            <div class="stat-box">
                                <div class="number">${stats.malicious || 0}</div>
                                <div class="label">Malveillants</div>
                            </div>
                            <div class="stat-box">
                                <div class="number">${stats.suspicious || 0}</div>
                                <div class="label">Suspects</div>
                            </div>
                            <div class="stat-box">
                                <div class="number">${stats.undetected || 0}</div>
                                <div class="label">Propres</div>
                            </div>
                        </div>
                        <span class="verdict-badge badge-${verdict.toLowerCase()}">${verdict}</span>
                    </div>
                `;
            }
        });
        html += '</div>';
    }
    
    html += '</div>';
    container.innerHTML = html;
}

function displayUrlResult(data) {
    const container = document.getElementById('urlResult');
    
    let html = '<div class="report">';
    
    if (data.virustotal && !data.virustotal.error) {
        const verdict = data.virustotal.verdict || 'UNKNOWN';
        const verdictClass = `verdict-${verdict.toLowerCase()}`;
        const stats = data.virustotal.stats || {};
        
        html += `
            <div class="report-section">
                <h3>🦠 VirusTotal</h3>
                <div class="verdict-box ${verdictClass}">
                    <p><span class="label">URL:</span> <a href="${data.url}" target="_blank">${data.url}</a></p>
                    <div class="stats-grid">
                        <div class="stat-box">
                            <div class="number">${stats.malicious || 0}</div>
                            <div class="label">Malveillants</div>
                        </div>
                        <div class="stat-box">
                            <div class="number">${stats.suspicious || 0}</div>
                            <div class="label">Suspects</div>
                        </div>
                        <div class="stat-box">
                            <div class="number">${stats.undetected || 0}</div>
                            <div class="label">Propres</div>
                        </div>
                    </div>
                    <span class="verdict-badge badge-${verdict.toLowerCase()}">${verdict}</span>
                </div>
            </div>
        `;
    }
    
    if (data.urlscan && !data.urlscan.error) {
        html += `
            <div class="report-section">
                <h3>🔗 URLScan.io</h3>
                <div class="file-info">
                    <p><span class="label">Scan ID:</span> ${data.urlscan.scan_id}</p>
                    <p><a href="${data.urlscan.result_url}" target="_blank">Voir le résultat complet</a></p>
                </div>
            </div>
        `;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

function displayIpResult(data) {
    const container = document.getElementById('ipResult');
    
    let html = '<div class="report">';
    
    if (data.virustotal && !data.virustotal.error) {
        const stats = data.virustotal.last_analysis_stats || {};
        
        html += `
            <div class="report-section">
                <h3>🦠 VirusTotal</h3>
                <div class="ip-info">
                    <p><span class="label">IP:</span> ${data.ip}</p>
                    <p><span class="label">Pays:</span> ${data.virustotal.country || 'N/A'}</p>
                    <p><span class="label">ASN:</span> ${data.virustotal.asn || 'N/A'}</p>
                    <div class="stats-grid">
                        <div class="stat-box">
                            <div class="number">${stats.malicious || 0}</div>
                            <div class="label">Malveillants</div>
                        </div>
                        <div class="stat-box">
                            <div class="number">${stats.suspicious || 0}</div>
                            <div class="label">Suspects</div>
                        </div>
                        <div class="stat-box">
                            <div class="number">${stats.undetected || 0}</div>
                            <div class="label">Propres</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    if (data.abuseipdb && !data.abuseipdb.error) {
        const score = data.abuseipdb.abuse_confidence_score || 0;
        const scoreBg = score > 75 ? '#dc3545' : score > 25 ? '#ffc107' : '#28a745';
        
        html += `
            <div class="report-section">
                <h3>⚠️ AbuseIPDB</h3>
                <div class="ip-info" style="border-left-color: ${scoreBg}; background: rgba(${scoreBg === '#dc3545' ? '220,53,69' : scoreBg === '#ffc107' ? '255,193,7' : '40,167,69'}, 0.1);">
                    <p><span class="label">Score de Confiance Abus:</span> ${score}%</p>
                    <p><span class="label">Total Rapports:</span> ${data.abuseipdb.total_reports}</p>
                    <p><span class="label">Whitelistée:</span> ${data.abuseipdb.is_whitelisted ? 'Oui' : 'Non'}</p>
                    <p><span class="label">Blacklistée:</span> ${data.abuseipdb.is_blacklisted ? 'Oui' : 'Non'}</p>
                </div>
            </div>
        `;
    }
    
    html += '</div>';
    container.innerHTML = html;
}

async function loadHistory() {
    const container = document.getElementById('historyList');
    showLoading('historyList');
    
    try {
        const response = await fetch('/api/history');
        const data = await response.json();
        
        let html = '';
        if (data.length === 0) {
            html = '<p style="text-align: center; color: #999;">Aucune analyse enregistrée</p>';
        } else {
            data.forEach(item => {
                html += `
                    <div class="history-item">
                        <div class="history-item-header">
                            <h4>${item.sender || 'N/A'}</h4>
                            <span class="history-item-date">${new Date(item.date).toLocaleString('fr-FR')}</span>
                        </div>
                        <div class="history-item-preview">Sujet: ${item.subject || 'N/A'}</div>
                    </div>
                `;
            });
        }
        container.innerHTML = html;
    } catch (error) {
        showError('historyList', error.message);
    }
}

// Utility Functions
function showLoading(containerId) {
    document.getElementById(containerId).innerHTML = '<div class="loading">Analyse en cours...</div>';
}

function showError(containerId, message) {
    document.getElementById(containerId).innerHTML = `<div class="error">❌ Erreur: ${message}</div>`;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}
