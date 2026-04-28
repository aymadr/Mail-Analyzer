/**
 * Analyse Phishing - Texte
 * Fonctions pour analyser le contenu et détecter les patterns de phishing
 */

// Analyse du contenu texte
async function analyzeText(e) {
    e.preventDefault();
    const text = document.getElementById('textInput').value.trim();
    
    if (!text) {
        return showToast('error', 'Erreur', 'Veuillez entrer du texte à analyser.');
    }
    
    showLoader('textResult');
    try {
        const res = await fetch('/api/analyze/text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });
        const data = await res.json();
        if (res.ok) renderPhishingTextResult(data);
        else throw new Error(data.error || 'Erreur serveur');
    } catch (err) {
        showError('textResult');
        showToast('error', 'Échec de l\'analyse', err.message);
    }
}

// Renderer pour analyse de texte
function renderPhishingTextResult(data) {
    const el = document.getElementById('textResult');
    const analysis = data.text_analysis || {};
    
    const verdictClass = {
        'MALICIOUS': 'badge-malicious',
        'SUSPICIOUS': 'badge-suspicious',
        'WARNING': 'badge-warning',
        'CLEAN': 'badge-clean'
    }[analysis.verdict] || 'badge-neutral';
    
    let html = `
        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-file-lines"></i> Analyse Heuristique</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-label">VERDICT</span>
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span class="badge ${verdictClass}">${analysis.verdict}</span>
                            <strong>${analysis.score || 0}/100</strong>
                        </div>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">MOTS-CLÉS TROUVÉS</span>
                        <span class="stat-value">${analysis.keywords_count || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">PATTERNS SUSPECTS</span>
                        <span class="stat-value">${analysis.patterns_count || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">PHRASES DE PHISHING</span>
                        <span class="stat-value">${analysis.phrases_count || 0}</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-triangle-exclamation"></i> Alertes Détectées</div>
            <div class="result-body">
    `;
    
    if (analysis.alerts && analysis.alerts.length > 0) {
        html += `<ul class="alerts-list" style="list-style:none; padding:0; margin:0;">`;
        analysis.alerts.forEach(alert => {
            html += `<li style="padding:10px; margin-bottom:8px; background:rgba(255,107,107,0.1); border-left:3px solid var(--danger); border-radius:4px;">
                <i class="fa-solid fa-circle-exclamation" style="color:var(--danger); margin-right:8px;"></i>
                ${alert}
            </li>`;
        });
        html += `</ul>`;
    } else {
        html += `<div class="stat-item">Aucune alerte majeure détectée.</div>`;
    }
    
    html += `</div></div>`;
    
    // Qualité du texte
    if (analysis.text_quality) {
        const tq = analysis.text_quality;
        html += `
            <div class="result-card">
                <div class="result-header"><i class="fa-solid fa-chart-simple"></i> Qualité du Texte</div>
                <div class="result-body">
                    <div class="stats-grid">
                        <div class="stat-item">
                            <span class="stat-label">RATIO DE MAJUSCULES</span>
                            <span class="stat-value">${(tq.capital_ratio * 100).toFixed(1)}%</span>
                        </div>
                    </div>
                    ${tq.alerts && tq.alerts.length > 0 ? `
                        <div style="margin-top:10px;">
                            <strong style="display:block; margin-bottom:8px;">Anomalies détectées:</strong>
                            <ul style="list-style:none; padding:0; margin:0;">
                                ${tq.alerts.map(a => `<li style="padding:6px 0;"><i class="fa-solid fa-check" style="color:var(--warning); margin-right:8px;"></i>${a}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }
    
    // URLs trouvées
    if (data.urls_analysis && data.urls_analysis.length > 0) {
        html += `
            <details class="result-card result-collapsible">
                <summary class="result-header"><i class="fa-solid fa-link"></i> URLs Trouvées (${data.urls_analysis.length})</summary>
                <div class="result-body">
        `;
        
        data.urls_analysis.forEach(urlItem => {
            const url = urlItem.url;
            const scamdoc = urlItem.scamdoc || {};
            const vt = urlItem.virustotal || {};
            
            html += `
                <div class="stat-item" style="margin-bottom:12px;">
                    <div style="word-break:break-all; margin-bottom:8px;">
                        <a href="${url}" target="_blank" class="text-primary">${url}</a>
                    </div>
            `;
            
            if (scamdoc.verdict) {
                const scamClass = {
                    'MALICIOUS': 'badge-malicious',
                    'SUSPICIOUS': 'badge-suspicious',
                    'CLEAN': 'badge-clean'
                }[scamdoc.verdict] || 'badge-neutral';
                html += `<span class="badge ${scamClass}">${scamdoc.verdict}</span>`;
            }
            
            html += `</div>`;
        });
        
        html += `</div></details>`;
    }
    
    // Emails trouvés
    if (data.emails_analysis && data.emails_analysis.length > 0) {
        html += `
            <details class="result-card result-collapsible">
                <summary class="result-header"><i class="fa-solid fa-envelope"></i> Adresses Email Trouvées (${data.emails_analysis.length})</summary>
                <div class="result-body">
        `;
        
        data.emails_analysis.forEach(emailItem => {
            const email = emailItem.email;
            const scamdoc = emailItem.scamdoc || {};
            
            html += `
                <div class="stat-item" style="margin-bottom:12px;">
                    <div style="margin-bottom:8px; font-family:monospace;">${email}</div>
            `;
            
            if (scamdoc.verdict) {
                const scamClass = {
                    'MALICIOUS': 'badge-malicious',
                    'SUSPICIOUS': 'badge-suspicious',
                    'CLEAN': 'badge-clean'
                }[scamdoc.verdict] || 'badge-neutral';
                html += `<span class="badge ${scamClass}">${scamdoc.verdict}</span>`;
            }
            
            html += `</div>`;
        });
        
        html += `</div></details>`;
    }
    
    el.innerHTML = html;
}
