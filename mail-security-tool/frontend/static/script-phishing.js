/**
 * Text Analysis - Phishing Detection
 * Professional SOC operations analysis
 */

// Analyze text content
async function analyzeText(e) {
    e.preventDefault();
    const text = document.getElementById('textInput').value.trim();
    
    if (!text) {
        return showToast('error', 'Invalid Input', 'Enter text to analyze.');
    }
    
    showLoader('textResult');
    try {
        const res = await fetch('/api/analyze/text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text })
        });
        const data = await res.json();
        if (res.ok) {
            renderPhishingTextResult(data);
            showToast('success', 'Analysis Complete', 'Heuristics evaluated');
        } else throw new Error(data.error || 'Server error');
    } catch (err) {
        showError('textResult');
        showToast('error', 'Analysis Failed', err.message);
    }
}

// Render text analysis results
function renderPhishingTextResult(data) {
    const el = document.getElementById('textResult');
    const analysis = data.text_analysis || {};
    
    const verdictClass = {
        'MALICIOUS': 'badge-malicious',
        'SUSPICIOUS': 'badge-suspicious',
        'WARNING': 'badge-warning',
        'CLEAN': 'badge-clean'
    }[analysis.verdict] || 'badge-neutral';
    
    const risk_score = analysis.score || 0;
    const risk_color = risk_score > 70 ? 'var(--danger)' : (risk_score > 40 ? 'var(--warning)' : 'var(--success)');
    
    let html = `
        <div class="result-card">
            <div class="result-header"><i class="fa-solid fa-file-lines"></i> Heuristic Analysis</div>
            <div class="result-body">
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-label">VERDICT</span>
                        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                            <span class="badge ${verdictClass}" style="font-size:0.8rem; font-weight:600;">${analysis.verdict}</span>
                            <span style="font-size:1.8rem; font-weight:700; color:${risk_color};">${risk_score}</span>
                            <span style="font-size:0.75rem; color:var(--text-muted);">/100</span>
                        </div>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">KEYWORDS</span>
                        <span class="stat-value">${analysis.keywords_count || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">PATTERNS</span>
                        <span class="stat-value">${analysis.patterns_count || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">PHISHING PHRASES</span>
                        <span class="stat-value">${analysis.phrases_count || 0}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    if (analysis.alerts && analysis.alerts.length > 0) {
        html += `
            <div class="result-card">
                <div class="result-header"><i class="fa-solid fa-triangle-exclamation"></i> Detections</div>
                <div class="result-body">
                    <ul style="list-style:none; padding:0; margin:0;">
        `;
        analysis.alerts.forEach(alert => {
            html += `<li style="padding:10px 12px; margin-bottom:8px; background:rgba(239, 68, 68, 0.08); border-left:3px solid var(--danger); border-radius:6px; font-size:0.9rem;">
                <i class="fa-solid fa-circle-exclamation" style="color:var(--danger); margin-right:8px; opacity:0.7;"></i>${alert}
            </li>`;
        });
        html += `</ul></div></div>`;
    }
    
    // Text quality
    if (analysis.text_quality) {
        const tq = analysis.text_quality;
        html += `
            <div class="result-card">
                <div class="result-header"><i class="fa-solid fa-chart-simple"></i> Text Quality</div>
                <div class="result-body">
                    <div class="stats-grid">
                        <div class="stat-item">
                            <span class="stat-label">UPPERCASE RATIO</span>
                            <span class="stat-value">${(tq.capital_ratio * 100).toFixed(1)}%</span>
                        </div>
                    </div>
                    ${tq.alerts && tq.alerts.length > 0 ? `
                        <div style="margin-top:12px;">
                            <strong style="display:block; margin-bottom:8px; font-size:0.9rem;">Anomalies:</strong>
                            <ul style="list-style:none; padding:0; margin:0;">
                                ${tq.alerts.map(a => `<li style="padding:6px 0; font-size:0.85rem;"><i class="fa-solid fa-alert-circle" style="color:var(--warning); margin-right:8px; opacity:0.7;"></i>${a}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }
    
    // URLs found
    if (data.urls_analysis && data.urls_analysis.length > 0) {
        html += `
            <details class="result-card result-collapsible">
                <summary class="result-header"><i class="fa-solid fa-link"></i> URLs Detected (${data.urls_analysis.length})</summary>
                <div class="result-body">
        `;
        
        data.urls_analysis.forEach(urlItem => {
            const url = urlItem.url;
            const scamdoc = urlItem.scamdoc || {};
            
            html += `
                <div class="stat-item" style="margin-bottom:12px;">
                    <div style="word-break:break-all; margin-bottom:8px;">
                        <a href="${url}" target="_blank" class="text-primary" style="font-size:0.85rem;">${url}</a>
                    </div>
            `;
            
            if (scamdoc.verdict) {
                const scamClass = {
                    'MALICIOUS': 'badge-malicious',
                    'SUSPICIOUS': 'badge-suspicious',
                    'CLEAN': 'badge-clean'
                }[scamdoc.verdict] || 'badge-neutral';
                html += `<span class="badge ${scamClass}" style="font-size:0.75rem;">${scamdoc.verdict}</span>`;
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
