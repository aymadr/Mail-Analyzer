"""
Interface Flask - API REST et Web
"""
import sys
from pathlib import Path

# Ajouter le backend au path Python
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import ipaddress
from analyzer import SecurityAnalyzer
from phishing_detector import PhishingTextAnalyzer

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Créer le dossier uploads
Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)

analyzer = SecurityAnalyzer()
phishing_analyzer = PhishingTextAnalyzer()

ALLOWED_EXTENSIONS = {'eml', 'msg', 'exe', 'dll', 'doc', 'docx', 'pdf', 'zip', 'rar', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Page d'accueil"""
    return render_template('index.html')

@app.route('/api/analyze/email', methods=['POST'])
def analyze_email():
    """Analyse un email"""
    if 'file' not in request.files:
        return jsonify({"error": "Aucun fichier fourni"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Fichier vide"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "Type de fichier non autorisé"}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        result = analyzer.analyze_email_file(filepath)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        # Cleanup - with retry for locked files
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except (PermissionError, OSError):
                # Fichier verrouillé, essayer après un court délai
                import time
                time.sleep(0.1)
                try:
                    os.remove(filepath)
                except Exception:
                    pass  # Ignorer l'erreur si vraiment verrouillé

@app.route('/api/analyze/attachment', methods=['POST'])
def analyze_attachment():
    """Analyse une pièce jointe"""
    if 'file' not in request.files:
        return jsonify({"error": "Aucun fichier fourni"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Fichier vide"}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        result = analyzer.analyze_attachment(filepath)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except (PermissionError, OSError):
                import time
                time.sleep(0.1)
                try:
                    os.remove(filepath)
                except Exception:
                    pass

@app.route('/api/analyze/attachment/hash', methods=['POST'])
def analyze_attachment_hash():
    """Analyse une pièce jointe à partir d'un hash déjà connu."""
    data = request.get_json(silent=True) or {}
    file_hash = (data.get('file_hash') or data.get('hash') or '').strip()

    if not file_hash:
        return jsonify({"error": "Hash non fourni"}), 400

    try:
        hash_type = 'sha256' if len(file_hash) == 64 else ('sha1' if len(file_hash) == 40 else ('md5' if len(file_hash) == 32 else 'hash'))

        vt_result = analyzer.vt_client.check_file_hash(file_hash)
        ha_result = {}
        if hash_type == 'sha256' and analyzer.hybrid_analysis_client.enabled:
            ha_result = analyzer.hybrid_analysis_client.get_report(file_hash)

        result = {
            'mode': 'hash',
            'input_hash': file_hash,
            'hash_type': hash_type,
            'virustotal': vt_result,
            'hybrid_analysis': ha_result,
        }

        analyzer.db.save_file_hash_analysis(file_hash, hash_type, vt_result)
        if ha_result and not ha_result.get('error'):
            analyzer.db.save_file_hash_analysis(file_hash, 'hybrid_analysis', ha_result)

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    """Analyse une URL"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "URL non fournie"}), 400
    
    try:
        result = analyzer.analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze/ip', methods=['POST'])
def analyze_ip():
    """Analyse une adresse IP"""
    data = request.get_json()
    ip = data.get('ip', '').strip()
    
    if not ip:
        return jsonify({"error": "IP non fournie"}), 400

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Format IP invalide (IPv4 ou IPv6 attendu)"}), 400
    
    try:
        vt_result = analyzer.vt_client.check_ip(ip)
        abuseipdb_result = analyzer.abuseipdb_client.check_ip(ip)
        
        result = {
            "ip": ip,
            "virustotal": vt_result,
            "abuseipdb": abuseipdb_result
        }
        
        analyzer.db.save_ip_analysis(ip, result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    """Récupère les métriques principales du dashboard."""
    return jsonify(analyzer.db.get_dashboard_summary())

@app.route('/api/history', methods=['GET'])
def get_history():
    """Récupère l'historique des analyses"""
    limit = request.args.get('limit', 50, type=int)
    analyses = analyzer.db.get_all_analyses(limit)
    return jsonify(analyses)

@app.route('/api/report/<email_hash>', methods=['GET'])
def get_report(email_hash):
    """Récupère un rapport spécifique"""
    report = analyzer.get_report(email_hash)
    if report:
        return jsonify(report)
    return jsonify({"error": "Rapport non trouvé"}), 404

@app.route('/api/analyze/text', methods=['POST'])
def analyze_text():
    """Analyse un contenu texte pour détecter les patterns de phishing"""
    data = request.get_json()
    text = data.get('text', '').strip() if data else ''
    
    if not text:
        return jsonify({"error": "Texte vide"}), 400
    
    try:
        # Analyse de phishing basée sur le texte
        text_analysis = phishing_analyzer.analyze(text)
        
        # Analyser les URLs si présentes via les APIs
        url_analyses = []
        for url in text_analysis.get("urls", [])[:5]:  # Limiter à 5 URLs
            try:
                url_analysis = {
                    "url": url,
                    "scamdoc": analyzer.scamdoc_client.check_url(url),
                    "virustotal": analyzer.vt_client.check_url(url)
                }
                url_analyses.append(url_analysis)
            except Exception as e:
                url_analyses.append({"url": url, "error": str(e)})
        
        # Analyser les domaines des emails
        email_analyses = []
        for email in text_analysis.get("emails", [])[:5]:
            domain = email.split("@")[1] if "@" in email else ""
            if domain:
                try:
                    email_analysis = {
                        "email": email,
                        "domain": domain,
                        "scamdoc": analyzer.scamdoc_client.check_url(f"https://{domain}")
                    }
                    email_analyses.append(email_analysis)
                except Exception as e:
                    email_analyses.append({"email": email, "error": str(e)})
        
        result = {
            "text_analysis": text_analysis,
            "urls_analysis": url_analyses,
            "emails_analysis": email_analyses,
            "summary": {
                "overall_verdict": text_analysis.get("verdict"),
                "risk_score": text_analysis.get("score"),
                "urls_checked": len(url_analyses),
                "emails_found": len(email_analyses)
            }
        }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint non trouvé"}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Erreur serveur interne"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
