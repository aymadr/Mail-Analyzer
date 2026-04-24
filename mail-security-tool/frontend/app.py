"""
Interface Flask - API REST et Web
"""
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
from pathlib import Path
from analyzer import SecurityAnalyzer

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Créer le dossier uploads
Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)

analyzer = SecurityAnalyzer()

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
        # Cleanup
        if os.path.exists(filepath):
            os.remove(filepath)

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
            os.remove(filepath)

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

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint non trouvé"}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Erreur serveur interne"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
