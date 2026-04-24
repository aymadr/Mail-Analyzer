"""
Exemples d'utilisation des modules individuels
"""
import sys
from pathlib import Path

# Ajouter backend au path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

print("\n" + "="*60)
print("🎓 Mail Security Analyzer - Exemples d'Utilisation")
print("="*60 + "\n")

# ============================================================
# 1. CALCULER LES HASH D'UN FICHIER
# ============================================================
print("1️⃣  CALCULER LES HASH D'UN FICHIER\n")
print("-" * 60)

from hash_calculator import HashCalculator

# Exemple avec une chaîne
print("Calcul du hash d'une chaîne 'malware':")
string_hashes = HashCalculator.calculate_string_hashes("malware")
print(f"  MD5:    {string_hashes['md5']}")
print(f"  SHA1:   {string_hashes['sha1']}")
print(f"  SHA256: {string_hashes['sha256']}\n")

# ============================================================
# 2. PARSER UN EMAIL
# ============================================================
print("2️⃣  PARSER UN EMAIL\n")
print("-" * 60)

from email_parser import EmailHeaderParser

parser = EmailHeaderParser()

# Exemple d'email brut
sample_email = """From: attacker@malicious.com
To: user@company.com
Subject: Invoice Payment Required
Date: Mon, 24 Apr 2026 10:30:00 +0000
SPF: pass (sender SPF authorized)
DKIM-Signature: v=1; a=rsa-sha256; d=malicious.com; s=default
Received: from mail.malicious.com (mail.malicious.com [192.168.1.1])
Authentication-Results: dmarc=none p=none

Dear User,
Please pay the invoice...
"""

print("Parsing de l'email...")
result = parser.parse_email_content(sample_email)

print(f"De: {result['from']}")
print(f"À: {result['to']}")
print(f"Sujet: {result['subject']}")
print(f"\nSPF Status: {result['spf']['status']}")
print(f"DKIM Status: {result['dkim']['status']}")
print(f"DMARC Status: {result['dmarc']['status']}")
print(f"\nIPs trouvées: {result['ips']}")
print(f"Domaines trouvés: {result['domains']}\n")

# ============================================================
# 3. UTILISER LE CLIENT VIRUSTOTAL
# ============================================================
print("3️⃣  UTILISER LE CLIENT VIRUSTOTAL\n")
print("-" * 60)

from api_clients import VirusTotalClient

vt = VirusTotalClient()

# Exemple avec un IP public connu
print("Analyse d'une IP (Google DNS: 8.8.8.8):")
print("⏳ Requête vers VirusTotal...\n")

ip_result = vt.check_ip("8.8.8.8")

if 'error' in ip_result:
    print(f"⚠️  Note: {ip_result['error']}")
    print("   (Clé API non configurée pour cet exemple)\n")
else:
    print(f"Source: {ip_result['source']}")
    print(f"IP: {ip_result['ip']}")
    print(f"Pays: {ip_result.get('country', 'N/A')}")
    print(f"ASN: {ip_result.get('asn', 'N/A')}")
    print(f"Résultat: {ip_result['url']}\n")

# ============================================================
# 4. UTILISER LE CLIENT ABUSEIPDB
# ============================================================
print("4️⃣  UTILISER LE CLIENT ABUSEIPDB\n")
print("-" * 60)

from api_clients import AbuseIPDBClient

abuseipdb = AbuseIPDBClient()

print("Vérification d'une IP sur AbuseIPDB (127.0.0.1 - localhost):")
print("⏳ Requête vers AbuseIPDB...\n")

abuse_result = abuseipdb.check_ip("127.0.0.1")

if 'error' in abuse_result:
    print(f"⚠️  Note: {abuse_result['error']}")
    print("   (Clé API non configurée pour cet exemple)\n")
else:
    print(f"Source: {abuse_result['source']}")
    print(f"IP: {abuse_result['ip']}")
    print(f"Score de Confiance Abus: {abuse_result['abuse_confidence_score']}%")
    print(f"Total Rapports: {abuse_result['total_reports']}")
    print(f"Whitelistée: {abuse_result['is_whitelisted']}")
    print(f"Blacklistée: {abuse_result['is_blacklisted']}\n")

# ============================================================
# 5. UTILISER LA BASE DE DONNÉES
# ============================================================
print("5️⃣  UTILISER LA BASE DE DONNÉES\n")
print("-" * 60)

from database import Database

db = Database()

print("Sauvegarde d'une analyse en base de données...\n")

# Sauvegarde d'une analyse de fichier
file_analysis = {
    "verdict": "SUSPICIOUS",
    "detections": 3,
    "sources": ["BitDefender", "K7AntiVirus", "McAfee"]
}

success = db.save_file_hash_analysis(
    "5d41402abc4b2a76b9719d911017c592",
    "md5",
    file_analysis
)

print(f"Sauvegarde: {'✅ OK' if success else '❌ Erreur'}\n")

# Récupération
retrieved = db.get_file_hash_analysis("5d41402abc4b2a76b9719d911017c592")
if retrieved:
    print("Données récupérées:")
    print(f"  Verdict: {retrieved['verdict']}")
    print(f"  Détections: {retrieved['detections']}\n")

# ============================================================
# 6. UTILISER L'ORCHESTRATEUR
# ============================================================
print("6️⃣  UTILISER L'ORCHESTRATEUR (ANALYZER)\n")
print("-" * 60)

from analyzer import SecurityAnalyzer

analyzer = SecurityAnalyzer()

print("L'orchestrateur coordonne tous les composants:\n")
print("✅ EmailHeaderParser  - Parsing d'entêtes")
print("✅ HashCalculator     - Calcul de hash")
print("✅ VirusTotalClient   - Vérification fichiers/URLs/IPs")
print("✅ URLScanIOClient    - Scan d'URLs")
print("✅ AbuseIPDBClient    - Vérification IPs malveillantes")
print("✅ Database           - Cache local\n")

# ============================================================
# 7. WORKFLOWS COMPLETS
# ============================================================
print("7️⃣  WORKFLOWS COMPLETS\n")
print("-" * 60)

print("A. Analyser une pièce jointe suspecte:")
print("   1. Calculer MD5, SHA1, SHA256")
print("   2. Vérifier sur VirusTotal")
print("   3. Sauvegarder en base")
print("   4. Afficher le verdict\n")

print("B. Analyser un email malveillant:")
print("   1. Parser l'entête (SPF, DKIM, DMARC)")
print("   2. Extraire les IPs et domaines")
print("   3. Vérifier chaque IP (VT + AbuseIPDB)")
print("   4. Sauvegarder l'analyse complète\n")

print("C. Analyser une URL suspecte:")
print("   1. Vérifier sur VirusTotal")
print("   2. Scanner avec URLScan.io")
print("   3. Extraire les IPs de la page")
print("   4. Vérifier les IPs")
print("   5. Créer un rapport complet\n")

# ============================================================
# 8. UTILISATION AVANCÉE
# ============================================================
print("8️⃣  UTILISATION AVANCÉE\n")
print("-" * 60)

print("Traitement en batch:\n")
print("files = ['file1.exe', 'file2.doc', 'file3.zip']")
print("for file in files:")
print("    hashes = HashCalculator.calculate_file_hashes(file)")
print("    vt_result = vt.check_file_hash(hashes['sha256'])")
print("    db.save_file_hash_analysis(hashes['sha256'], 'sha256', vt_result)\n")

print("Filtrage par verdict:\n")
print("results = [vt.check_file_hash(h) for h in hashes]")
print("malicious = [r for r in results if r.get('verdict') == 'MALICIOUS']")
print("print(f'Fichiers malveillants: {len(malicious)}')\n")

print("Export JSON:\n")
print("import json")
print("analysis = analyzer.analyze_email_file('email.eml')")
print("with open('report.json', 'w') as f:")
print("    json.dump(analysis, f, indent=2, default=str)\n")

# ============================================================
# RÉSUMÉ
# ============================================================
print("="*60)
print("✨ Résumé")
print("="*60)
print("\n✅ Modules principaux à utiliser:\n")
print("  • HashCalculator     → Calcul de hash (MD5, SHA1, SHA256)")
print("  • EmailHeaderParser  → Parsing d'emails (SPF, DKIM, DMARC)")
print("  • VirusTotalClient   → Vérification VirusTotal")
print("  • URLScanIOClient    → Scan d'URLs")
print("  • AbuseIPDBClient    → Vérification d'IPs")
print("  • Database           → Sauvegarde/récupération des résultats")
print("  • SecurityAnalyzer   → Orchestrateur complet\n")

print("📖 Pour plus d'infos:")
print("  • README.md          → Vue d'ensemble du projet")
print("  • INSTALLATION.md    → Guide d'installation détaillé")
print("  • cli.py             → Interface ligne de commande")
print("  • test.py            → Tests unitaires\n")

print("🚀 Lancer l'interface web:")
print("  cd frontend && python app.py\n")

print("="*60 + "\n")
