# Installation et Utilisation

## 🚀 Démarrage Rapide

### Option 1: Interface Web (Recommandée)

```bash
# 1. Cloner/télécharger le projet
cd mail-security-tool

# 2. Créer environnement virtuel
python -m venv venv
# Windows PowerShell
.\venv\Scripts\Activate.ps1
# Windows CMD
venv\Scripts\activate.bat
# Linux/Mac
source venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer les API keys dans .env
nano .env  # éditer avec tes clés

# 5. Lancer l'application
python run.py
# ou
cd frontend && python app.py

# 6. Ouvrir le navigateur
# http://127.0.0.1:5000
```

### Option 1 bis: Lancement avec Docker (clone puis run)

Oui, le flux est bien: **cloner le projet GitHub**, puis **lancer Docker**.

```bash
# 1. Cloner le repo
git clone <URL_DU_REPO>
cd mail-security-tool

# 2. Préparer les variables d'environnement
cp .env.example .env
# puis éditer .env avec les clés API

# 3. Construire et démarrer le conteneur
docker compose up --build -d

# 4. Ouvrir l'interface
# http://127.0.0.1:5000
```

Commandes utiles:
```bash
# Voir les logs
docker compose logs -f

# Arrêter les services
docker compose down
```

### Option 2: Ligne de Commande (CLI)

```bash
# Active d'abord l'environnement virtuel
# Windows PowerShell: .\venv\Scripts\Activate.ps1
# Windows CMD: venv\Scripts\activate.bat
# Linux/Mac: source venv/bin/activate

# Analyser un email
python cli.py --email mon_email.eml

# Analyser une pièce jointe
python cli.py --attachment malware.exe

# Analyser une URL
python cli.py --url https://suspicious.com

# Analyser une IP
python cli.py --ip 192.168.1.1

# Calculer le hash d'un fichier
python cli.py --hash /path/to/file.exe

# Output en JSON
python cli.py --email mon_email.eml --json

# Avec détails supplémentaires
python cli.py --email mon_email.eml -v
```

### Option CLI Windows (raccourci prêt à l'emploi)

```powershell
# Depuis le dossier mail-security-tool
.\venv\Scripts\Activate.ps1
python cli.py --email .\examples\sample.eml --json
```

## 🔑 Obtenir les Clés API

### 1. VirusTotal
1. Aller sur https://www.virustotal.com
2. Créer un compte (gratuit)
3. Aller dans "Settings" → "API key"
4. Copier la clé API

```env
VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE
```

**Limites Gratuites:**
- 4 requêtes par minute
- Pas de priorité sur l'analyse

### 2. URLScan.io
1. Aller sur https://urlscan.io
2. Créer un compte (gratuit)
3. Accéder à https://urlscan.io/settings/
4. Copier l'API key

```env
URLSCAN_API_KEY=YOUR_API_KEY_HERE
```

**Limites Gratuites:**
- Scans limités par jour
- Publicité sur rapports

### 3. AbuseIPDB
1. Aller sur https://www.abuseipdb.com
2. Créer un compte (gratuit)
3. Aller dans "Account" → "API"
4. Copier l'API key

```env
ABUSEIPDB_API_KEY=YOUR_API_KEY_HERE
```

**Limites Gratuites:**
- 1000 requêtes par jour
- Données limitées (5 rapports max)

## 📊 Architecture Modulaire

### Backend Modules

#### 1. `config.py`
- Gestion des variables d'environnement
- Paramètres API et timeouts

```python
from backend.config import VIRUSTOTAL_API_KEY, API_TIMEOUT
```

#### 2. `email_parser.py`
- Parse des entêtes email
- Extraction SPF, DKIM, DMARC
- Extraction IPs et domaines

```python
from backend.email_parser import EmailHeaderParser

parser = EmailHeaderParser()
result = parser.parse_eml_file("email.eml")
print(result['spf'])
print(result['ips'])
```

#### 3. `hash_calculator.py`
- Calcul MD5, SHA1, SHA256
- Calcul depuis fichier ou bytes

```python
from backend.hash_calculator import HashCalculator

hashes = HashCalculator.calculate_file_hashes("file.exe")
print(hashes['md5'])
print(hashes['sha256'])
```

#### 4. `api_clients.py`
- Clients pour VirusTotal, URLScan.io, AbuseIPDB
- Gestion des retries et erreurs

```python
from backend.api_clients import VirusTotalClient, AbuseIPDBClient

vt = VirusTotalClient()
result = vt.check_file_hash("5d41402abc4b2a76b9719d911017c592")
print(result['verdict'])  # CLEAN, SUSPICIOUS, MALICIOUS

abuseipdb = AbuseIPDBClient()
ip_result = abuseipdb.check_ip("8.8.8.8")
print(ip_result['abuse_confidence_score'])
```

#### 5. `database.py`
- Cache SQLite
- Sauvegarde/récupération des analyses

```python
from backend.database import Database

db = Database()
db.save_file_hash_analysis("abc123", "md5", {"verdict": "CLEAN"})
result = db.get_file_hash_analysis("abc123")
```

#### 6. `analyzer.py`
- Orchestrateur principal
- Coordonne toutes les analyses

```python
from backend.analyzer import SecurityAnalyzer

analyzer = SecurityAnalyzer()
email_analysis = analyzer.analyze_email_file("email.eml")
attachment_analysis = analyzer.analyze_attachment("file.exe")
url_analysis = analyzer.analyze_url("https://example.com")
```

## 🎨 Utilisation du Frontend

### Onglets Disponibles

1. **Email** - Analyser un fichier email
   - Parse automatique SPF/DKIM/DMARC
   - Extraction et analyse des IPs

2. **Pièce Jointe** - Analyser les fichiers suspects
   - Calcul automatique des hash
   - Vérification VirusTotal

3. **URL** - Analyser les URLs suspectes
   - Scan URLScan.io
   - Vérification VirusTotal

4. **IP** - Analyser les adresses IP
   - VirusTotal check
   - AbuseIPDB reputation

5. **Historique** - Voir les analyses précédentes
   - Accès rapide aux rapports

## 💾 Structure de la Base de Données

```sql
-- Email Analysis
CREATE TABLE email_analysis (
    id INTEGER PRIMARY KEY,
    email_hash TEXT UNIQUE,
    sender TEXT,
    subject TEXT,
    analysis_data TEXT,  -- JSON
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- File Hashes
CREATE TABLE file_hashes (
    id INTEGER PRIMARY KEY,
    file_hash TEXT UNIQUE,
    hash_type TEXT,  -- md5, sha1, sha256
    analysis_data TEXT,  -- JSON
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- IP Analysis
CREATE TABLE ip_analysis (
    id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE,
    analysis_data TEXT,  -- JSON (VT + AbuseIPDB)
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- URL Analysis
CREATE TABLE url_analysis (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    analysis_data TEXT,  -- JSON (VT + URLScan)
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

## 🔄 Workflow d'Analyse

```
Email Reçu
    ↓
[Email Parser]
    ├─ Parse headers
    ├─ Extrait SPF/DKIM/DMARC
    └─ Extrait IPs et domaines
    ↓
[Hash Calculator]
    └─ Calcule MD5, SHA1, SHA256
    ↓
[API Clients]
    ├─ VirusTotal Check
    ├─ URLScan.io Scan
    └─ AbuseIPDB Check
    ↓
[Database]
    └─ Cache les résultats
    ↓
[Web Interface]
    └─ Affiche le rapport complet
```

## 🛡️ Bonnes Pratiques de Sécurité

1. **Protéger les clés API**
   - Jamais commit `.env` en Git
   - Utiliser des variables d'environnement en production

2. **Validation des entrées**
   - Valider les IPs avant envoi API
   - Valider les URLs (format)

3. **Rate Limiting**
   - Respecter les limites des APIs
   - Implémenter un backoff exponentiel

4. **HTTPS en production**
   - Configurer SSL/TLS
   - Utiliser Gunicorn + Nginx

## 🐛 Debugging

### Activer les logs verbeux
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Tester une API individuellement
```python
from backend.api_clients import VirusTotalClient
vt = VirusTotalClient()
print(vt.check_ip("8.8.8.8"))
```

### Vérifier la base de données
```python
from backend.database import Database
db = Database()
analyses = db.get_all_analyses(10)
print(analyses)
```

## 📚 Ressources Utiles

- [VirusTotal API](https://developers.virustotal.com/v3.0/reference)
- [URLScan.io API](https://urlscan.io/docs/api/)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [RFC 7208 - SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 6376 - DKIM](https://tools.ietf.org/html/rfc6376)
- [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)

## ❓ FAQ

**Q: Comment ajouter un nouvel service d'analyse?**
A: Créer une nouvelle classe dans `api_clients.py` et l'intégrer à `analyzer.py`

**Q: Puis-je utiliser cela en production?**
A: Oui, mais avec Gunicorn/uWSGI + Nginx, HTTPS, et base de données PostgreSQL

**Q: Comment ajouter l'authentification?**
A: Installer `Flask-Login` et ajouter des décorateurs `@login_required`

**Q: Puis-je analyser les emails directement depuis ma boîte mail?**
A: Oui, avec IMAP (voir futur module `email_client.py`)

---

**Dernière mise à jour:** Avril 2026
