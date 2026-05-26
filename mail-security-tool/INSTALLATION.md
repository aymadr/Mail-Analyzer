# Installation et Utilisation - Windows Only

##  Démarrage Rapide

###  Option 1: Interface Web 

**Méthode 1A - Double-cliquer sur `run.bat` (le plus simple)**
```batch
run.bat
```
→ L'application démarre automatiquement sur http://127.0.0.1:5000

**Méthode 1B - Via PowerShell**
```powershell
# 1. Aller au dossier du projet
cd mail-security-tool

# 2. Activer l'environnement virtuel
.\venv\Scripts\Activate.ps1

# 3. Installer les dépendances (première fois seulement)
pip install -r requirements.txt

# 4. Configurer les clés API
# Éditer le fichier .env avec tes clés API (VirusTotal, URLScan, AbuseIPDB, Scamdoc, MXToolbox, Hybrid Analysis)

# 5. Lancer
python run.py
```

**Méthode 1C - Via CMD (Invite de commande)**
```batch
REM 1. Aller au dossier
cd mail-security-tool

REM 2. Activer l'environnement virtuel
venv\Scripts\activate.bat

REM 3. Installer les dépendances (première fois seulement)
pip install -r requirements.txt

REM 4. Éditer .env avec tes clés API

REM 5. Lancer
python run.py
```

→ L'application démarre sur http://127.0.0.1:5000

###  Option 2: Docker

**Prérequis:** Docker Desktop installé sur Windows

```powershell
# 1. Aller au dossier du projet
cd mail-security-tool

# 2. Préparer les variables d'environnement
copy .env.example .env
# Puis éditer .env avec tes clés API

# 3. Construire et démarrer le conteneur
docker compose up --build -d

# 4. Ouvrir http://127.0.0.1:5000
```

Commandes Docker utiles:
```powershell
# Voir les logs
docker compose logs -f

# Arrêter les services
docker compose down

# Afficher les conteneurs en cours
docker ps
```

##  Obtenir les Clés API

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

### 4. ScamDoc
1. Aller sur https://rapidapi.com/
2. Créer un compte (gratuit)
3. Aller dans la barre de recherche, et chercher "ScamPredictor"
4. Prendre la version basique (gratuite)
5. Aller dans API Overview, et récupérer la "X-RapidAPI-Key"

```env
SCAMDOC_API_KEY=YOUR_API_KEY_HERE
```

### 5. MXToolbox
1. Aller sur https://rapidapi.com/ et rechercher "MXToolbox"
2. S'abonner au plan souhaité
3. Récupérer la clé RapidAPI

```env
MXTOOLBOX_ENABLED=true
MXTOOLBOX_API_KEY=YOUR_API_KEY_HERE
MXTOOLBOX_BASE_URL=https://mxtoolbox.com/api/v1
```

### 6. Hybrid Analysis
1. Aller sur https://hybrid-analysis.com/
2. Créer un compte et générer une clé API
3. Ajouter les variables dans `.env`

```env
HYBRID_ANALYSIS_ENABLED=true
HYBRID_ANALYSIS_API_KEY=YOUR_API_KEY_HERE
HYBRID_ANALYSIS_BASE_URL=https://hybrid-analysis.com/api/v2
HYBRID_ANALYSIS_USER_AGENT=Falcon
HYBRID_ANALYSIS_MAX_FILESIZE_MB=30
```


##  Architecture Modulaire

### Backend Modules

#### 1. `config.py`
- Gestion des variables d'environnement
- Paramètres API et timeouts


#### 2. `email_parser.py`
- Parse des entêtes email
- Extraction SPF, DKIM, DMARC
- Extraction IPs et domaines


#### 3. `hash_calculator.py`
- Calcul MD5, SHA1, SHA256
- Calcul depuis fichier ou bytes


#### 4. `api_clients.py`
- Clients pour VirusTotal, URLScan.io, AbuseIPDB, Scamdoc, MXToolbox et Hybrid Analysis
- Gestion des retries et erreurs


#### 5. `database.py`
- Cache SQLite
- Sauvegarde/récupération des analyses



#### 6. `analyzer.py`
- Orchestrateur principal
- Coordonne toutes les analyses


##  Utilisation du Frontend

### Onglets Disponibles

1. **Email** - Analyser un fichier email
   - Parse automatique SPF/DKIM/DMARC
   - Extraction et analyse des IPs
    - Vérifications via VirusTotal, AbuseIPDB, Scamdoc et MXToolbox

2. **Pièce Jointe** - Analyser les fichiers suspects
   - Calcul automatique des hash
    - Vérification VirusTotal (+ Hybrid Analysis optionnel)

3. **URL** - Analyser les URLs suspectes
   - Scan URLScan.io
    - Vérification VirusTotal, Scamdoc, MXToolbox DNS (+ Hybrid Analysis optionnel)

4. **IP** - Analyser les adresses IP
    - VirusTotal et AbuseIPDB
    - MXToolbox PTR/RBL

5. **Historique** - Voir les analyses précédentes
   - Accès rapide aux rapports

##  Structure de la Base de Données

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
    analysis_data TEXT,  -- JSON (VT + AbuseIPDB + MXToolbox)
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- URL Analysis
CREATE TABLE url_analysis (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    analysis_data TEXT,  -- JSON (VT + URLScan + Scamdoc + MXToolbox + Hybrid Analysis)
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

##  Workflow d'Analyse

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
    ├─ AbuseIPDB Check
    ├─ Scamdoc Check
    ├─ MXToolbox DNS/PTR/RBL
    └─ Hybrid Analysis (optionnel)
    ↓
[Database]
    └─ Cache les résultats
    ↓
[Web Interface]
    └─ Affiche le rapport complet
```

##  Bonnes Pratiques de Sécurité

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

##  Debugging

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

##  Ressources Utiles

- [VirusTotal API](https://developers.virustotal.com/v3.0/reference)
- [URLScan.io API](https://urlscan.io/docs/api/)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [RFC 7208 - SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 6376 - DKIM](https://tools.ietf.org/html/rfc6376)
- [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)

