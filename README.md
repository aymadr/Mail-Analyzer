# Mail Security Analyzer 🔒

Outil d'analyse de sécurité email centralisé intégrant VirusTotal, URLScan.io et AbuseIPDB.

## 🎯 Fonctionnalités

- ✅ **Analyse d'email** : Parse entête SPF, DKIM, DMARC
- ✅ **Extraction d'informations** : IPs, domaines, en-têtes
- ✅ **Calcul de hash** : MD5, SHA1, SHA256
- ✅ **Analyse de pièces jointes** : Vérification VirusTotal
- ✅ **Analyse d'URLs** : Vérification VirusTotal + URLScan.io
- ✅ **Analyse d'IPs** : VirusTotal + AbuseIPDB
- ✅ **Base de données** : Cache local SQLite
- ✅ **Interface web** : Dashboard moderne et intuitif

## 📊 Architecture

```
mail-security-tool/
├── backend/
│   ├── config.py              # Configuration centralisée
│   ├── email_parser.py        # Parser d'entête email
│   ├── hash_calculator.py     # Calcul de hash
│   ├── api_clients.py         # Clients API (VT, URLScan, AbuseIPDB)
│   ├── database.py            # Gestion SQLite
│   └── analyzer.py            # Orchestrateur principal
├── frontend/
│   ├── app.py                 # Serveur Flask
│   ├── templates/
│   │   └── index.html         # Interface web
│   └── static/
│       ├── style.css          # Styles
│       └── script.js          # JavaScript frontend
├── data/                       # Base de données
├── requirements.txt           # Dépendances Python
├── .env                       # Variables d'environnement
└── README.md                  # Ce fichier
```

## 🚀 Installation

### Prérequis
- Python 3.8+
- pip

### Étapes

1. **Cloner/télécharger le projet**
   ```bash
   cd mail-security-tool
   ```

2. **Créer un environnement virtuel**
   ```bash
   python -m venv venv
   source venv/Scripts/activate  # Windows
   # ou
   source venv/bin/activate      # Linux/Mac
   ```

3. **Installer les dépendances**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configurer les clés API**
   - Éditer le fichier `.env`
   - Ajouter tes clés API VirusTotal, URLScan.io, AbuseIPDB

   **Obtenir les clés API :**
   - [VirusTotal](https://www.virustotal.com/gui/home/upload)
   - [URLScan.io](https://urlscan.io/)
   - [AbuseIPDB](https://www.abuseipdb.com/)

5. **Lancer l'application**
   ```bash
   cd frontend
   python app.py
   ```

6. **Accéder à l'interface**
   - Ouvrir navigateur: `http://127.0.0.1:5000`

## 📖 Utilisation

### 1. Analyse d'Email
- Charger un fichier `.eml` ou `.msg`
- Le système parse automatiquement:
  - En-têtes SPF, DKIM, DMARC
  - IPs et domaines
  - Vérifie les IPs sur VirusTotal et AbuseIPDB

### 2. Analyse de Pièce Jointe
- Charger le fichier suspect
- Calcule: MD5, SHA1, SHA256
- Vérifie les hash sur VirusTotal
- Affiche le verdict (Malveillant/Suspect/Propre)

### 3. Analyse d'URL
- Entrer une URL
- Analyse via VirusTotal et URLScan.io
- Affiche le verdict et les détails

### 4. Analyse d'IP
- Entrer une adresse IP
- Vérifie sur VirusTotal et AbuseIPDB
- Affiche pays, ASN, score de confiance abus

## 🔧 Configuration Avancée

### Modifier le timeout API
```python
# backend/config.py
API_TIMEOUT = 15  # secondes
```

### Changer le chemin de la BD
```python
# backend/config.py
DB_PATH = "chemin/vers/ma/bdd.db"
```

### Rate Limiting
```python
# backend/config.py
VIRUSTOTAL_RATE_LIMIT = 4    # 4 req/min
URLSCAN_RATE_LIMIT = 1       # 1 req/s
ABUSEIPDB_RATE_LIMIT = 1     # 1 req/s
```

## 📝 API Endpoints

### Email
```
POST /api/analyze/email
Body: multipart/form-data (file)
```

### Pièce Jointe
```
POST /api/analyze/attachment
Body: multipart/form-data (file)
```

### URL
```
POST /api/analyze/url
Body: {"url": "https://example.com"}
```

### IP
```
POST /api/analyze/ip
Body: {"ip": "8.8.8.8"}
```

### Historique
```
GET /api/history?limit=50
```

### Rapport
```
GET /api/report/<email_hash>
```

## 🔐 Sécurité

- ✅ Clés API dans `.env` (jamais en dur)
- ✅ Validation des fichiers uploadés
- ✅ Limite de taille (50MB)
- ✅ Validation des IPs/URLs
- ✅ CORS à configurer si nécessaire

## 🐛 Troubleshooting

### "API key not configured"
→ Vérifie ton fichier `.env`

### Erreur de timeout
→ Augmente `API_TIMEOUT` dans `config.py`

### Port 5000 déjà utilisé
```bash
python app.py --port 5001
```

## 📈 À améliorer

- [ ] Authentication utilisateur
- [ ] Export PDF/CSV des rapports
- [ ] Dashboard analytics
- [ ] Intégration Slack/Email pour alertes
- [ ] Support multi-threading
- [ ] Docker container
- [ ] Tests unitaires

## 📄 License

MIT

## 👥 Support

Pour des questions ou améliorations, n'hésite pas à me contacter !

---

**Dernière mise à jour:** Avril 2026
