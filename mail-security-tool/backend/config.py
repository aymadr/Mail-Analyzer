"""
Configuration centralisée - Gérer les variables d'environnement et credentials
"""
import os
from dotenv import load_dotenv

load_dotenv()

# API Keys - À remplir dans le fichier .env
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Configuration Base de Données
DB_PATH = os.getenv("DB_PATH", "data/results.db")

# Configuration API
API_TIMEOUT = 10
MAX_RETRIES = 3

# Rate limiting (requêtes par seconde)
VIRUSTOTAL_RATE_LIMIT = 4  # 4 req/min gratuit
URLSCAN_RATE_LIMIT = 1
ABUSEIPDB_RATE_LIMIT = 1
