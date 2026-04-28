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

# Any.Run integration (optional)
ANYRUN_ENABLED = os.getenv("ANYRUN_ENABLED", "false").lower() in {"1", "true", "yes"}
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY", "")
ANYRUN_BASE_URL = os.getenv("ANYRUN_BASE_URL", "https://api.any.run")
ANYRUN_SUBMIT_PATH = os.getenv("ANYRUN_SUBMIT_PATH", "/tasks/submit")
ANYRUN_REPORT_PATH = os.getenv("ANYRUN_REPORT_PATH", "/tasks/{task_id}/report")
ANYRUN_MAX_FILESIZE_MB = int(os.getenv("ANYRUN_MAX_FILESIZE_MB", "20"))
