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
SCAMDOC_API_KEY = os.getenv("SCAMDOC_API_KEY", "")
SCAMDOC_BASE_URL = os.getenv("SCAMDOC_BASE_URL", "https://scampredictor.p.rapidapi.com")
SCAMDOC_URL_PATH = os.getenv("SCAMDOC_URL_PATH", "/domain/{domain_name}")
SCAMDOC_EMAIL_PATH = os.getenv("SCAMDOC_EMAIL_PATH", "/email/{email}")
SCAMDOC_RAPIDAPI_HOST = os.getenv("SCAMDOC_RAPIDAPI_HOST", "scampredictor.p.rapidapi.com")

# Any.Run sandbox integration (optional)
ANYRUN_ENABLED = os.getenv("ANYRUN_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY", "")
ANYRUN_BASE_URL = os.getenv("ANYRUN_BASE_URL", "https://api.any.run")
ANYRUN_SUBMIT_PATH = os.getenv("ANYRUN_SUBMIT_PATH", "/tasks/submit")
ANYRUN_REPORT_PATH = os.getenv("ANYRUN_REPORT_PATH", "/tasks/{task_id}/report")
ANYRUN_AUTH_HEADER = os.getenv("ANYRUN_AUTH_HEADER", "Authorization")
ANYRUN_AUTH_PREFIX = os.getenv("ANYRUN_AUTH_PREFIX", "Bearer ")
ANYRUN_TIMEOUT = int(os.getenv("ANYRUN_TIMEOUT", "60"))
ANYRUN_MAX_FILESIZE_MB = int(os.getenv("ANYRUN_MAX_FILESIZE_MB", "20"))

# Configuration Base de Données
DB_PATH = os.getenv("DB_PATH", "data/results.db")

# Configuration API
API_TIMEOUT = 10
MAX_RETRIES = 3
SCAMDOC_TIMEOUT = 30

# Rate limiting (requêtes par seconde)
VIRUSTOTAL_RATE_LIMIT = 4  # 4 req/min gratuit
URLSCAN_RATE_LIMIT = 1
ABUSEIPDB_RATE_LIMIT = 1
SCAMDOC_RATE_LIMIT = 1
