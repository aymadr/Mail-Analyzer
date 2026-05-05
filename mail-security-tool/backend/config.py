"""
Configuration centralisée - Gérer les variables d'environnement et credentials
"""
import os
from dotenv import load_dotenv

load_dotenv()

def to_bool(value: str) -> bool:
    """Convert environment string to boolean."""
    return value.lower() in {"1", "true", "yes", "on"}

# API Keys - À remplir dans le fichier .env
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SCAMDOC_API_KEY = os.getenv("SCAMDOC_API_KEY", "")
SCAMDOC_BASE_URL = os.getenv("SCAMDOC_BASE_URL", "https://scampredictor.p.rapidapi.com")
SCAMDOC_URL_PATH = os.getenv("SCAMDOC_URL_PATH", "/domain/{domain_name}")
SCAMDOC_EMAIL_PATH = os.getenv("SCAMDOC_EMAIL_PATH", "/email/{email}")
SCAMDOC_RAPIDAPI_HOST = os.getenv("SCAMDOC_RAPIDAPI_HOST", "scampredictor.p.rapidapi.com")

# Hybrid Analysis sandbox integration
HYBRID_ANALYSIS_ENABLED = to_bool(os.getenv("HYBRID_ANALYSIS_ENABLED", "true"))
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
HYBRID_ANALYSIS_BASE_URL = os.getenv("HYBRID_ANALYSIS_BASE_URL", "https://hybrid-analysis.com/api/v2")
HYBRID_ANALYSIS_USER_AGENT = os.getenv("HYBRID_ANALYSIS_USER_AGENT", "Falcon")
HYBRID_ANALYSIS_TIMEOUT = int(os.getenv("HYBRID_ANALYSIS_TIMEOUT", "60"))
HYBRID_ANALYSIS_MAX_FILESIZE_MB = int(os.getenv("HYBRID_ANALYSIS_MAX_FILESIZE_MB", "30"))

# Configuration Base de Données
DB_PATH = os.getenv("DB_PATH", "data/results.db")

# Configuration API
API_TIMEOUT = 10
MAX_RETRIES = 3
SCAMDOC_TIMEOUT = 30

# MXToolbox DNS API integration
MXTOOLBOX_ENABLED = to_bool(os.getenv("MXTOOLBOX_ENABLED", "true"))
MXTOOLBOX_API_KEY = os.getenv("MXTOOLBOX_API_KEY", "")
MXTOOLBOX_BASE_URL = os.getenv("MXTOOLBOX_BASE_URL", "https://mxtoolbox.com/api/v1")
MXTOOLBOX_TIMEOUT = int(os.getenv("MXTOOLBOX_TIMEOUT", "10"))

# Rate limiting (requêtes par seconde)
VIRUSTOTAL_RATE_LIMIT = 4  # 4 req/min gratuit
URLSCAN_RATE_LIMIT = 1
ABUSEIPDB_RATE_LIMIT = 1
SCAMDOC_RATE_LIMIT = 1
MXTOOLBOX_RATE_LIMIT = 1
