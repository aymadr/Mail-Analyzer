"""
Clients API pour VirusTotal, URLScan.io, AbuseIPDB
"""
import requests
import time
from typing import Dict, Optional
from config import (
    VIRUSTOTAL_API_KEY, URLSCAN_API_KEY, ABUSEIPDB_API_KEY,
    API_TIMEOUT, MAX_RETRIES
)

class APIClient:
    """Classe de base avec gestion des retries"""
    
    @staticmethod
    def retry_request(func, *args, **kwargs):
        """Retry logic pour les requêtes"""
        for attempt in range(MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except requests.RequestException as e:
                if attempt == MAX_RETRIES - 1:
                    raise
                time.sleep(2 ** attempt)  # Exponential backoff


class VirusTotalClient(APIClient):
    """Client VirusTotal pour analyser fichiers/URLs/IPs"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self):
        self.api_key = VIRUSTOTAL_API_KEY
        self.headers = {"x-apikey": self.api_key}
    
    def check_file_hash(self, file_hash: str) -> Dict:
        """Recherche un hash de fichier (MD5, SHA1, SHA256)"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        url = f"{self.BASE_URL}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=API_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            return {
                "source": "VirusTotal",
                "hash": file_hash,
                "stats": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
                "verdict": self._analyze_verdict(data),
                "url": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        except Exception as e:
            return {"error": str(e), "source": "VirusTotal"}
    
    def check_url(self, url: str) -> Dict:
        """Analyse une URL"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            # Encoder l'URL
            url_id = requests.utils.requote_uri(url)
            vt_url = f"{self.BASE_URL}/urls/{url_id}"
            
            response = requests.get(vt_url, headers=self.headers, timeout=API_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            return {
                "source": "VirusTotal",
                "url": url,
                "stats": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
                "verdict": self._analyze_verdict(data),
            }
        except Exception as e:
            return {"error": str(e), "source": "VirusTotal"}
    
    def check_ip(self, ip: str) -> Dict:
        """Analyse une adresse IP"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            url = f"{self.BASE_URL}/ip_addresses/{ip}"
            response = requests.get(url, headers=self.headers, timeout=API_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "source": "VirusTotal",
                "ip": ip,
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                "url": f"https://www.virustotal.com/gui/ip-address/{ip}"
            }
        except Exception as e:
            return {"error": str(e), "source": "VirusTotal"}
    
    @staticmethod
    def _analyze_verdict(data: Dict) -> str:
        """Analyse le verdict basé sur les stats"""
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        
        if malicious > 5:
            return "MALICIOUS"
        elif malicious > 0:
            return "SUSPICIOUS"
        else:
            return "CLEAN"


class URLScanIOClient(APIClient):
    """Client URLScan.io pour analyser URLs"""
    
    BASE_URL = "https://urlscan.io/api/v1"
    
    def __init__(self):
        self.api_key = URLSCAN_API_KEY
        self.headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
    
    def scan_url(self, url: str) -> Dict:
        """Lance une analyse d'URL"""
        if not self.api_key:
            return {"error": "URLScan API key not configured"}
        
        try:
            payload = {"url": url, "visibility": "public"}
            response = requests.post(
                f"{self.BASE_URL}/scan/",
                json=payload,
                headers=self.headers,
                timeout=API_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            
            return {
                "source": "URLScan.io",
                "url": url,
                "scan_id": data.get("uuid"),
                "result_url": data.get("result"),
                "report_url": data.get("report")
            }
        except Exception as e:
            return {"error": str(e), "source": "URLScan.io"}
    
    def get_result(self, scan_uuid: str) -> Dict:
        """Récupère les résultats d'un scan"""
        if not self.api_key:
            return {"error": "URLScan API key not configured"}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/result/{scan_uuid}/",
                headers=self.headers,
                timeout=API_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            
            return {
                "source": "URLScan.io",
                "scan_id": scan_uuid,
                "stats": data.get("stats", {}),
                "verdicts": data.get("verdicts", {}),
                "screenshot": data.get("screenshot"),
                "url": data.get("page", {}).get("url")
            }
        except Exception as e:
            return {"error": str(e), "source": "URLScan.io"}


class AbuseIPDBClient(APIClient):
    """Client AbuseIPDB pour analyser IPs"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self):
        self.api_key = ABUSEIPDB_API_KEY
    
    def check_ip(self, ip: str, max_age_in_days: int = 90) -> Dict:
        """Vérifie une IP sur AbuseIPDB"""
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": max_age_in_days,
                "verbose": ""
            }
            
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=headers,
                params=params,
                timeout=API_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            
            abuse_data = data.get("data", {})
            return {
                "source": "AbuseIPDB",
                "ip": ip,
                "abuse_confidence_score": abuse_data.get("abuseConfidenceScore"),
                "total_reports": abuse_data.get("totalReports"),
                "is_whitelisted": abuse_data.get("isWhitelisted"),
                "is_blacklisted": abuse_data.get("isBlacklisted"),
                "reports": abuse_data.get("reports", [])[:5],  # Derniers 5 rapports
                "url": f"https://www.abuseipdb.com/check/{ip}"
            }
        except Exception as e:
            return {"error": str(e), "source": "AbuseIPDB"}


if __name__ == "__main__":
    # Tests
    # vt = VirusTotalClient()
    # print(vt.check_ip("8.8.8.8"))
    
    # abuseipdb = AbuseIPDBClient()
    # print(abuseipdb.check_ip("8.8.8.8"))
    pass
