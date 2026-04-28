"""
Clients API pour VirusTotal, URLScan.io, AbuseIPDB
"""
import requests
import time
import base64
from typing import Dict, Optional
from pathlib import Path
from config import (
    VIRUSTOTAL_API_KEY, URLSCAN_API_KEY, ABUSEIPDB_API_KEY,
    API_TIMEOUT, MAX_RETRIES
)
from config import (
    ANYRUN_ENABLED, ANYRUN_API_KEY, ANYRUN_BASE_URL,
    ANYRUN_SUBMIT_PATH, ANYRUN_REPORT_PATH, ANYRUN_MAX_FILESIZE_MB
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
            # VirusTotal v3 attend l'URL en base64 url-safe sans padding
            url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
            vt_url = f"{self.BASE_URL}/urls/{url_id}"
            
            response = requests.get(vt_url, headers=self.headers, timeout=API_TIMEOUT)
            if response.status_code == 404:
                # L'URL n'existe pas encore côté VT: on soumet un scan
                submit = requests.post(
                    f"{self.BASE_URL}/urls",
                    headers=self.headers,
                    data={"url": url},
                    timeout=API_TIMEOUT
                )
                submit.raise_for_status()
                submit_data = submit.json()
                analysis_id = submit_data.get("data", {}).get("id")
                return {
                    "source": "VirusTotal",
                    "url": url,
                    "status": "QUEUED",
                    "analysis_id": analysis_id,
                    "message": "URL soumise a VirusTotal, resultat en attente"
                }

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

    def check_file(self, file_path: str, file_hash: Optional[str] = None) -> Dict:
        """Analyse un fichier: hash lookup puis upload si inconnu"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured", "source": "VirusTotal"}

        if file_hash:
            hash_result = self.check_file_hash(file_hash)
            if not hash_result.get("error"):
                return hash_result

        try:
            with open(file_path, "rb") as file_obj:
                response = requests.post(
                    f"{self.BASE_URL}/files",
                    headers=self.headers,
                    files={"file": file_obj},
                    timeout=API_TIMEOUT
                )
            response.raise_for_status()

            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            return {
                "source": "VirusTotal",
                "status": "QUEUED",
                "analysis_id": analysis_id,
                "message": "Fichier envoye a VirusTotal, resultat en attente"
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
    REPORT_WAIT_TIMEOUT = 60  # Attendre max 60 secondes
    REPORT_CHECK_INTERVAL = 2  # Vérifier toutes les 2 secondes
    
    def __init__(self):
        self.api_key = URLSCAN_API_KEY
        self.headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
    
    def scan_url(self, url: str) -> Dict:
        """Lance une analyse d'URL et attend que le rapport soit prêt"""
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
            
            scan_id = data.get("uuid")
            result_url = data.get("result")
            report_url = data.get("report")
            
            # Attendre que le rapport soit prêt
            is_ready = self._wait_for_report(result_url)
            
            return {
                "source": "URLScan.io",
                "url": url,
                "scan_id": scan_id,
                "result_url": result_url,
                "report_url": report_url,
                "ready": is_ready
            }
        except Exception as e:
            return {"error": str(e), "source": "URLScan.io"}
    
    def _wait_for_report(self, result_url: str, timeout: int = REPORT_WAIT_TIMEOUT) -> bool:
        """Attend que le rapport soit disponible sur result_url"""
        elapsed = 0
        while elapsed < timeout:
            try:
                # Faire une requête HEAD pour vérifier que le rapport existe
                response = requests.head(
                    result_url,
                    timeout=API_TIMEOUT
                )
                # Si on reçoit 200, le rapport est prêt
                if response.status_code == 200:
                    return True
            except Exception:
                pass
            
            # Attendre avant prochain essai
            time.sleep(self.REPORT_CHECK_INTERVAL)
            elapsed += self.REPORT_CHECK_INTERVAL
        
        # Timeout atteint
        return False
    
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


class AnyRunClient(APIClient):
    """Client minimal pour Any.Run (configurable via .env).

    NOTE: Any.Run a des API propriétaires; ici on fournit une intégration
    générique basée sur `ANYRUN_BASE_URL` et chemins configurables.
    Ajuste `ANYRUN_SUBMIT_PATH` et `ANYRUN_REPORT_PATH` dans `.env` si
    nécessaire pour correspondre à l'API réelle.
    """

    def __init__(self):
        self.enabled = bool(ANYRUN_ENABLED)
        self.api_key = ANYRUN_API_KEY
        self.base_url = ANYRUN_BASE_URL.rstrip("/")
        self.submit_path = ANYRUN_SUBMIT_PATH
        self.report_path = ANYRUN_REPORT_PATH
        self.max_filesize_mb = ANYRUN_MAX_FILESIZE_MB

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def submit_file(self, file_path: str, metadata: Optional[Dict] = None) -> Dict:
        """Soumet un fichier à Any.Run. Retourne le JSON de la réponse ou une erreur."""
        if not self.enabled:
            return {"error": "Any.Run integration disabled", "source": "AnyRun"}
        if not self.api_key:
            return {"error": "Any.Run API key not configured", "source": "AnyRun"}

        try:
            size_mb = Path(file_path).stat().st_size / (1024 * 1024)
            if size_mb > self.max_filesize_mb:
                return {"error": f"File too large for Any.Run (>{self.max_filesize_mb} MB)", "source": "AnyRun"}
        except Exception:
            pass

        headers = {"Authorization": f"Bearer {self.api_key}"}
        files = {"file": open(file_path, "rb")}
        data = metadata or {}

        try:
            resp = requests.post(self._url(self.submit_path), headers=headers, files=files, data=data, timeout=API_TIMEOUT)
            files["file"].close()
            resp.raise_for_status()
            return {"source": "AnyRun", "response": resp.json()}
        except Exception as e:
            return {"error": str(e), "source": "AnyRun"}

    def submit_url(self, url: str, metadata: Optional[Dict] = None) -> Dict:
        """Soumet une URL pour analyse dynamique (si supporté)."""
        if not self.enabled:
            return {"error": "Any.Run integration disabled", "source": "AnyRun"}
        if not self.api_key:
            return {"error": "Any.Run API key not configured", "source": "AnyRun"}

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {"url": url}
        if metadata:
            payload.update(metadata)

        try:
            resp = requests.post(self._url(self.submit_path), headers=headers, json=payload, timeout=API_TIMEOUT)
            resp.raise_for_status()
            return {"source": "AnyRun", "response": resp.json()}
        except Exception as e:
            return {"error": str(e), "source": "AnyRun"}

    def get_report(self, task_id: str) -> Dict:
        """Récupère le rapport d'un job Any.Run via le chemin configuré."""
        if not self.enabled:
            return {"error": "Any.Run integration disabled", "source": "AnyRun"}
        if not self.api_key:
            return {"error": "Any.Run API key not configured", "source": "AnyRun"}

        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            path = self.report_path.format(task_id=task_id)
            resp = requests.get(self._url(path), headers=headers, timeout=API_TIMEOUT)
            resp.raise_for_status()
            return {"source": "AnyRun", "report": resp.json()}
        except Exception as e:
            return {"error": str(e), "source": "AnyRun"}


if __name__ == "__main__":
    # Tests
    # vt = VirusTotalClient()
    # print(vt.check_ip("8.8.8.8"))
    
    # abuseipdb = AbuseIPDBClient()
    # print(abuseipdb.check_ip("8.8.8.8"))
    pass
