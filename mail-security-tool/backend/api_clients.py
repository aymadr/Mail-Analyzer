"""
Clients API pour VirusTotal, URLScan.io, AbuseIPDB
"""
import requests
import time
import base64
import logging
from pathlib import Path
from urllib.parse import urljoin
from urllib.parse import urlparse
from typing import Dict, Optional

logger = logging.getLogger(__name__)
from config import (
    VIRUSTOTAL_API_KEY, URLSCAN_API_KEY, ABUSEIPDB_API_KEY,
    SCAMDOC_API_KEY, SCAMDOC_BASE_URL, SCAMDOC_URL_PATH, SCAMDOC_EMAIL_PATH, SCAMDOC_RAPIDAPI_HOST, SCAMDOC_TIMEOUT,
    API_TIMEOUT, MAX_RETRIES,
    HYBRID_ANALYSIS_ENABLED, HYBRID_ANALYSIS_API_KEY, HYBRID_ANALYSIS_BASE_URL, HYBRID_ANALYSIS_USER_AGENT, HYBRID_ANALYSIS_TIMEOUT, HYBRID_ANALYSIS_MAX_FILESIZE_MB
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
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return {"error": "Hash not found", "source": "VirusTotal"}
            return {"error": "Hash not found", "source": "VirusTotal"}
        except Exception as e:
            return {"error": "Hash not found", "source": "VirusTotal"}
    
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


class HybridAnalysisClient(APIClient):
    """Client Hybrid Analysis (Falcon Sandbox) pour quick-scan d'URLs et fichiers.
    
    API v2: https://hybrid-analysis.com/api/v2
    Endpoints: /quick-scan/file, /quick-scan/url, /overview/{sha256}
    """

    def __init__(self):
        self.enabled = HYBRID_ANALYSIS_ENABLED
        self.api_key = HYBRID_ANALYSIS_API_KEY
        self.base_url = HYBRID_ANALYSIS_BASE_URL.rstrip("/")
        self.user_agent = HYBRID_ANALYSIS_USER_AGENT
        self.timeout = HYBRID_ANALYSIS_TIMEOUT
        self.max_filesize_mb = HYBRID_ANALYSIS_MAX_FILESIZE_MB

    def _headers(self) -> Dict:
        """Build request headers with API key and user agent."""
        headers = {
            "User-Agent": "Falcon",
            "api-key": self.api_key,
        }
        return headers

    def submit_file(self, file_path: str, metadata: Optional[Dict] = None) -> Dict:
        """Submit file to Hybrid Analysis quick-scan."""
        if not self.enabled:
            return {"source": "HybridAnalysis", "status": "DISABLED"}
        if not self.api_key:
            return {"error": "Hybrid Analysis API key not configured", "source": "HybridAnalysis"}

        try:
            file_size_mb = Path(file_path).stat().st_size / (1024 * 1024)
            if file_size_mb > self.max_filesize_mb:
                return {
                    "source": "HybridAnalysis",
                    "status": "SKIPPED",
                    "error": f"File > {self.max_filesize_mb}MB",
                }
        except Exception:
            pass

        try:
            with open(file_path, "rb") as f:
                files = {"file": (Path(file_path).name, f, "application/octet-stream")}
                data = {
                    "scan_type": "all"
                }
                
                response = requests.post(
                    f"{self.base_url}/quick-scan/file",
                    headers=self._headers(),
                    files=files,
                    data=data,
                    timeout=self.timeout,
                )
            
            if response.status_code >= 400:
                return {"error": f"{response.status_code}: {response.text}", "source": "HybridAnalysis"}
            
            result = response.json()
            logger.info(f"[HybridAnalysis] submit_file response keys: {result.keys()}")
            logger.info(f"[HybridAnalysis] Full response: {result}")
            return {
                "source": "HybridAnalysis",
                "status": "SUBMITTED",
                "job_id": result.get("job_id"),
                "sha256": result.get("sha256"),
                "report_url": f"https://hybrid-analysis.com/sample/{result.get('sha256')}",
            }
        except Exception as e:
            return {"error": str(e), "source": "HybridAnalysis"}

    def submit_url(self, url: str, metadata: Optional[Dict] = None) -> Dict:
        """Submit URL to Hybrid Analysis quick-scan."""
        if not self.enabled:
            return {"source": "HybridAnalysis", "status": "DISABLED"}
        if not self.api_key:
            return {"error": "Hybrid Analysis API key not configured", "source": "HybridAnalysis"}

        try:
            data = {
                "url": url,
                "scan_type": "all"
            }
            
            response = requests.post(
                f"{self.base_url}/quick-scan/url",
                headers=self._headers(),
                data=data,
                timeout=self.timeout,
            )
            
            if response.status_code >= 400:
                return {"error": f"{response.status_code}: {response.text}", "source": "HybridAnalysis"}
            
            result = response.json()
            logger.info(f"[HybridAnalysis] submit_url response keys: {result.keys()}")
            logger.info(f"[HybridAnalysis] Full response: {result}")
            return {
                "source": "HybridAnalysis",
                "status": "SUBMITTED",
                "job_id": result.get("job_id"),
                "url": url,
                "report_url": f"https://hybrid-analysis.com/submission/{result.get('job_id')}",
            }
        except Exception as e:
            return {"error": str(e), "source": "HybridAnalysis"}

    def get_report(self, sha256: str) -> Dict:
        """Get overview/report for a file by SHA256."""
        if not self.enabled:
            return {"source": "HybridAnalysis", "status": "DISABLED"}
        if not self.api_key:
            return {"error": "Hybrid Analysis API key not configured", "source": "HybridAnalysis"}

        try:
            response = requests.get(
                f"{self.base_url}/overview/{sha256}",
                headers=self._headers(),
                timeout=self.timeout,
            )
            response.raise_for_status()
            result = response.json()
            
            verdict = result.get("verdict", "unknown")
            threat_level = result.get("threat_level", 0)
            
            return {
                "source": "HybridAnalysis",
                "sha256": sha256,
                "verdict": verdict,
                "threat_level": threat_level,
                "summary": result.get("summary", ""),
                "report_url": f"https://hybrid-analysis.com/sample/{sha256}",
            }
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return {"error": "Hash not found", "source": "HybridAnalysis"}
            return {"error": "Hash not found", "source": "HybridAnalysis"}
        except Exception as e:
            return {"error": "Hash not found", "source": "HybridAnalysis"}

    def get_quick_scan_result(self, job_id: str) -> Dict:
        """Get quick-scan result by job ID."""
        if not self.enabled:
            return {"source": "HybridAnalysis", "status": "DISABLED"}
        if not self.api_key:
            return {"error": "Hybrid Analysis API key not configured", "source": "HybridAnalysis"}

        try:
            response = requests.get(
                f"{self.base_url}/quick-scan/{job_id}",
                headers=self._headers(),
                timeout=self.timeout,
            )
            
            if response.status_code >= 400:
                return {"error": f"{response.status_code}: {response.text}", "source": "HybridAnalysis"}
            
            result = response.json()
            
            return {
                "source": "HybridAnalysis",
                "job_id": job_id,
                "state": result.get("state"),
                "verdict": result.get("verdict", "unknown"),
                "threat_level": result.get("threat_level", 0),
                "type": result.get("type"),
                "sha256": result.get("sha256"),
                "report_url": f"https://hybrid-analysis.com/sample/{result.get('sha256')}" if result.get("sha256") else f"https://hybrid-analysis.com/sample/{job_id}",
                "full_report": result
            }
        except Exception as e:
            return {"error": str(e), "source": "HybridAnalysis"}

    def submit_and_wait(self, file_path: str = None, url: str = None, timeout: int = 120) -> Dict:
        """Submit file/URL and poll until result is ready."""
        if file_path:
            submit_result = self.submit_file(file_path)
        elif url:
            submit_result = self.submit_url(url)
        else:
            return {"error": "Either file_path or url required", "source": "HybridAnalysis"}
        
        if submit_result.get("error"):
            return submit_result
        
        job_id = submit_result.get("job_id")
        if not job_id:
            return {"error": "No job_id returned from submission", "source": "HybridAnalysis"}
        
        # Poll for result
        import time
        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self.get_quick_scan_result(job_id)
            
            if result.get("error"):
                return result
            
            # Check if analysis is complete
            state = result.get("state", "")
            if state not in ["running", "pending"]:
                return result
            
            time.sleep(2)  # Wait 2 seconds before retrying
        
        # Timeout reached
        return {
            "source": "HybridAnalysis",
            "job_id": job_id,
            "state": "timeout",
            "verdict": "unknown",
            "error": f"Analysis did not complete within {timeout} seconds"
        }


class ScamdocClient(APIClient):
    """Client Scamdoc / ScamPredictor pour analyser URL et email."""

    def __init__(self):
        self.api_key = SCAMDOC_API_KEY
        self.base_url = SCAMDOC_BASE_URL.rstrip("/")
        self.url_path = SCAMDOC_URL_PATH
        self.email_path = SCAMDOC_EMAIL_PATH
        self.rapidapi_host = SCAMDOC_RAPIDAPI_HOST or self._infer_host(self.base_url)

    def check_url(self, url: str, timeout: Optional[int] = None) -> Dict:
        """Analyse une URL avec Scamdoc."""
        if not self.api_key:
            return {"error": "Scamdoc API key not configured", "source": "Scamdoc"}

        domain = self._extract_domain_from_url(url)
        payload = {"url": url, "domain_name": domain, "domain": domain}

        candidate_paths = [
            self.url_path,
            "/Domain_trustscore/{domain_name}",
            "/domain_trustscore/{domain_name}",
            "/domain/{domain_name}",
        ]

        return self._request_with_fallback(candidate_paths, payload, timeout=timeout)

    def check_email(self, email_value: str, timeout: Optional[int] = None) -> Dict:
        """Analyse un email avec Scamdoc."""
        if not self.api_key:
            return {"error": "Scamdoc API key not configured", "source": "Scamdoc"}

        payload = {"email": email_value}
        candidate_paths = [
            self.email_path,
            "/Email_trustscore/{email}",
            "/email_trustscore/{email}",
            "/email/{email}",
        ]

        return self._request_with_fallback(candidate_paths, payload, timeout=timeout)

    def _request_with_fallback(self, paths, payload: Dict, timeout: Optional[int] = None) -> Dict:
        """Essaie plusieurs paths Scamdoc (RapidAPI variants) jusqu'au succès."""
        errors = []
        for candidate in paths:
            result = self._request(candidate, payload, timeout=timeout)
            if not result.get("error"):
                return result

            errors.append({
                "path": candidate,
                "error": result.get("error"),
                "endpoint": result.get("endpoint"),
            })

            # Sur timeout ou erreur réseau, inutile de tenter d'autres paths.
            message = (result.get("error") or "").lower()
            if "timed out" in message or "connection" in message:
                break

        return {
            "source": "Scamdoc",
            "error": errors[-1]["error"] if errors else "Unknown Scamdoc error",
            "target": payload,
            "attempts": errors,
            "endpoint": errors[-1].get("endpoint") if errors else None,
        }

    def _request(self, path: str, payload: Dict, timeout: Optional[int] = None) -> Dict:
        endpoint_path = path.format(**payload)
        endpoint = urljoin(f"{self.base_url}/", endpoint_path.lstrip("/"))
        headers = {
            "x-rapidapi-key": self.api_key,
            "x-rapidapi-host": self.rapidapi_host,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        # Si le path utilise des placeholders, on évite de doubler les infos en query params.
        params = {} if "{" in path else dict(payload)
        request_timeout = timeout or SCAMDOC_TIMEOUT

        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=request_timeout)
            if response.status_code >= 400:
                response = requests.post(endpoint, headers=headers, json=payload, timeout=request_timeout)

            response.raise_for_status()
            data = response.json() if response.text else {}

            return self._normalize_response(data, payload)
        except Exception as e:
            return {
                "source": "Scamdoc",
                "error": str(e),
                "target": payload,
                "endpoint": endpoint,
            }

    @staticmethod
    def _extract_domain_from_url(value: str) -> str:
        try:
            parsed = urlparse(value if "://" in value else f"https://{value}")
            return (parsed.hostname or value).lower()
        except Exception:
            return value.lower() if value else ""

    @staticmethod
    def _infer_host(base_url: str) -> str:
        try:
            return urlparse(base_url).netloc
        except Exception:
            return ""

    def _normalize_response(self, data: Dict, payload: Dict) -> Dict:
        # ScamPredictor specific logic: usually returns `{"class": 1...5}` where 1 is safe, 5 is malicious
        if "class" in data and isinstance(data["class"], (int, float)):
            cls_val = float(data["class"])
            
            # Map class 1-5 to a 0-100 risk score and 100-0 trust score
            risk_score = (cls_val - 1) * 25.0
            trust_score = 100.0 - risk_score
            
            if cls_val <= 2:
                verdict = "CLEAN"
            elif cls_val == 3:
                verdict = "SUSPICIOUS"
            else:
                verdict = "MALICIOUS"
        else:
            trust_score = self._pick_number(
                data,
                ["trust_score", "trustScore", "score_trust", "reliability_score", "trustscore", "score"]
            )
            risk_score = self._pick_number(
                data,
                ["risk_score", "riskScore", "scam_score", "fraud_score", "threat_score", "risk"]
            )
    
            verdict_raw = self._pick_value(data, ["verdict", "status", "result", "prediction", "label", "classif", "classification"]) 
            verdict = self._normalize_verdict(verdict_raw, trust_score, risk_score)
        
        detail_url = self._pick_value(data, ["url", "report_url", "link", "result_url"])

        return {
            "source": "Scamdoc",
            "target": payload,
            "verdict": verdict,
            "trust_score": trust_score,
            "risk_score": risk_score,
            "detail_url": detail_url,
            "raw": data,
        }

    @staticmethod
    def _pick_value(data: Dict, keys) -> Optional[str]:
        for key in keys:
            if key in data and data[key] not in (None, ""):
                return str(data[key])
        return None

    @staticmethod
    def _pick_number(data: Dict, keys) -> Optional[float]:
        for key in keys:
            if key in data and data[key] not in (None, ""):
                try:
                    return float(data[key])
                except (TypeError, ValueError):
                    continue
        return None

    @staticmethod
    def _normalize_verdict(verdict_raw: Optional[str], trust_score: Optional[float], risk_score: Optional[float]) -> str:
        if verdict_raw:
            lowered = verdict_raw.strip().lower()
            if lowered in {"clean", "safe", "trusted", "legit", "legitimate", "low"}:
                return "CLEAN"
            if lowered in {"suspicious", "medium", "warning", "unknown"}:
                return "SUSPICIOUS"
            if lowered in {"malicious", "scam", "fraud", "high", "dangerous", "phishing"}:
                return "MALICIOUS"

        if risk_score is not None:
            if risk_score >= 70:
                return "MALICIOUS"
            if risk_score >= 30:
                return "SUSPICIOUS"
            return "CLEAN"

        if trust_score is not None:
            if trust_score < 30:
                return "MALICIOUS"
            if trust_score < 60:
                return "SUSPICIOUS"
            return "CLEAN"

        return "UNKNOWN"


if __name__ == "__main__":
    # Tests
    # vt = VirusTotalClient()
    # print(vt.check_ip("8.8.8.8"))
    
    # abuseipdb = AbuseIPDBClient()
    # print(abuseipdb.check_ip("8.8.8.8"))
    pass
