"""
Orchestrateur principal - Coordonne toutes les analyses
"""
import hashlib
import ipaddress
import re
import requests
from urllib.parse import urlparse
from email_parser import EmailHeaderParser
from hash_calculator import HashCalculator
from api_clients import VirusTotalClient, URLScanIOClient, AbuseIPDBClient, ScamdocClient, AnyRunClient
from database import Database
from typing import Dict, List

class SecurityAnalyzer:
    MAX_EMAIL_URL_REDIRECTS = 25
    MAX_EMAIL_URL_SCAMDOC = 10

    def __init__(self):
        self.email_parser = EmailHeaderParser()
        self.hash_calc = HashCalculator()
        self.vt_client = VirusTotalClient()
        self.urlscan_client = URLScanIOClient()
        self.abuseipdb_client = AbuseIPDBClient()
        self.scamdoc_client = ScamdocClient()
        self.anyrun_client = AnyRunClient()
        self.db = Database()
    
    def analyze_email_file(self, file_path: str) -> Dict:
        """Analyse complète d'un fichier email"""
        # Parse l'email
        email_data = self.email_parser.parse_eml_file(file_path)
        
        # Crée un hash unique pour cet email
        email_hash = hashlib.sha256(
            f"{email_data['from']}{email_data['subject']}".encode()
        ).hexdigest()
        
        # Analyse les IPs
        ip_results = []
        for ip in email_data.get('ips', []):
            vt_ip = self.vt_client.check_ip(ip)
            abuseipdb_ip = self.abuseipdb_client.check_ip(ip)
            
            ip_results.append({
                "ip": ip,
                "virustotal": vt_ip,
                "abuseipdb": abuseipdb_ip
            })
            self.db.save_ip_analysis(ip, {"vt": vt_ip, "abuseipdb": abuseipdb_ip})
        
        # Analyse les pièces jointes (hashes)
        attachment_results = []
        for attachment in email_data.get('attachments', []):
            vt_results = {}
            for hash_type in ['md5', 'sha1', 'sha256']:
                vt_result = self.vt_client.check_file_hash(attachment[hash_type])
                vt_results[hash_type] = vt_result
                self.db.save_file_hash_analysis(attachment[hash_type], hash_type, vt_result)
            
            attachment_results.append({
                "filename": attachment['filename'],
                "size": attachment['size'],
                "md5": attachment['md5'],
                "sha1": attachment['sha1'],
                "sha256": attachment['sha256'],
                "virustotal": vt_results
            })

        # Analyse locale des URLs extraites du mail (normalisation + redirections)
        url_results = self._analyze_email_urls(email_data.get("urls", {}))
        scamdoc_results = self._analyze_email_scamdoc(email_data, url_results)
        
        # Compile les résultats
        full_analysis = {
            "email": email_data,
            "ips": ip_results,
            "attachments": attachment_results,
            "urls": url_results,
            "scamdoc": scamdoc_results,
            "hash": email_hash
        }
        
        # Sauvegarde en BD
        self.db.save_email_analysis(
            email_hash,
            email_data['from'],
            email_data['subject'],
            full_analysis
        )
        
        return full_analysis
    
    def analyze_attachment(self, file_path: str) -> Dict:
        """Analyse complète d'une pièce jointe"""
        # Calcule les hashes
        hashes = self.hash_calc.calculate_file_hashes(file_path)
        
        results = {
            "file": hashes,
            "virustotal": {},
            "urlscan": {},
            "analysis": {}
        }
        
        # Analyse VirusTotal par hash (lookup dans la base VirusTotal, sans upload)
        for hash_type in ['md5', 'sha1', 'sha256']:
            vt_result = self.vt_client.check_file_hash(hashes[hash_type])
            results["virustotal"][hash_type] = vt_result
            self.db.save_file_hash_analysis(hashes[hash_type], hash_type, vt_result)

        if self.anyrun_client.enabled:
            anyrun_result = self.anyrun_client.submit_file(file_path, metadata={"file_hash": hashes.get("sha256", "")})
            results["anyrun"] = anyrun_result
            if hashes.get("sha256"):
                self.db.save_file_hash_analysis(hashes["sha256"], "anyrun", anyrun_result)
        
        return results
    
    def analyze_url(self, url: str) -> Dict:
        """Analyse complète d'une URL"""
        normalized_url = self._normalize_url(url)
        results = {
            "url": normalized_url,
            "virustotal": self.vt_client.check_url(normalized_url),
            "urlscan": self.urlscan_client.scan_url(normalized_url),
            "scamdoc": self.scamdoc_client.check_url(normalized_url)
        }

        if self.anyrun_client.enabled:
            results["anyrun"] = self.anyrun_client.submit_url(normalized_url)
        
        self.db.save_url_analysis(normalized_url, results)
        return results

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Ajoute https:// si aucun schéma n'est présent."""
        value = (url or "").strip()
        if not value:
            return value
        parsed = urlparse(value)
        if not parsed.scheme:
            return f"https://{value}"
        return value
    
    def get_report(self, email_hash: str) -> Dict:
        """Récupère le rapport d'une analyse"""
        return self.db.get_email_analysis(email_hash)

    def _analyze_email_urls(self, url_payload: Dict) -> Dict:
        """Construit l'analyse URL locale pour les emails."""
        items = url_payload.get("items", [])
        grouped_domains = url_payload.get("grouped_domains", [])
        summary = url_payload.get("summary", {})

        unique_urls: List[str] = []
        seen = set()
        for item in items:
            value = item.get("normalized")
            if not value or value in seen:
                continue
            seen.add(value)
            unique_urls.append(value)

        redirects = []
        for url in unique_urls[: self.MAX_EMAIL_URL_REDIRECTS]:
            redirects.append(self._resolve_redirect_chain(url))

        return {
            "extracted": items,
            "grouped_domains": grouped_domains,
            "redirects": redirects,
            "summary": {
                "total_found": summary.get("total_found", len(items)),
                "unique_urls": summary.get("unique_urls", len(unique_urls)),
                "sources": summary.get("sources", {}),
                "redirects_checked": len(redirects),
                "redirects_limited": len(unique_urls) > self.MAX_EMAIL_URL_REDIRECTS,
            },
        }

    def _resolve_redirect_chain(self, url: str, max_hops: int = 8) -> Dict:
        """Suit les redirections HTTP sans JS/cookies/auth utilisateur."""
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return {
                "start_url": url,
                "final_url": url,
                "redirected": False,
                "chain": [url],
                "error": "Invalid hostname",
            }

        if self._is_private_or_local_host(hostname):
            return {
                "start_url": url,
                "final_url": url,
                "redirected": False,
                "chain": [url],
                "error": "Skipped private/local target",
            }

        session = requests.Session()
        session.max_redirects = max_hops

        def format_chain(response):
            chain = [r.url for r in response.history] + [response.url]
            if not chain:
                chain = [url]
            return list(dict.fromkeys(chain))

        try:
            # HEAD d'abord pour limiter le payload
            response = session.head(
                url,
                allow_redirects=True,
                timeout=8,
            )
            chain = format_chain(response)
            return {
                "start_url": url,
                "final_url": chain[-1],
                "redirected": len(chain) > 1,
                "chain": chain,
                "status_code": response.status_code,
            }
        except Exception:
            try:
                # Fallback GET pour serveurs qui refusent HEAD
                response = session.get(
                    url,
                    allow_redirects=True,
                    timeout=8,
                    stream=True,
                )
                chain = format_chain(response)
                response.close()
                return {
                    "start_url": url,
                    "final_url": chain[-1],
                    "redirected": len(chain) > 1,
                    "chain": chain,
                    "status_code": response.status_code,
                }
            except Exception as e:
                return {
                    "start_url": url,
                    "final_url": url,
                    "redirected": False,
                    "chain": [url],
                    "error": str(e),
                }

    def _analyze_email_scamdoc(self, email_data: Dict, url_results: Dict) -> Dict:
        """Analyse Scamdoc pour les éléments clés d'un email."""
        sender_value = email_data.get("from", "")
        sender_email = self._extract_first_email(sender_value)
        recipient_email = self._extract_first_email(email_data.get("to", ""))

        sender_domain = self._extract_domain_from_email(sender_email)
        if sender_domain and not self._is_local_email_domain(sender_domain):
            sender_result = self.scamdoc_client.check_url(f"https://{sender_domain}")
        elif sender_domain:
            sender_result = {
                "source": "Scamdoc",
                "error": "Sender domain is local/internal and is skipped",
            }
        else:
            sender_result = {
                "source": "Scamdoc",
                "error": "Sender email/domain not found",
            }

        # Selon la demande, on n'analyse pas le destinataire via Scamdoc.
        recipient_result = {
            "source": "Scamdoc",
            "error": "Recipient Scamdoc check disabled (sender-focused mode)",
        }

        url_checks = []
        extracted = url_results.get("extracted", [])
        unique_urls = []
        seen = set()
        for item in extracted:
            normalized = item.get("normalized")
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            unique_urls.append(normalized)

        for value in unique_urls[: self.MAX_EMAIL_URL_SCAMDOC]:
            url_checks.append({
                "url": value,
                "result": self.scamdoc_client.check_url(value)
            })

        return {
            "sender_email": sender_email,
            "sender_domain": sender_domain,
            "sender": sender_result,
            "recipient_email": recipient_email,
            "recipient": recipient_result,
            "urls": url_checks,
            "summary": {
                "checked_urls": len(url_checks),
                "limited": len(unique_urls) > self.MAX_EMAIL_URL_SCAMDOC,
            }
        }

    @staticmethod
    def _extract_first_email(value: str) -> str:
        if not value:
            return ""
        match = re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", value)
        return match.group(0).lower() if match else ""

    @staticmethod
    def _extract_domain_from_email(email_value: str) -> str:
        if not email_value or "@" not in email_value:
            return ""
        return email_value.split("@", 1)[1].lower().strip()

    @staticmethod
    def _is_local_email_domain(domain: str) -> bool:
        lowered = (domain or "").lower().strip()
        if not lowered:
            return True
        if lowered.endswith(".local") or lowered.endswith(".lan"):
            return True
        return False

    @staticmethod
    def _is_private_or_local_host(hostname: str) -> bool:
        lowered = hostname.lower()
        if lowered in {"localhost"} or lowered.endswith(".local"):
            return True

        try:
            ip = ipaddress.ip_address(lowered)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            return False


if __name__ == "__main__":
    analyzer = SecurityAnalyzer()
    # result = analyzer.analyze_email_file("test_email.eml")
    # print(result)
