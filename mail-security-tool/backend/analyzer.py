"""
Orchestrateur principal - Coordonne toutes les analyses
"""
import hashlib
from email_parser import EmailHeaderParser
from hash_calculator import HashCalculator
from api_clients import VirusTotalClient, URLScanIOClient, AbuseIPDBClient
from database import Database
from typing import Dict

class SecurityAnalyzer:
    def __init__(self):
        self.email_parser = EmailHeaderParser()
        self.hash_calc = HashCalculator()
        self.vt_client = VirusTotalClient()
        self.urlscan_client = URLScanIOClient()
        self.abuseipdb_client = AbuseIPDBClient()
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
        
        # Compile les résultats
        full_analysis = {
            "email": email_data,
            "ips": ip_results,
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
        
        # Analyse VirusTotal
        for hash_type in ['md5', 'sha1', 'sha256']:
            vt_result = self.vt_client.check_file_hash(hashes[hash_type])
            results["virustotal"][hash_type] = vt_result
            self.db.save_file_hash_analysis(hashes[hash_type], hash_type, vt_result)
        
        return results
    
    def analyze_url(self, url: str) -> Dict:
        """Analyse complète d'une URL"""
        results = {
            "url": url,
            "virustotal": self.vt_client.check_url(url),
            "urlscan": self.urlscan_client.scan_url(url)
        }
        
        self.db.save_url_analysis(url, results)
        return results
    
    def get_report(self, email_hash: str) -> Dict:
        """Récupère le rapport d'une analyse"""
        return self.db.get_email_analysis(email_hash)


if __name__ == "__main__":
    analyzer = SecurityAnalyzer()
    # result = analyzer.analyze_email_file("test_email.eml")
    # print(result)
