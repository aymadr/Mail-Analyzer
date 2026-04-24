"""
Parser d'entête email - Extrait SPF, DKIM, DMARC et IPs
"""
import re
from email.parser import Parser
from typing import Dict, List, Tuple

class EmailHeaderParser:
    def __init__(self):
        self.parser = Parser()
    
    def parse_eml_file(self, file_path: str) -> Dict:
        """Charge et parse un fichier .eml"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            email_content = f.read()
        return self.parse_email_content(email_content)
    
    def parse_email_content(self, email_content: str) -> Dict:
        """Parse le contenu brut d'un email"""
        message = self.parser.parsestr(email_content)
        
        return {
            "from": message.get("From", ""),
            "to": message.get("To", ""),
            "subject": message.get("Subject", ""),
            "date": message.get("Date", ""),
            "spf": self._extract_spf(email_content),
            "dkim": self._extract_dkim(email_content),
            "dmarc": self._extract_dmarc(email_content),
            "ips": self._extract_ips(email_content),
            "domains": self._extract_domains(email_content),
            "received_from": self._extract_received_headers(message),
            "raw_headers": dict(message.items())
        }
    
    def _extract_spf(self, content: str) -> Dict:
        """Extrait les informations SPF"""
        spf_pattern = r"(?:Received-SPF|Authentication-Results).*?spf=(.*?)(?:;|$)"
        match = re.search(spf_pattern, content, re.IGNORECASE | re.DOTALL)
        
        return {
            "status": match.group(1).strip() if match else "Not found",
            "record": self._fetch_spf_record(content)
        }
    
    def _extract_dkim(self, content: str) -> Dict:
        """Extrait les informations DKIM"""
        dkim_pattern = r"DKIM-Signature:(.*?)(?=\n[A-Z]|\Z)"
        match = re.search(dkim_pattern, content, re.IGNORECASE | re.DOTALL)
        
        return {
            "status": "Present" if match else "Not found",
            "domain": self._extract_dkim_domain(match.group(1)) if match else None,
            "algorithm": self._extract_dkim_algo(match.group(1)) if match else None
        }
    
    def _extract_dmarc(self, content: str) -> Dict:
        """Extrait les informations DMARC"""
        dmarc_pattern = r"Authentication-Results:.*?dmarc=(.*?)(?:;|$)"
        match = re.search(dmarc_pattern, content, re.IGNORECASE)
        
        return {
            "status": match.group(1).strip() if match else "Not found",
            "policy": self._extract_dmarc_policy(content)
        }
    
    def _extract_ips(self, content: str) -> List[str]:
        """Extrait toutes les adresses IP"""
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_pattern, content)
        return list(set(ips))  # Remove duplicates
    
    def _extract_domains(self, content: str) -> List[str]:
        """Extrait les domaines"""
        domain_pattern = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,}"
        domains = re.findall(domain_pattern, content)
        return list(set(domains))
    
    def _extract_received_headers(self, message) -> List[Dict]:
        """Parse les headers 'Received'"""
        received = message.get_all("Received", [])
        return [{"header": h} for h in received] if received else []
    
    def _extract_dkim_domain(self, dkim_content: str) -> str:
        """Extrait le domaine DKIM"""
        match = re.search(r"d=([^;]+)", dkim_content)
        return match.group(1).strip() if match else None
    
    def _extract_dkim_algo(self, dkim_content: str) -> str:
        """Extrait l'algorithme DKIM"""
        match = re.search(r"a=([^;]+)", dkim_content)
        return match.group(1).strip() if match else None
    
    def _fetch_spf_record(self, content: str) -> str:
        """Essaie de trouver le record SPF"""
        spf_pattern = r"v=spf1\s[^\n]*"
        match = re.search(spf_pattern, content, re.IGNORECASE)
        return match.group(0) if match else None
    
    def _extract_dmarc_policy(self, content: str) -> str:
        """Extrait la politique DMARC"""
        dmarc_pattern = r"p=(reject|quarantine|none)"
        match = re.search(dmarc_pattern, content, re.IGNORECASE)
        return match.group(1) if match else None


# Utilisation facile
if __name__ == "__main__":
    parser = EmailHeaderParser()
    # result = parser.parse_eml_file("test_email.eml")
    # print(result)
