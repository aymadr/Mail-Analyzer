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
        """Extrait les informations SPF, le domaine et l'IP"""
        status = "Not found"
        domain = None
        ip = None

        # 1. Vérification dans Received-SPF (ex: Received-SPF: pass (domain of example.com designates 192.168.1.1 as permitted sender) client-ip=192.168.1.1;)
        received_spf_match = re.search(r"Received-SPF:\s*([a-zA-Z]+)(.*)", content, re.IGNORECASE)
        if received_spf_match:
            status = received_spf_match.group(1).capitalize()
            line_content = received_spf_match.group(2)

            # Essaie de trouver le client-ip ou IP (IPv4 ou IPv6)
            ip_match = re.search(r"client-ip=([a-fA-F0-9\.:]+)", line_content, re.IGNORECASE)
            if not ip_match:
                ip_match = re.search(r"designates\s+([a-fA-F0-9\.:]+)\s+as permitted sender", line_content, re.IGNORECASE)
            if ip_match:
                ip = ip_match.group(1)

            # Essaie de trouver le domaine (envelope-from ou domain of)
            domain_match = re.search(r"envelope-from=[^\s@]*@([^\s;]+)", line_content, re.IGNORECASE)
            if not domain_match:
                domain_match = re.search(r"domain of ([^\s]+)\s+designates", line_content, re.IGNORECASE)
            if domain_match:
                domain = domain_match.group(1).lstrip(".*@")
                
        # 2. Sinon, vérification dans Authentication-Results
        else:
            auth_results_match = re.search(r"Authentication-Results:.*?spf=([a-zA-Z]+)(.*)", content, re.IGNORECASE | re.DOTALL)
            if auth_results_match:
                status = auth_results_match.group(1).capitalize()
                rest = auth_results_match.group(2).split(';')[0] if ';' in auth_results_match.group(2) else auth_results_match.group(2)
                
                # IP dans Authentication-Results (IPv4 ou IPv6)
                ip_match = re.search(r"sender IP is ([a-fA-F0-9\.:]+)", content, re.IGNORECASE)
                if ip_match:
                    ip = ip_match.group(1)
                    
                domain_match = re.search(r"smtp\.mailfrom=([^\s;]+)", content, re.IGNORECASE)
                if domain_match:
                    domain = domain_match.group(1)
                    if "@" in domain:
                        domain = domain.split("@")[-1]

        return {
            "status": status,
            "domain": domain,
            "ip": ip,
            "record": self._fetch_spf_record(content)
        }
    
    def _extract_dkim(self, content: str) -> Dict:
        """Extrait les informations DKIM"""
        status = "Not found"
        domain = None
        
        # On vérifie Authentication-Results pour un statut DKIM (ex: dkim=pass)
        auth_results_match = re.search(r"Authentication-Results:.*?dkim=([a-zA-Z]+)", content, re.IGNORECASE | re.DOTALL)
        if auth_results_match:
            status = auth_results_match.group(1).capitalize()
            
        dkim_pattern = r"DKIM-Signature:(.*?)(?=\n[A-Z]|\Z)"
        match = re.search(dkim_pattern, content, re.IGNORECASE | re.DOTALL)
        
        if match and status == "Not found":
            status = "Present"
            
        if match:
            domain = self._extract_dkim_domain(match.group(1))
            
        return {
            "status": status,
            "domain": domain,
            "algorithm": self._extract_dkim_algo(match.group(1)) if match else None
        }
    
    def _extract_dmarc(self, content: str) -> Dict:
        """Extrait les informations DMARC"""
        dmarc_pattern = r"Authentication-Results:.*?dmarc=([a-zA-Z]+)(.*)(?:;|$)"
        match = re.search(dmarc_pattern, content, re.IGNORECASE | re.DOTALL)
        
        status = "Not found"
        domain = None
        
        if match:
            status = match.group(1).capitalize()
            # Trouve le domaine header.from (souvent indiqué en header.from=example.com)
            domain_match = re.search(r"header\.from=([^\s;]+)", match.group(2), re.IGNORECASE)
            if domain_match:
                domain = domain_match.group(1)
        
        return {
            "status": status,
            "domain": domain,
            "policy": self._extract_dmarc_policy(content)
        }
    
    def _extract_ips(self, content: str) -> List[str]:
        """Extrait toutes les adresses IP (IPv4 et IPv6)"""
        # Regex pour IPv4
        ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        # Regex pour IPv6
        ipv6_pattern = r"(?<![:.\w])(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}(?![:.\w])|(?<![:.\w])(?:[A-F0-9]{1,4}:)*::(?:[A-F0-9]{1,4}:)*[A-F0-9]{1,4}(?![:.\w])"
        
        ips = re.findall(f"{ipv4_pattern}|{ipv6_pattern}", content, re.IGNORECASE)
        # re.findall retourne des strings pleines si pas de groupes, donc on nettoie
        cleaned_ips = [ip for ip in ips if ip]
        return list(set(cleaned_ips))  # Remove duplicates
    
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
