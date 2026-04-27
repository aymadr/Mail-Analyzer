#!/usr/bin/env python3
"""
CLI - Ligne de commande pour analyse sans interface web
"""
import sys
import argparse
import re
import ipaddress
from pathlib import Path

# Ajouter backend au path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from analyzer import SecurityAnalyzer
from hash_calculator import HashCalculator
import json

def main():
    parser = argparse.ArgumentParser(
        description="Mail Security Analyzer - CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python cli.py --email test.eml
  python cli.py --attachment malware.exe
  python cli.py --url https://example.com
  python cli.py --ip 8.8.8.8
  python cli.py --hash /path/to/file.exe
        """
    )
    
    parser.add_argument('--email', type=str, help='Analyser un email (.eml)')
    parser.add_argument('--attachment', type=str, help='Analyser une pièce jointe')
    parser.add_argument('--url', type=str, help='Analyser une URL')
    parser.add_argument('--ip', type=str, help='Analyser une adresse IP')
    parser.add_argument('--hash', type=str, help='Calculer le hash d\'un fichier')
    parser.add_argument('--json', action='store_true', help='Output en JSON')
    parser.add_argument('--verbose', '-v', action='store_true', help='Output détaillé')
    
    args = parser.parse_args()
    
    if not any([args.email, args.attachment, args.url, args.ip, args.hash]):
        parser.print_help()
        return
    
    analyzer = SecurityAnalyzer()
    result = None
    
    try:
        if args.email:
            print("📧 Analyse email...")
            result = analyzer.analyze_email_file(args.email)
            
        elif args.attachment:
            print("📎 Analyse pièce jointe...")
            result = analyzer.analyze_attachment(args.attachment)
            
        elif args.url:
            print("🔗 Analyse URL...")
            result = analyzer.analyze_url(args.url)
            
        elif args.ip:
            print("🌐 Analyse IP...")
            result = {
                "ip": args.ip,
                "virustotal": analyzer.vt_client.check_ip(args.ip),
                "abuseipdb": analyzer.abuseipdb_client.check_ip(args.ip)
            }
            
        elif args.hash:
            print("🔑 Calcul du hash...")
            result = HashCalculator.calculate_file_hashes(args.hash)
        
        # Afficher les résultats
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print_result(result, args.verbose)
            
    except Exception as e:
        print(f"❌ Erreur: {e}", file=sys.stderr)
        sys.exit(1)

def print_result(result, verbose=False):
    """Affiche un résumé concis orienté décision."""
    print("\n" + "=" * 60)
    print("RÉSUMÉ")
    print("=" * 60)

    if not isinstance(result, dict):
        print(result)
        print("\n" + "=" * 60)
        return

    if "email" in result:
        _print_email_summary(result)
    elif "file" in result and "virustotal" in result:
        _print_attachment_summary(result)
    elif "url" in result and "urlscan" in result:
        _print_url_summary(result)
    elif "ip" in result and "abuseipdb" in result:
        _print_ip_summary(result)
    elif all(k in result for k in ["md5", "sha1", "sha256"]):
        _print_hash_summary(result)
    else:
        # Fallback compact si format non prévu
        for key, value in result.items():
            if isinstance(value, (dict, list)):
                continue
            print(f"- {key}: {value}")

    print("\n" + "=" * 60)


def _extract_domain_from_email_address(value: str) -> str:
    if not value:
        return "N/A"
    match = re.search(r"@([^>\s]+)", value)
    return match.group(1).lower() if match else "N/A"


def _first_non_empty(*values) -> str:
    for value in values:
        if value:
            return value
    return "N/A"


def _format_vt_stats(stats: dict) -> str:
    if not isinstance(stats, dict):
        return "N/A"
    return (
        f"malicious={stats.get('malicious', 0)} | "
        f"suspicious={stats.get('suspicious', 0)} | "
        f"clean={stats.get('undetected', 0)}"
    )


def _is_public_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except Exception:
        return False


def _pick_primary_ip(spf_ip: str, routing_ips: list, header_ips: list):
    # Priorité 1: IP extraite du SPF (la plus fiable pour l'émetteur)
    if spf_ip and spf_ip != "N/A":
        return spf_ip, "SPF"

    candidates = []
    for ip in routing_ips + header_ips:
        if ip and ip not in candidates:
            candidates.append(ip)

    # Priorité 2: première IP publique observée
    for ip in candidates:
        if _is_public_ip(ip):
            return ip, "Routage"

    # Priorité 3: première IP disponible
    if candidates:
        return candidates[0], "Headers"

    return "N/A", "N/A"


def _print_email_summary(result: dict):
    email = result.get("email", {})
    spf = email.get("spf", {})
    dkim = email.get("dkim", {})
    dmarc = email.get("dmarc", {})

    sender = email.get("from", "N/A")
    sender_domain = _extract_domain_from_email_address(sender)
    auth_domain = _first_non_empty(spf.get("domain"), dkim.get("domain"), dmarc.get("domain"))

    print("Email")
    print(f"- Expéditeur: {sender}")
    print(f"- Domaine expéditeur: {sender_domain}")
    print(f"- Domaine authentification: {auth_domain}")
    print(f"- SPF: {spf.get('status', 'N/A')}")
    print(f"- DKIM: {dkim.get('status', 'N/A')}")
    print(f"- DMARC: {dmarc.get('status', 'N/A')}")

    header_ips = email.get("ips", [])
    routing_ips = [item.get("ip") for item in result.get("ips", []) if item.get("ip")]
    primary_ip, primary_source = _pick_primary_ip(spf.get("ip"), routing_ips, header_ips)

    all_ips = []
    for ip in [primary_ip] + routing_ips + header_ips:
        if ip and ip != "N/A" and ip not in all_ips:
            all_ips.append(ip)

    other_ips = [ip for ip in all_ips if ip != primary_ip]

    print(f"- IP principale ({primary_source}): {primary_ip}")
    print(f"- Autres IPs: {', '.join(other_ips) if other_ips else 'N/A'}")

    routing = result.get("ips", [])
    if routing:
        print("\nAnalyse des routages")
        for item in routing:
            ip = item.get("ip", "N/A")
            vt = item.get("virustotal", {})
            ab = item.get("abuseipdb", {})

            if vt.get("error"):
                vt_info = f"VT: erreur ({vt.get('error')})"
            else:
                vt_info = f"VT: {_format_vt_stats(vt.get('last_analysis_stats', {}))}"

            if ab.get("error"):
                ab_info = f"AbuseIPDB: erreur ({ab.get('error')})"
            else:
                ab_info = f"AbuseIPDB score={ab.get('abuse_confidence_score', 'N/A')}%"

            print(f"- {ip} | {vt_info} | {ab_info}")


def _print_attachment_summary(result: dict):
    file_info = result.get("file", {})
    vt = result.get("virustotal", {}).get("sha256", {})

    print("Pièce jointe")
    print(f"- Nom: {file_info.get('file_name', 'N/A')}")
    print(f"- Taille: {file_info.get('file_size', 'N/A')} octets")
    print(f"- SHA256: {file_info.get('sha256', 'N/A')}")

    if vt.get("error"):
        print(f"- Verdict VirusTotal: erreur ({vt.get('error')})")
    elif vt.get("status") == "QUEUED":
        print("- Verdict VirusTotal: en attente")
    else:
        print(f"- Verdict VirusTotal: {vt.get('verdict', 'N/A')}")
        print(f"- Stats VirusTotal: {_format_vt_stats(vt.get('stats', {}))}")


def _print_url_summary(result: dict):
    vt = result.get("virustotal", {})
    us = result.get("urlscan", {})

    print("URL")
    print(f"- Cible: {result.get('url', 'N/A')}")

    if vt.get("error"):
        print(f"- VirusTotal: erreur ({vt.get('error')})")
    elif vt.get("status") == "QUEUED":
        print("- VirusTotal: en attente")
    else:
        print(f"- VirusTotal verdict: {vt.get('verdict', 'N/A')}")
        print(f"- VirusTotal stats: {_format_vt_stats(vt.get('stats', {}))}")

    if us.get("error"):
        print(f"- URLScan: erreur ({us.get('error')})")
    else:
        print("- URLScan: scan soumis")


def _print_ip_summary(result: dict):
    vt = result.get("virustotal", {})
    ab = result.get("abuseipdb", {})

    print("IP")
    print(f"- Adresse: {result.get('ip', 'N/A')}")

    if vt.get("error"):
        print(f"- VirusTotal: erreur ({vt.get('error')})")
    else:
        print(f"- VirusTotal: {_format_vt_stats(vt.get('last_analysis_stats', {}))}")

    if ab.get("error"):
        print(f"- AbuseIPDB: erreur ({ab.get('error')})")
    else:
        print(f"- AbuseIPDB score: {ab.get('abuse_confidence_score', 'N/A')}%")
        print(f"- AbuseIPDB reports: {ab.get('total_reports', 'N/A')}")


def _print_hash_summary(result: dict):
    print("Hash fichier")
    print(f"- MD5: {result.get('md5', 'N/A')}")
    print(f"- SHA1: {result.get('sha1', 'N/A')}")
    print(f"- SHA256: {result.get('sha256', 'N/A')}")

if __name__ == "__main__":
    main()
