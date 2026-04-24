#!/usr/bin/env python3
"""
CLI - Ligne de commande pour analyse sans interface web
"""
import sys
import argparse
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
    """Affiche les résultats de manière lisible"""
    print("\n" + "="*60)
    print("RÉSULTATS")
    print("="*60)
    
    if isinstance(result, dict):
        for key, value in result.items():
            if isinstance(value, dict):
                print(f"\n📋 {key.upper()}")
                print("-" * 40)
                for k, v in value.items():
                    if isinstance(v, (list, dict)):
                        print(f"  {k}: {json.dumps(v, indent=2, default=str)}")
                    else:
                        print(f"  {k}: {v}")
            elif isinstance(value, list):
                print(f"\n📋 {key.upper()}")
                print("-" * 40)
                for item in value:
                    print(f"  • {item}")
            else:
                print(f"{key}: {value}")
    else:
        print(result)
    
    print("\n" + "="*60)

if __name__ == "__main__":
    main()
