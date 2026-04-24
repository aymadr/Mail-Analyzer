"""
Tests basiques pour valider le projet
"""
import sys
from pathlib import Path

# Ajouter backend au path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

def test_imports():
    """Tester les imports"""
    try:
        from config import VIRUSTOTAL_API_KEY, DB_PATH
        from email_parser import EmailHeaderParser
        from hash_calculator import HashCalculator
        from api_clients import VirusTotalClient, URLScanIOClient, AbuseIPDBClient
        from database import Database
        from analyzer import SecurityAnalyzer
        print("✅ Tous les imports OK")
        return True
    except Exception as e:
        print(f"❌ Erreur import: {e}")
        return False

def test_hash_calculator():
    """Tester le calcul de hash"""
    try:
        from hash_calculator import HashCalculator
        
        # Test sur une chaîne
        hashes = HashCalculator.calculate_string_hashes("test")
        
        assert 'md5' in hashes
        assert 'sha1' in hashes
        assert 'sha256' in hashes
        assert len(hashes['md5']) == 32
        assert len(hashes['sha1']) == 40
        assert len(hashes['sha256']) == 64
        
        print("✅ Hash Calculator OK")
        return True
    except Exception as e:
        print(f"❌ Hash Calculator Error: {e}")
        return False

def test_email_parser():
    """Tester le parser email"""
    try:
        from email_parser import EmailHeaderParser
        
        parser = EmailHeaderParser()
        
        # Email de test
        test_email = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 24 Apr 2026 10:00:00 +0000
Received: from mail.example.com (mail.example.com [8.8.8.8])

This is a test email."""
        
        result = parser.parse_email_content(test_email)
        
        assert result['from'] == "sender@example.com"
        assert result['to'] == "recipient@example.com"
        assert "ips" in result
        
        print("✅ Email Parser OK")
        return True
    except Exception as e:
        print(f"❌ Email Parser Error: {e}")
        return False

def test_database():
    """Tester la base de données"""
    try:
        from database import Database
        import tempfile
        import os
        
        # Créer une BD temporaire
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
            db_path = tmp.name
        
        try:
            db = Database(db_path)
            
            # Test sauvegarde email
            test_data = {"test": "data"}
            db.save_email_analysis("hash123", "test@example.com", "Test", test_data)
            
            # Test récupération
            result = db.get_email_analysis("hash123")
            assert result == test_data
            
            print("✅ Database OK")
            return True
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
                
    except Exception as e:
        print(f"❌ Database Error: {e}")
        return False

def test_api_clients():
    """Tester les clients API (sans vraies requêtes)"""
    try:
        from api_clients import VirusTotalClient, URLScanIOClient, AbuseIPDBClient
        
        vt = VirusTotalClient()
        assert vt.api_key is not None or vt.api_key == ""
        
        urlscan = URLScanIOClient()
        assert urlscan.api_key is not None or urlscan.api_key == ""
        
        abuseipdb = AbuseIPDBClient()
        assert abuseipdb.api_key is not None or abuseipdb.api_key == ""
        
        print("✅ API Clients OK")
        return True
    except Exception as e:
        print(f"❌ API Clients Error: {e}")
        return False

def test_analyzer():
    """Tester l'orchestrateur"""
    try:
        from analyzer import SecurityAnalyzer
        
        analyzer = SecurityAnalyzer()
        assert analyzer.email_parser is not None
        assert analyzer.hash_calc is not None
        assert analyzer.vt_client is not None
        assert analyzer.db is not None
        
        print("✅ Analyzer OK")
        return True
    except Exception as e:
        print(f"❌ Analyzer Error: {e}")
        return False

def run_all_tests():
    """Lancer tous les tests"""
    print("\n" + "="*50)
    print("🧪 Mail Security Analyzer - Tests")
    print("="*50 + "\n")
    
    tests = [
        test_imports,
        test_hash_calculator,
        test_email_parser,
        test_database,
        test_api_clients,
        test_analyzer
    ]
    
    results = []
    for test in tests:
        results.append(test())
        print()
    
    print("="*50)
    passed = sum(results)
    total = len(results)
    print(f"📊 Résultats: {passed}/{total} tests réussis")
    print("="*50 + "\n")
    
    return all(results)

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
