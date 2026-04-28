#!/usr/bin/env python3
"""Diagnostic pour vérifier les dépendances et .msg support"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "backend"))

print("🔍 DIAGNOSTIC - Vérification support .MSG\n")

# 1. Vérifier extract_msg
print("1️⃣ Checking extract_msg installation...")
try:
    import extract_msg
    print(f"   ✅ extract_msg installé (version: {extract_msg.__version__ if hasattr(extract_msg, '__version__') else 'unknown'})")
except ImportError as e:
    print(f"   ❌ extract_msg NOT installed: {e}")
    print("   → Install with: pip install extract-msg")

# 2. Test parse .eml vs .msg
print("\n2️⃣ Testing email_parser...")
from email_parser import EmailHeaderParser
parser = EmailHeaderParser()

# Test .eml
test_eml = Path("test.eml")
if test_eml.exists():
    try:
        result = parser.parse_eml_file(str(test_eml))
        print(f"   ✅ .eml parsing works")
        if result.get("warnings"):
            print(f"      Warnings: {result['warnings']}")
    except Exception as e:
        print(f"   ❌ .eml parsing error: {e}")

# Test .msg
test_msg = Path("test.msg")
if test_msg.exists():
    try:
        result = parser.parse_eml_file(str(test_msg))
        print(f"   ✅ .msg parsing works")
        print(f"      Format: {result.get('format', 'unknown')}")
        if result.get("warnings"):
            print(f"      Warnings: {result['warnings']}")
        if not result.get("from"):
            print(f"      ⚠️ No 'from' extracted")
    except Exception as e:
        print(f"   ❌ .msg parsing error: {e}")
else:
    print("   ⚠️ No test.msg found for testing")

print("\n✨ Diagnostic complete!\n")
