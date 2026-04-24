"""
Calcul de hash - SHA1, MD5, SHA256
"""
import hashlib
from pathlib import Path
from typing import Dict

class HashCalculator:
    @staticmethod
    def calculate_file_hashes(file_path: str) -> Dict[str, str]:
        """Calcule tous les hash d'un fichier"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Fichier non trouvé: {file_path}")
        
        hashes = {}
        
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        hashes['md5'] = hashlib.md5(file_content).hexdigest()
        hashes['sha1'] = hashlib.sha1(file_content).hexdigest()
        hashes['sha256'] = hashlib.sha256(file_content).hexdigest()
        
        hashes['file_name'] = file_path.name
        hashes['file_size'] = file_path.stat().st_size
        
        return hashes
    
    @staticmethod
    def calculate_string_hashes(content: str) -> Dict[str, str]:
        """Calcule les hash d'une chaîne"""
        content_bytes = content.encode('utf-8')
        
        return {
            'md5': hashlib.md5(content_bytes).hexdigest(),
            'sha1': hashlib.sha1(content_bytes).hexdigest(),
            'sha256': hashlib.sha256(content_bytes).hexdigest(),
        }
    
    @staticmethod
    def calculate_from_bytes(data: bytes) -> Dict[str, str]:
        """Calcule les hash à partir de bytes"""
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }


if __name__ == "__main__":
    # Test
    calc = HashCalculator()
    # result = calc.calculate_file_hashes("test_file.exe")
    # print(result)
