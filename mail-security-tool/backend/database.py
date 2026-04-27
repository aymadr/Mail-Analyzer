"""
Gestion de la base de données SQLite pour cache des résultats
"""
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List
from config import DB_PATH

class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()
    
    def init_db(self):
        """Initialise les tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table pour les analyses d'emails
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_analysis (
                    id INTEGER PRIMARY KEY,
                    email_hash TEXT UNIQUE,
                    sender TEXT,
                    subject TEXT,
                    analysis_data TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            """)
            
            # Table pour les hashes de fichiers
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_hashes (
                    id INTEGER PRIMARY KEY,
                    file_hash TEXT UNIQUE,
                    hash_type TEXT,
                    analysis_data TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            """)
            
            # Table pour les IPs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_analysis (
                    id INTEGER PRIMARY KEY,
                    ip_address TEXT UNIQUE,
                    analysis_data TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            """)
            
            # Table pour les URLs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS url_analysis (
                    id INTEGER PRIMARY KEY,
                    url TEXT UNIQUE,
                    analysis_data TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            """)
            
            conn.commit()
    
    def save_email_analysis(self, email_hash: str, sender: str, subject: str, 
                          analysis_data: Dict) -> bool:
        """Sauvegarde l'analyse d'un email"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                now = datetime.now()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO email_analysis 
                    (email_hash, sender, subject, analysis_data, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    email_hash, sender, subject, 
                    json.dumps(analysis_data), now, now
                ))
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Erreur sauvegarde email: {e}")
            return False
    
    def save_file_hash_analysis(self, file_hash: str, hash_type: str, 
                               analysis_data: Dict) -> bool:
        """Sauvegarde l'analyse d'un hash de fichier"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                now = datetime.now()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO file_hashes 
                    (file_hash, hash_type, analysis_data, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    file_hash, hash_type, 
                    json.dumps(analysis_data), now, now
                ))
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Erreur sauvegarde hash: {e}")
            return False
    
    def save_ip_analysis(self, ip: str, analysis_data: Dict) -> bool:
        """Sauvegarde l'analyse d'une IP"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                now = datetime.now()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO ip_analysis 
                    (ip_address, analysis_data, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                """, (ip, json.dumps(analysis_data), now, now))
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Erreur sauvegarde IP: {e}")
            return False
    
    def save_url_analysis(self, url: str, analysis_data: Dict) -> bool:
        """Sauvegarde l'analyse d'une URL"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                now = datetime.now()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO url_analysis 
                    (url, analysis_data, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                """, (url, json.dumps(analysis_data), now, now))
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Erreur sauvegarde URL: {e}")
            return False
    
    def get_email_analysis(self, email_hash: str) -> Optional[Dict]:
        """Récupère l'analyse d'un email"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT analysis_data FROM email_analysis WHERE email_hash = ?",
                    (email_hash,)
                )
                result = cursor.fetchone()
                return json.loads(result[0]) if result else None
        except Exception as e:
            print(f"Erreur lecture email: {e}")
            return None
    
    def get_file_hash_analysis(self, file_hash: str) -> Optional[Dict]:
        """Récupère l'analyse d'un hash"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT analysis_data FROM file_hashes WHERE file_hash = ?",
                    (file_hash,)
                )
                result = cursor.fetchone()
                return json.loads(result[0]) if result else None
        except Exception as e:
            print(f"Erreur lecture hash: {e}")
            return None
    
    def get_ip_analysis(self, ip: str) -> Optional[Dict]:
        """Récupère l'analyse d'une IP"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT analysis_data FROM ip_analysis WHERE ip_address = ?",
                    (ip,)
                )
                result = cursor.fetchone()
                return json.loads(result[0]) if result else None
        except Exception as e:
            print(f"Erreur lecture IP: {e}")
            return None
    
    def get_url_analysis(self, url: str) -> Optional[Dict]:
        """Récupère l'analyse d'une URL"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT analysis_data FROM url_analysis WHERE url = ?",
                    (url,)
                )
                result = cursor.fetchone()
                return json.loads(result[0]) if result else None
        except Exception as e:
            print(f"Erreur lecture URL: {e}")
            return None
    
    def get_all_analyses(self, limit: int = 50) -> List[Dict]:
        """Récupère les dernières analyses"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 'email' AS type, sender AS title, subject AS detail, updated_at AS date, analysis_data AS data
                    FROM email_analysis
                    UNION ALL
                    SELECT 'attachment' AS type, file_hash AS title, hash_type AS detail, updated_at AS date, analysis_data AS data
                    FROM file_hashes
                    UNION ALL
                    SELECT 'ip' AS type, ip_address AS title, 'IP' AS detail, updated_at AS date, analysis_data AS data
                    FROM ip_analysis
                    UNION ALL
                    SELECT 'url' AS type, url AS title, 'URL' AS detail, updated_at AS date, analysis_data AS data
                    FROM url_analysis
                    ORDER BY date DESC
                    LIMIT ?
                """, (limit,))
                results = cursor.fetchall()

                history = []
                for row in results:
                    data = json.loads(row[4]) if row[4] else {}
                    history.append({
                        "type": row[0],
                        "title": row[1],
                        "detail": row[2],
                        "data": data,
                        "date": row[3]
                    })

                return history
        except Exception as e:
            print(f"Erreur lecture analyses: {e}")
            return []

    def get_dashboard_summary(self) -> Dict:
        """Récupère les métriques principales pour le dashboard."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM email_analysis")
                emails = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM file_hashes")
                attachments = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM ip_analysis")
                ips = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM url_analysis")
                urls = cursor.fetchone()[0]

                cursor.execute(
                    "SELECT sender, subject, updated_at FROM email_analysis ORDER BY updated_at DESC LIMIT 1"
                )
                latest = cursor.fetchone()

                return {
                    "totals": {
                        "emails": emails,
                        "attachments": attachments,
                        "ips": ips,
                        "urls": urls
                    },
                    "latest_email": {
                        "sender": latest[0] if latest else None,
                        "subject": latest[1] if latest else None,
                        "date": latest[2] if latest else None
                    },
                    "recent": self.get_all_analyses(5)
                }
        except Exception as e:
            print(f"Erreur dashboard: {e}")
            return {
                "totals": {"emails": 0, "attachments": 0, "ips": 0, "urls": 0},
                "latest_email": {"sender": None, "subject": None, "date": None},
                "recent": []
            }


if __name__ == "__main__":
    db = Database()
    # Tests
    # db.save_email_analysis("hash123", "test@example.com", "Test", {"test": "data"})
    # print(db.get_email_analysis("hash123"))
