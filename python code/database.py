import sqlite3
from datetime import datetime

class Database:
    def __init__(self, db_file="phishing_detector.db"):
        self.db_file = db_file
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                email TEXT DEFAULT '',
                risk_level TEXT NOT NULL,
                risk_score REAL DEFAULT 0,
                is_phishing INTEGER DEFAULT 0,
                malicious_engines INTEGER DEFAULT 0,
                suspicious_engines INTEGER DEFAULT 0,
                total_engines INTEGER DEFAULT 0,
                recommendation TEXT DEFAULT ''
            )
        """)
        self.conn.commit()
    
    def add_scan(self, url, result, email=""):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO scan_results 
            (timestamp, url, email, risk_level, risk_score, is_phishing, 
             malicious_engines, suspicious_engines, total_engines, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            email,
            result.get("risk_level", "UNKNOWN"),
            result.get("risk_score", 0),
            1 if result.get("is_phishing") else 0,
            result.get("malicious_engines", 0),
            result.get("suspicious_engines", 0),
            result.get("total_engines", 0),
            result.get("recommendation", "")
        ))
        self.conn.commit()
    
    def get_all_scans(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM scan_results ORDER BY id DESC")
        columns = [d[0] for d in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_stats(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_results")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_results WHERE is_phishing = 1")
        phishing = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_results WHERE risk_level = 'MEDIUM'")
        suspicious = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_results WHERE risk_level IN ('CLEAN', 'LOW')")
        safe = cursor.fetchone()[0]
        return {
            "total_links_checked": total,
            "phishing_links": phishing,
            "suspicious_links": suspicious,
            "safe_links": safe
        }
    
    def close(self):
        self.conn.close()