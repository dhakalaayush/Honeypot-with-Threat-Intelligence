import sqlite3
import datetime

DB_NAME = "honeypot.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Table schema
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        attack_type TEXT,
        data_captured TEXT,
        abuse_score INTEGER,
        country TEXT,
        isp TEXT
    )
    """)
    conn.commit()
    conn.close()

def log_attack(ip, attack_type, data_captured, threat_data=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Handle local IPs or failed threat intel queries
    score = threat_data.get("score", 0) if threat_data else 0
    country = threat_data.get("country", "Local/Unknown") if threat_data else "Local/Unknown"
    isp = threat_data.get("isp", "Local/Unknown") if threat_data else "Local/Unknown"

    cursor.execute("""
    INSERT INTO attacks (timestamp, ip, attack_type, data_captured, abuse_score, country, isp)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, ip, attack_type, data_captured, score, country, isp))
    
    conn.commit()
    conn.close()
    print(f"[DB] Successfully recorded attack from {ip} into SQLite.")

if __name__ == "__main__":
    init_db()
    print("[*] Database initialized successfully.")