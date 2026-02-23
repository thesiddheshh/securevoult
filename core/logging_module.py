import sqlite3
import os
from datetime import datetime

DB_PATH = "database/logs.db"

def init_db():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            admin_id TEXT,
            action TEXT,
            details TEXT,
            status TEXT,
            ip_sim TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_event(admin_id: str, action: str, details: str, status: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_sim = f"192.168.1.{hash(admin_id) % 255}" # Simulated IP
    
    c.execute('''
        INSERT INTO audit_logs (timestamp, admin_id, action, details, status, ip_sim)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, admin_id, action, details, status, ip_sim))
    
    conn.commit()
    conn.close()

def get_logs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows