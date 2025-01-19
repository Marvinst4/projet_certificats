import sqlite3

def create_db():
    conn = sqlite3.connect("certificates.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            signature_algorithm TEXT,
            issuer TEXT,
            not_before INTEGER,
            not_after INTEGER,
            fingerprint TEXT
        )
    ''')
    conn.commit()
    conn.close()
create_db()
