import sqlite3

def create_db():
    conn = sqlite3.connect("certificates.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT,
            serial_number INTEGER,
            signature_algorithm TEXT,
            not_valid_before TEXT,
            not_valid_after TEXT,
            issuer_cn TEXT,
            subject_cn TEXT,
            modulus INTEGER,
            exponent INTEGER
        );
    ''')
    conn.commit()
    conn.close()
create_db()
