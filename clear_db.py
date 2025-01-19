import sqlite3

def clear_database():
    conn = sqlite3.connect('certificates.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM certificates")
    conn.commit()
    print("La base de données a été vidée.")
    conn.close()

clear_database()
