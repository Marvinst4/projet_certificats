import sqlite3

conn = sqlite3.connect('certificates.db')
cursor = conn.cursor()

cursor.execute("SELECT * FROM certificates")
rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()
