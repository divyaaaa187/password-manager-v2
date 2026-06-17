import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()

print("DATABASE CONTENT:")
for row in rows:
    print(row)

conn.close()