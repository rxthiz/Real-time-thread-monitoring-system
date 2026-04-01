import sqlite3

conn = sqlite3.connect("students.db")
cursor = conn.cursor()

# Create table with PRIMARY KEY
cursor.execute("""
CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY,
    name TEXT,
    age INTEGER,
    marks INTEGER,
    city TEXT
)
""")

students_data = [
    (1, "Rishi", 21, 85, "Chennai"),
    (2, "Arun", 22, 70, "Mumbai"),
    (3, "Kiran", 20, 90, "Delhi"),
    (4, "Rahul", 23, 60, "Chennai"),
    (5, "Ajay", 21, 75, "Mumbai")
]

cursor.executemany(
    "INSERT INTO students VALUES (?, ?, ?, ?, ?)", students_data)

conn.commit()

cursor.execute("SELECT * FROM students")
for row in cursor.fetchall():
    print(row)

conn.close()
cursor.execute("DELETE FROM students")
