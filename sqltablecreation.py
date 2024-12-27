import sqlite3

# Database connection
conn = sqlite3.connect("pdf_analysis.db")
cursor = conn.cursor()

# Create table without 'predicted_class' and 'virustotal_detections'
cursor.execute('''
CREATE TABLE IF NOT EXISTS pdf_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT,
    upload_timestamp TEXT,
    main_file_hash TEXT,
    result TEXT
)
''')

conn.commit()
conn.close()
