import sqlite3

# Connect to your database
conn = sqlite3.connect("pdf_analysis.db")
c = conn.cursor()

# Fetch all records in the `uploads` table
c.execute("SELECT * FROM pdf_records")

# Print the rows in a readable format
rows = c.fetchall()
for row in rows:
    print(row)

# Close the connection
conn.close()
