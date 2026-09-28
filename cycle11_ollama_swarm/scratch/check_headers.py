import sqlite3

db_path = r'C:\Users\Lenovo\AppData\Local\Temp\cycle19_run_1789929313.db'
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

rows = conn.execute('SELECT * FROM challenges ORDER BY finding_id, challenger_id').fetchall()
print(f"Total challenges: {len(rows)}")
for r in rows:
    text = r['challenge_text']
    has_header = 'FACTUAL_VALIDITY' in text
    print(f"Finding #{r['finding_id']:02d} ({r['challenger_id']}) - Has Header: {has_header}")
    if not has_header:
        print(f"  TEXT: {text}\n")
