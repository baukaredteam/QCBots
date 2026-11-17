import sqlite3

conn = sqlite3.connect(':memory:')
cur = conn.cursor()

with open('C:/Users/Бауыржан/Desktop/QC_Bots/migrations/0003_evidence_graph.sql', 'r', encoding='utf-8') as f:
    sql = f.read()

cur.executescript(sql)

cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = cur.fetchall()
print(f"Tables ({len(tables)}):")
for t in tables:
    print(f"  {t[0]}")

print(f"\nChecking global_publication_queue:")
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='global_publication_queue'")
result = cur.fetchone()
print(f"  Found: {result is not None}")

print(f"\nPRAGMA foreign_key_check:")
cur.execute("PRAGMA foreign_key_check")
fk = cur.fetchall()
if fk:
    for row in fk:
        print(f"  FK violation: {row}")
else:
    print("   None")

# Try inserting into global_publication_queue
print(f"\nInserting into global_publication_queue:")
try:
    cur.execute("""
        INSERT INTO global_publication_queue (queue_id, entity_id, edge_id, requested_by, requested_at, status)
        VALUES ('q1', 'e1', 'e_edge1', 'user-admin', datetime('now'), 'pending')
    """)
    print("   Insert OK")
except sqlite3.Error as e:
    print(f"   Insert failed: {e}")

conn.close()