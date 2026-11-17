import sqlite3

conn = sqlite3.connect(':memory:')
cur = conn.cursor()

# Step 1: Create helper tables (as smoke_test does)
cur.executescript("""
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'READ_ONLY',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS indicators (
    indicator_id TEXT PRIMARY KEY,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO clients (client_id, client_name, status, created_at, updated_at)
VALUES ('client_alpha', 'Client Alpha', 'active', datetime('now'), datetime('now')),
       ('client_beta', 'Client Beta', 'active', datetime('now'), datetime('now'));
INSERT INTO users (user_id, username, role, is_active, created_at, updated_at)
VALUES ('user-admin', 'admin', 'ADMINISTRATOR', 1, datetime('now'), datetime('now')),
       ('user-analyst-alpha', 'analyst-alpha', 'CTI_ANALYST', 1, datetime('now'), datetime('now'));
""")
print("Helper tables created.")

# Step 2: Run migration
with open('C:/Users/Бауыржан/Desktop/QC_Bots/migrations/0003_evidence_graph.sql', 'r', encoding='utf-8') as f:
    migration_sql = f.read()
cur.executescript(migration_sql)
print("Migration applied.")

# Step 3: Check tables
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'evidence_%' ORDER BY name")
tables = [row[0] for row in cur.fetchall()]
print(f"Tables found ({len(tables)}):")
for t in tables:
    print(f"  {t}")

expected = ['evidence_entities', 'evidence_graph_edges', 'evidence_references', 'evidence_graph_reviews', 'evidence_edge_history', 'global_publication_queue']
for t in expected:
    status = "OK" if t in tables else "MISSING"
    print(f"  {t}: {status}")

print(f"\nExpected count: 6, Found: {len(tables)}")