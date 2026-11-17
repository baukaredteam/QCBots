import sqlite3

conn = sqlite3.connect(':memory:')
cur = conn.cursor()

cur.executescript("""
CREATE TABLE IF NOT EXISTS evidence_entities (
    entity_id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL CHECK (entity_type IN ('indicator','threat_actor','technique','cve','malware','campaign','report','file')),
    entity_ref_type TEXT NOT NULL CHECK (entity_ref_type IN ('indicators','threat_actors','techniques','cves','malware','campaigns','cti_reports','file_artifacts')),
    entity_ref TEXT NOT NULL,
    visibility_scope TEXT NOT NULL CHECK (visibility_scope IN ('GLOBAL','CLIENT')),
    client_id TEXT REFERENCES clients(client_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT REFERENCES users(user_id),
    CONSTRAINT chk_entity_scope CHECK (
        (visibility_scope = 'GLOBAL' AND client_id IS NULL) OR
        (visibility_scope = 'CLIENT' AND client_id IS NOT NULL)
    )
);
CREATE TABLE IF NOT EXISTS global_publication_queue (
    queue_id TEXT PRIMARY KEY,
    entity_id TEXT REFERENCES evidence_entities(entity_id),
    edge_id TEXT REFERENCES evidence_graph_edges(edge_id),
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_by TEXT REFERENCES users(user_id),
    approved_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    rejection_reason TEXT
);
""")

cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [row[0] for row in cur.fetchall()]
print(f"Tables: {tables}")
print(f"Count: {len(tables)}")

# Try inserting into global_publication_queue
try:
    cur.execute("""
        INSERT INTO global_publication_queue (queue_id, entity_id, edge_id, requested_by, requested_at, status)
        VALUES ('q1', 'e1', 'e_edge1', 'user-admin', datetime('now'), 'pending')
    """)
    print("global_publication_queue insert: OK")
except sqlite3.Error as e:
    print(f"global_publication_queue insert FAILED: {e}")