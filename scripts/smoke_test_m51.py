import sqlite3
import os
import sys

DB_PATH = "C:/Users/Бауыржан/Desktop/QC_Bots/scripts/m51_smoke_test.db"
MIGRATION_FILE = "C:/Users/Бауыржан/Desktop/QC_Bots/migrations/0003_evidence_graph.sql"

def main():
    # Remove old DB if exists
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON")

    print("=== Smoke Test M5.1 Evidence Graph ===")
    print("")

    # Step 1: Create helper tables
    print("1. Creating helper tables...")
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
    print("   Helper tables created.")

    # Step 2: Run migration
    print("2. Running migration 0003_evidence_graph.sql...")
    with open(MIGRATION_FILE, 'r', encoding='utf-8') as f:
        migration_sql = f.read()
    cur.executescript(migration_sql)
    print("   Migration applied.")

    # Step 3: Check 6 evidence tables
    print("5. Checking evidence tables...")
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row[0] for row in cur.fetchall()]
    print(f"   Tables found ({len(tables)}):")
    for t in tables:
        print(f"     {t}")
    expected_tables = ['evidence_entities', 'evidence_graph_edges', 'evidence_references', 'evidence_graph_reviews', 'evidence_edge_history', 'global_publication_queue']
    missing = []
    for t in expected_tables:
        if t not in tables:
            print(f"   ERROR: Missing table {t}")
            missing.append(t)
    if missing:
        print(f"   ERROR: Missing {len(missing)} table(s): {missing}")
        exit(1)
    print("   All 6 tables present.")

    # Step 4: PRAGMA foreign_key_check
    print("6. Running PRAGMA foreign_key_check...")
    cur.execute("PRAGMA foreign_key_check")
    fk_violations = cur.fetchall()
    if fk_violations:
        print("   ERROR: Foreign key violations found:")
        for row in fk_violations:
            print(f"   {row}")
        exit(1)
    print("   No foreign key violations.")

    # Step 7: Insert evidence entities
    print("8. Inserting evidence entities...")
    cur.execute("""
INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, visibility_scope, client_id, created_at, updated_at, created_by)
VALUES ('e_alpha_1', 'indicator', 'indicators', 'ind_alpha_1', 'CLIENT', 'client_alpha', datetime('now'), datetime('now'), 'user-admin');
""")
    cur.execute("""
INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, visibility_scope, client_id, created_at, updated_at, created_by)
VALUES ('e_alpha_2', 'indicator', 'indicators', 'ind_alpha_2', 'CLIENT', 'client_alpha', datetime('now'), datetime('now'), 'user-admin');
""")
    cur.execute("""
INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, visibility_scope, client_id, created_at, updated_at, created_by)
VALUES ('e_global_1', 'technique', 'techniques', 'T1001', 'GLOBAL', NULL, datetime('now'), datetime('now'), 'user-admin');
""")
    print("   Entities created.")

    # Step 9: Create CLIENT edge
    print("9. Creating CLIENT edge between entities of same client...")
    cur.execute("""
INSERT INTO evidence_graph_edges (edge_id, source_entity_id, target_entity_id, relationship_type, visibility_scope, client_id, relationship_confidence, verification_status, created_at, updated_at, created_by)
VALUES ('e_edge1', 'e_alpha_1', 'e_alpha_2', 'USES', 'CLIENT', 'client_alpha', '3', 'pending', datetime('now'), datetime('now'), 'user-admin');
""")
    print("   Edge created.")

    # Step 10: Create evidence reference
    print("10. Creating evidence reference...")
    cur.execute("""
INSERT INTO evidence_references (evidence_id, edge_id, entity_id, source_type, source_ref, source_snippet, created_at)
VALUES ('ev1', 'e_edge1', 'e_alpha_1', 'report', 'cti_reports.report_alpha_1', 'Ссылка на отчет', datetime('now'));
""")
    print("   Evidence reference created.")

    # Step 11: Create review
    print("11. Creating review...")
    cur.execute("""
INSERT INTO evidence_graph_reviews (review_id, edge_id, reviewer_id, decision, reason, reviewed_at)
VALUES ('r1', 'e_edge1', 'user-admin', 'APPROVED', 'Верно', datetime('now'));
""")
    print("   Review created.")

    # Step 12: Test UPDATE on review (should be blocked by trigger)
    print("12. Testing UPDATE on review (should be blocked by trigger)...")
    try:
        cur.execute("UPDATE evidence_graph_reviews SET reason = 'changed' WHERE review_id = 'r1'")
        print("   ERROR: UPDATE should have been blocked!")
        exit(1)
    except sqlite3.IntegrityError as e:
        if 'immutable' in str(e).lower():
            print("   UPDATE correctly blocked by trigger")
        else:
            print(f"   ERROR: Unexpected error: {e}")
            exit(1)

    # Step 13: Running PRAGMA foreign_key_check
    print("13. Running PRAGMA foreign_key_check...")
    cur.execute("PRAGMA foreign_key_check")
    fk_violations = cur.fetchall()
    if fk_violations:
        print("   ERROR: Foreign key violations found:")
        for row in fk_violations:
            print(f"   {row}")
        exit(1)
    print("   No foreign key violations.")

    # Step 14: Testing: GLOBAL edge with client_id should fail CHECK constraint
    print("14. Testing: GLOBAL edge with client_id should fail CHECK constraint...")
    try:
        cur.execute("""
INSERT INTO evidence_graph_edges (edge_id, source_entity_id, target_entity_id, relationship_type, visibility_scope, client_id, relationship_confidence, verification_status, created_at, updated_at, created_by)
VALUES ('e2', 'e_alpha_1', 'e_alpha_1', 'USES', 'GLOBAL', 'client_alpha', '1', 'pending', datetime('now'), datetime('now'), 'user-admin');
""")
        print("   ERROR: GLOBAL edge with client_id should have been rejected!")
        exit(1)
    except sqlite3.IntegrityError as e:
        print(f"   GLOBAL edge with client_id correctly rejected")

    print("")
    print("=== Smoke Test PASSED ===")
    conn.close()

if __name__ == '__main__':
    main()