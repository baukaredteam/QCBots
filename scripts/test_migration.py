import sqlite3
import sys

conn = sqlite3.connect(':memory:')
cur = conn.cursor()

with open('C:/Users/Бауыржан/Desktop/QC_Bots/migrations/0003_evidence_graph.sql', 'r', encoding='utf-8') as f:
    migration_sql = f.read()

print(f'Migration file size: {len(migration_sql)} bytes')
print(f'Contains global_publication_queue: {"global_publication_queue" in migration_sql}')
print(f'Contains evidence_entities: {"evidence_entities" in migration_sql}')
print(f'Contains evidence_graph_edges: {"evidence_graph_edges" in migration_sql}')
print(f'Contains evidence_references: {"evidence_references" in migration_sql}')
print(f'Contains evidence_graph_reviews: {"evidence_graph_reviews" in migration_sql}')
print(f'Contains evidence_edge_history: {"evidence_edge_history" in migration_sql}')

cur.executescript(migration_sql)

cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'evidence_%' ORDER BY name")
tables = [row[0] for row in cur.fetchall()]
print(f"\nTables found ({len(tables)}):")
for t in tables:
    print(f"  {t}")

expected_tables = ['evidence_entities', 'evidence_graph_edges', 'evidence_references', 'evidence_graph_reviews', 'evidence_edge_history', 'global_publication_queue']
print(f"\nExpected tables: {expected_tables}")

for t in expected_tables:
    if t not in tables:
        print(f"  ERROR: Missing table {t}")
    else:
        print(f"  OK: {t}")

print("\nRunning PRAGMA foreign_key_check...")
cur.execute("PRAGMA foreign_key_check")
fk_violations = cur.fetchall()
if fk_violations:
    print(f"FK violations found: {fk_violations}")
else:
    print("No foreign key violations.")

print("\nInserting test clients and users...")
cur.execute("""
INSERT INTO clients (client_id, client_name, status, created_at, updated_at)
VALUES ('client_alpha', 'Client Alpha', 'active', datetime('now'), datetime('now')),
       ('client_beta', 'Client Beta', 'active', datetime('now'), datetime('now'));
INSERT INTO users (user_id, username, role, is_active, created_at, updated_at)
VALUES ('user-admin', 'admin', 'ADMINISTRATOR', 1, datetime('now'), datetime('now')),
       ('user-analyst-alpha', 'analyst-alpha', 'CTI_ANALYST', 1, datetime('now'), datetime('now'));
""")

print("\nInserting evidence entities...")
cur.execute("""
INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, visibility_scope, client_id, created_at, updated_at, created_by)
VALUES ('e_alpha_1', 'indicator', 'indicators', 'ind_alpha_1', 'CLIENT', 'client_alpha', datetime('now'), datetime('now'), 'user-admin');
INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, visibility_scope, client_id, created_at, updated_at, created_by)
VALUES ('e_alpha_2', 'indicator', 'indicators', 'ind_alpha_2', 'CLIENT', 'client_alpha', datetime('now'), datetime('now'), 'user-admin');
INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, visibility_scope, client_id, created_at, updated_at, created_by)
VALUES ('e_global_1', 'technique', 'techniques', 'T1001', 'GLOBAL', NULL, datetime('now'), datetime('now'), 'user-admin');
""")
print("   Entities created.")

print("\nCreating CLIENT edge between entities of same client...")
cur.execute("""
INSERT INTO evidence_graph_edges (edge_id, source_entity_id, target_entity_id, relationship_type, visibility_scope, client_id, relationship_confidence, verification_status, created_at, updated_at, created_by)
VALUES ('e_edge1', 'e_alpha_1', 'e_alpha_2', 'USES', 'CLIENT', 'client_alpha', '3', 'pending', datetime('now'), datetime('now'), 'user-admin');
""")
print("   Edge created.")

print("\nCreating evidence reference...")
cur.execute("""
INSERT INTO evidence_references (evidence_id, edge_id, entity_id, source_type, source_ref, source_snippet, created_at)
VALUES ('ev1', 'e_edge1', 'e_alpha_1', 'report', 'cti_reports.report_alpha_1', 'Ссылка на отчет', datetime('now'));
""")
print("   Evidence reference created.")

print("\nCreating review...")
cur.execute("""
INSERT INTO evidence_graph_reviews (review_id, edge_id, reviewer_id, decision, reason, reviewed_at)
VALUES ('r1', 'e_edge1', 'user-admin', 'APPROVED', 'Верно', datetime('now'));
""")
print("   Review created.")

print("\nTesting UPDATE on review (should be blocked by trigger)...")
try:
    cur.execute("UPDATE evidence_graph_reviews SET reason = 'changed' WHERE review_id = 'r1'")
    print("   ERROR: UPDATE should have been blocked!")
except sqlite3.OperationalError as e:
    if 'immutable' in str(e).lower():
        print("   UPDATE correctly blocked by trigger")
    else:
        print(f"   ERROR: Unexpected error: {e}")

print("\nRunning PRAGMA foreign_key_check...")
cur.execute("PRAGMA foreign_key_check")
fk_violations = cur.fetchall()
if fk_violations:
    print(f"   ERROR: Foreign key violations found:")
    for row in fk_violations:
        print(f"   {row}")
else:
    print("   No foreign key violations.")

print("\nTesting GLOBAL edge with client_id (should fail CHECK constraint)...")
try:
    cur.execute("""
        INSERT INTO evidence_graph_edges (edge_id, source_entity_id, target_entity_id, relationship_type, visibility_scope, client_id, relationship_confidence, verification_status, created_at, updated_at, created_by)
        VALUES ('e2', 'e_alpha_1', 'e_alpha_1', 'USES', 'GLOBAL', 'client_alpha', '1', 'pending', datetime('now'), datetime('now'), 'user-admin');
    """)
    print("   ERROR: GLOBAL edge with client_id should have been rejected!")
except sqlite3.IntegrityError as e:
    print(f"   GLOBAL edge with client_id correctly rejected: {e}")

print("\n=== Smoke Test COMPLETE ===")