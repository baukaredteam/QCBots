#!/bin/bash
# smoke_test_m51.sh — Проверка миграции 0003_evidence_graph.sql на чистой SQLite
set -e

DB_PATH="/tmp/m51_smoke_test.db"
SQL_FILE="migrations/0003_evidence_graph.sql"

rm -f "$DB_PATH"

echo "=== Smoke Test M5.1 Evidence Graph ==="
echo ""

# Проверка: файл миграции существует
if [ ! -f "$SQL_FILE" ]; then
    echo "ERROR: Migration file $SQL_FILE does not exist."
    exit 1
fi
echo "1. Migration file found: $SQL_FILE"

echo "2. Creating helper tables..."
sqlite3 "$DB_PATH" "PRAGMA foreign_keys = ON;" \
"CREATE TABLE IF NOT EXISTS clients (
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
);"
echo "   Helper tables created."

echo "3. Running migration 0003_evidence_graph.sql..."
sqlite3 "$DB_PATH" < "$SQL_FILE"
echo "   Migration applied."

echo "4. Checking 6 evidence_* tables..."
TABLE_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'evidence_%';")
echo "   Tables found: $TABLE_COUNT"
if [ "$TABLE_COUNT" -ne 6 ]; then
    echo "   ERROR: Expected 6 tables, got $TABLE_COUNT"
    sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'evidence_%';"
    exit 1
fi
echo "   All 6 evidence_* tables present."

echo "5. Listing evidence_* tables:"
sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'evidence_%' ORDER BY name;"

echo "6. Checking all 4 triggers exist..."
TRIGGER_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'trg_evidence%';")
echo "   Triggers found: $TRIGGER_COUNT"
if [ "$TRIGGER_COUNT" -ne 4 ]; then
    echo "   ERROR: Expected 4 triggers, got $TRIGGER_COUNT"
    exit 1
fi

echo "7. Running PRAGMA foreign_key_check..."
FK_CHECK=$(sqlite3 "$DB_PATH" "PRAGMA foreign_key_check;")
if [ -n "$FK_CHECK" ]; then
    echo "   ERROR: Foreign key violations found:"
    echo "$FK_CHECK"
    exit 1
fi
echo "   No foreign key violations."

echo "8. Inserting test clients and users..."
sqlite3 "$DB_PATH" "PRAGMA foreign_keys=ON;
INSERT INTO clients (client_id, client_name, status, created_at, updated_at)
VALUES ('client_alpha', 'Client Alpha', 'active', datetime('now'), datetime('now')),
       ('client_beta', 'Client Beta', 'active', datetime('now'), datetime('now'));
INSERT INTO users (user_id, username, role, is_active, created_at, updated_at)
VALUES ('user-admin', 'admin', 'ADMINISTRATOR', 1, datetime('now'), datetime('now')),
       ('user-analyst-alpha', 'analyst-alpha', 'CTI_ANALYST', 1, datetime('now'), datetime('now'));
"
echo "   Clients and users created."

echo "9. Inserting evidence entities (CLIENT + GLOBAL)..."
sqlite3 "$DB_PATH" "PRAGMA foreign_keys=ON;
INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, visibility_scope, client_id, created_at, updated_at, created_by)
VALUES ('e_alpha_1', 'indicator', 'indicators', 'ind_alpha_1', 'CLIENT', 'client_alpha', datetime('now'), datetime('now'), 'user-admin');
INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, visibility_scope, client_id, created_at, updated_at, created_by)
VALUES ('e_alpha_2', 'indicator', 'indicators', 'ind_alpha_2', 'CLIENT', 'client_alpha', datetime('now'), datetime('now'), 'user-admin');
INSERT INTO evidence_entities (entity_id, entity_type, entity_ref_type, entity_ref, visibility_scope, client_id, created_at, updated_at, created_by)
VALUES ('e_global_1', 'technique', 'techniques', 'T1001', 'GLOBAL', NULL, datetime('now'), datetime('now'), 'user-admin');
"
echo "   Entities created."

echo "10. Creating CLIENT edge between entities of same client..."
sqlite3 "$DB_PATH" "PRAGMA foreign_keys=ON;
INSERT INTO evidence_graph_edges (edge_id, source_entity_id, target_entity_id, relationship_type, visibility_scope, client_id, relationship_confidence, verification_status, created_at, updated_at, created_by)
VALUES ('e_edge1', 'e_alpha_1', 'e_alpha_2', 'USES', 'CLIENT', 'client_alpha', '3', 'pending', datetime('now'), datetime('now'), 'user-admin');
"
echo "   Edge created."

echo "11. Creating evidence reference..."
sqlite3 "$DB_PATH" "PRAGMA foreign_keys=ON;
INSERT INTO evidence_references (evidence_id, edge_id, entity_id, source_type, source_ref, source_snippet, created_at)
VALUES ('ev1', 'e_edge1', 'e_alpha_1', 'report', 'cti_reports.report_alpha_1', 'Ссылка на отчет', datetime('now'));
"
echo "   Evidence reference created."

echo "12. Creating review..."
sqlite3 "$DB_PATH" "PRAGMA foreign_keys=ON;
INSERT INTO evidence_graph_reviews (review_id, edge_id, reviewer_id, decision, reason, reviewed_at)
VALUES ('r1', 'e_edge1', 'user-admin', 'APPROVED', 'Верно', datetime('now'));
"
echo "   Review created."

echo "13. Testing UPDATE on review (should be blocked by trigger)..."
UPDATE_RESULT=$(sqlite3 "$DB_PATH" "PRAGMA foreign_keys=ON;
UPDATE evidence_graph_reviews SET reason = 'changed' WHERE review_id = 'r1';" 2>&1)
UPDATE_EXIT=$?
if [ $UPDATE_EXIT -ne 0 ]; then
    echo "   UPDATE correctly blocked (exit code: $UPDATE_EXIT)"
    echo "   Message: $UPDATE_RESULT"
else
    echo "   ERROR: UPDATE should have been blocked!"
    exit 1
fi

echo "14. Testing DELETE on review (should be blocked by trigger)..."
DELETE_RESULT=$(sqlite3 "$DB_PATH" "PRAGMA foreign_keys=ON;
DELETE FROM evidence_graph_reviews WHERE review_id = 'r1';" 2>&1)
DELETE_EXIT=$?
if [ $DELETE_EXIT -ne 0 ]; then
    echo "   DELETE correctly blocked (exit code: $DELETE_EXIT)"
else
    echo "   ERROR: DELETE should have been blocked!"
    exit 1
fi

echo "15. Running PRAGMA foreign_key_check..."
FK_CHECK=$(sqlite3 "$DB_PATH" "PRAGMA foreign_key_check;")
if [ -n "$FK_CHECK" ]; then
    echo "   ERROR: Foreign key violations found:"
    echo "$FK_CHECK"
    exit 1
fi
echo "   No foreign key violations."

echo "16. Testing: GLOBAL edge with client_id should fail CHECK constraint..."
sqlite3 "$DB_PATH" "PRAGMA foreign_keys=ON;
INSERT INTO evidence_graph_edges (edge_id, source_entity_id, target_entity_id, relationship_type, visibility_scope, client_id, relationship_confidence, verification_status, created_at, updated_at, created_by)
VALUES ('e2', 'e_alpha_1', 'e_alpha_1', 'USES', 'GLOBAL', 'client_alpha', '1', 'pending', datetime('now'), datetime('now'), 'user-admin');" 2>&1
GLOBAL_EXIT=$?
if [ $GLOBAL_EXIT -ne 0 ]; then
    echo "   GLOBAL edge with client_id correctly rejected (exit code: $GLOBAL_EXIT)"
else
    echo "   ERROR: GLOBAL edge with client_id should have been rejected!"
    exit 1
fi

echo ""
echo "=== Smoke Test PASSED ==="
exit 0