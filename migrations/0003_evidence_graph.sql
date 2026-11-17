-- Migration 0003_evidence_graph.sql v2.1
-- Evidence Graph Foundation (M5.1)
-- READ-ONLY design: existing tables NOT modified

PRAGMA foreign_keys = ON;

-- 1. Evidence entities (graph nodes)
CREATE TABLE IF NOT EXISTS evidence_entities (
    entity_id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL
        CHECK (entity_type IN ('indicator','threat_actor','technique','cve','malware','campaign','report','file')),
    entity_ref_type TEXT NOT NULL
        CHECK (entity_ref_type IN ('indicators','threat_actors','techniques','cves','malware','campaigns','cti_reports','file_artifacts')),
    entity_ref TEXT NOT NULL,
    display_name TEXT,
    description TEXT,
    visibility_scope TEXT NOT NULL
        CHECK (visibility_scope IN ('GLOBAL','CLIENT')),
    client_id TEXT REFERENCES clients(client_id),
    provenance_source TEXT,
    provenance_checksum TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT REFERENCES users(user_id),
    CONSTRAINT chk_entity_scope CHECK (
        (visibility_scope = 'GLOBAL' AND client_id IS NULL) OR
        (visibility_scope = 'CLIENT' AND client_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_entities_global_unique
    ON evidence_entities(entity_type, entity_ref_type, entity_ref)
    WHERE visibility_scope = 'GLOBAL' AND client_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_entities_client_unique
    ON evidence_entities(entity_type, entity_ref_type, entity_ref, client_id)
    WHERE visibility_scope = 'CLIENT' AND client_id IS NOT NULL;

-- 2. Evidence graph edges (relationships)
CREATE TABLE IF NOT EXISTS evidence_graph_edges (
    edge_id TEXT PRIMARY KEY,
    source_entity_id TEXT NOT NULL REFERENCES evidence_entities(entity_id),
    target_entity_id TEXT NOT NULL REFERENCES evidence_entities(entity_id),
    relationship_type TEXT NOT NULL
        CHECK (relationship_type IN ('USES','TARGETS','ASSOCIATED_WITH','EXPLOITS','COMMUNICATES_WITH','OBSERVED_IN','RELATED_TO','MITIGATES','DETECTED_BY')),
    visibility_scope TEXT NOT NULL
        CHECK (visibility_scope IN ('GLOBAL','CLIENT')),
    client_id TEXT REFERENCES clients(client_id),
    relationship_confidence TEXT
        CHECK (relationship_confidence IN ('1','2','3','4','5','6')),
    verification_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (verification_status IN ('pending','verified','rejected','revoked')),
    verified_by TEXT REFERENCES users(user_id),
    verified_at TEXT,
    review_reason TEXT,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_by TEXT REFERENCES users(user_id),
    revoked_at TEXT,
    revoke_reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT REFERENCES users(user_id),
    CONSTRAINT chk_edge_client_scope CHECK (
        (visibility_scope = 'GLOBAL' AND client_id IS NULL) OR
        (visibility_scope = 'CLIENT' AND client_id IS NOT NULL)
    )
);

-- 3. Evidence references (multiple per edge) — NO ON DELETE CASCADE
CREATE TABLE IF NOT EXISTS evidence_references (
    evidence_id TEXT PRIMARY KEY,
    edge_id TEXT NOT NULL REFERENCES evidence_graph_edges(edge_id),
    entity_id TEXT NOT NULL REFERENCES evidence_entities(entity_id),
    source_type TEXT NOT NULL
        CHECK (source_type IN ('report','claim','field','file')),
    source_ref TEXT NOT NULL,
    source_snippet TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Evidence graph reviews (immutable)
CREATE TABLE IF NOT EXISTS evidence_graph_reviews (
    review_id TEXT PRIMARY KEY,
    edge_id TEXT NOT NULL REFERENCES evidence_graph_edges(edge_id),
    reviewer_id TEXT NOT NULL REFERENCES users(user_id),
    decision TEXT NOT NULL
        CHECK (decision IN ('APPROVED','REJECTED','NEEDS_MORE_DATA')),
    reason TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT,
    reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 5. Edge change history (immutable)
CREATE TABLE IF NOT EXISTS evidence_edge_history (
    history_id TEXT PRIMARY KEY,
    edge_id TEXT NOT NULL REFERENCES evidence_graph_edges(edge_id),
    field_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by TEXT REFERENCES users(user_id),
    changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 6. Global publication queue
CREATE TABLE IF NOT EXISTS global_publication_queue (
    queue_id TEXT PRIMARY KEY,
    entity_id TEXT REFERENCES evidence_entities(entity_id),
    edge_id TEXT REFERENCES evidence_graph_edges(edge_id),
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_by TEXT REFERENCES users(user_id),
    approved_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected')),
    rejection_reason TEXT
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_evidence_entities_client ON evidence_entities(client_id);
CREATE INDEX IF NOT EXISTS idx_evidence_entities_type ON evidence_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_evidence_entities_scope ON evidence_entities(visibility_scope);
CREATE INDEX IF NOT EXISTS idx_evidence_entities_ref ON evidence_entities(entity_ref_type, entity_ref);
CREATE INDEX IF NOT EXISTS idx_edges_source ON evidence_graph_edges(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON evidence_graph_edges(target_entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_client ON evidence_graph_edges(client_id);
CREATE INDEX IF NOT EXISTS idx_edges_scope ON evidence_graph_edges(visibility_scope);
CREATE INDEX IF NOT EXISTS idx_edges_status ON evidence_graph_edges(verification_status);
CREATE INDEX IF NOT EXISTS idx_edges_relationship ON evidence_graph_edges(relationship_type);
CREATE INDEX IF NOT EXISTS idx_edges_revoked ON evidence_graph_edges(is_revoked);
CREATE INDEX IF NOT EXISTS idx_provenance_entity ON evidence_references(entity_id);
CREATE INDEX IF NOT EXISTS idx_provenance_edge ON evidence_references(edge_id);
CREATE INDEX IF NOT EXISTS idx_reviews_edge ON evidence_graph_reviews(edge_id);
CREATE INDEX IF NOT EXISTS idx_reviews_reviewer ON evidence_graph_reviews(reviewer_id);
CREATE INDEX IF NOT EXISTS idx_history_edge ON evidence_edge_history(edge_id);
CREATE INDEX IF NOT EXISTS idx_pub_queue_status ON global_publication_queue(status);

-- 7. Triggers: protect reviews and history from modification
CREATE TRIGGER IF NOT EXISTS trg_evidence_graph_reviews_no_update
BEFORE UPDATE ON evidence_graph_reviews
BEGIN
    SELECT RAISE(ABORT, 'evidence_graph_reviews is immutable: UPDATE not allowed');
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_graph_reviews_no_delete
BEFORE DELETE ON evidence_graph_reviews
BEGIN
    SELECT RAISE(ABORT, 'evidence_graph_reviews is immutable: DELETE not allowed');
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_edge_history_no_update
BEFORE UPDATE ON evidence_edge_history
BEGIN
    SELECT RAISE(ABORT, 'evidence_edge_history is immutable: UPDATE not allowed');
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_edge_history_no_delete
BEFORE DELETE ON evidence_edge_history
BEGIN
    SELECT RAISE(ABORT, 'evidence_edge_history is immutable: DELETE not allowed');
END;