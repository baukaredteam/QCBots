-- Migration 0002: QRadar Inventory tables
-- MSSP Intelligence Workbench
-- SQLite WAL mode, foreign keys enabled, transactional writes

PRAGMA foreign_keys = ON;

-- Extend global_fields with QRadar inventory columns
ALTER TABLE global_fields ADD COLUMN availability TEXT;
ALTER TABLE global_fields ADD COLUMN log_sources TEXT;
ALTER TABLE global_fields ADD COLUMN adversary_control TEXT;
ALTER TABLE global_fields ADD COLUMN used_in_events TEXT;
ALTER TABLE global_fields ADD COLUMN display_name TEXT;

-- Extend detection_rules with QRadar inventory columns
ALTER TABLE detection_rules ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN created_date TEXT;
ALTER TABLE detection_rules ADD COLUMN modified_date TEXT;
ALTER TABLE detection_rules ADD COLUMN event_count_30d INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN offense_count_30d INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN log_source TEXT;
ALTER TABLE detection_rules ADD COLUMN criticality TEXT;
ALTER TABLE detection_rules ADD COLUMN sysmon_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN full_rule_logic TEXT;
ALTER TABLE detection_rules ADD COLUMN effective_detection_logic TEXT;
ALTER TABLE detection_rules ADD COLUMN bb_chain_summary TEXT;
ALTER TABLE detection_rules ADD COLUMN custom_fields TEXT;
ALTER TABLE detection_rules ADD COLUMN reference_sets_used TEXT;
ALTER TABLE detection_rules ADD COLUMN building_blocks TEXT;

-- Building blocks (shared QRadar building blocks)
CREATE TABLE IF NOT EXISTS building_blocks (
    bb_id TEXT PRIMARY KEY,
    bb_name TEXT NOT NULL,
    level INTEGER,
    category TEXT,
    depends_on_bb TEXT,
    own_conditions TEXT,
    full_bb_logic TEXT,
    adversary_control TEXT,
    availability TEXT,
    sysmon_required INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Rule to building block mapping
CREATE TABLE IF NOT EXISTS rule_building_blocks (
    rule_id TEXT NOT NULL REFERENCES detection_rules(rule_id),
    bb_id TEXT NOT NULL REFERENCES building_blocks(bb_id),
    PRIMARY KEY (rule_id, bb_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_building_blocks_category ON building_blocks(category);
CREATE INDEX IF NOT EXISTS idx_building_blocks_level ON building_blocks(level);
CREATE INDEX IF NOT EXISTS idx_rule_building_blocks_rule ON rule_building_blocks(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_building_blocks_bb ON rule_building_blocks(bb_id);

-- Record migration
INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES ('0002_qradar_inventory', datetime('now'));