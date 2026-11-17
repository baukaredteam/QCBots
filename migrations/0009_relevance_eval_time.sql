-- Migration 0009_relevance_eval_time.sql
-- M7-C: persist the evaluation reference time. TELEMETRY staleness is judged
-- against this clock, pinned at assessment creation, so historical findings
-- are never reinterpreted using a later clock.

PRAGMA foreign_keys = ON;

ALTER TABLE relevance_assessments ADD COLUMN evaluation_at TEXT;
