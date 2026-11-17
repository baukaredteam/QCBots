-- 0014_import_identity_scope.sql
-- Forward migration. 0011-0013 are already applied and are not rewritten.
--
-- Import identity was scoped to (client_id, file_hash). A single Atlas client
-- can own several QRadar domains, so the same export can legitimately be
-- imported into two domains and must produce two batches — while a replay into
-- the same domain must stay idempotent.
--
-- Canonical identity: (client_id, domain_id, source_type, file_hash).
--
-- A Log Source ID is not part of the key: at upload time it is not known (the
-- operator uploads a domain-scoped export, not a single log source), and adding
-- a nullable column to the key would make uniqueness depend on NULL semantics.
-- Source type is included because the same bytes parsed as CSV and as IIS are
-- different operations with different parser semantics.
--
-- If existing rows already collide on the new key the unique index creation
-- fails, the migration transaction rolls back, and the database is left exactly
-- as it was. That situation needs an operator decision (which duplicate is
-- authoritative) and is reported as a blocker rather than resolved by deletion.

DROP INDEX IF EXISTS idx_qradar_import_batches_file_hash;

CREATE UNIQUE INDEX IF NOT EXISTS idx_qradar_import_batches_identity
    ON qradar_import_batches(client_id, domain_id, source_type, file_hash);
