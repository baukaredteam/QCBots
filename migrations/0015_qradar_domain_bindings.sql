-- 0015_qradar_domain_bindings.sql
-- M7-D Phase 2A.1: shared QRadar console support.
--
-- One physical QRadar instance can host several native QRadar domains, each
-- belonging to a different Atlas client. Ownership is therefore a property of
-- the DOMAIN, not of the instance. 0011-0014 are applied and are not rewritten.
--
-- Expand step: additive only. Legacy attribution is preserved as inferred
-- metadata and never becomes an authoritative binding automatically.

-- ---------------------------------------------------------------------------
-- Native identity on the domain row
-- ---------------------------------------------------------------------------
ALTER TABLE qradar_domains ADD COLUMN native_qradar_domain_id TEXT;
ALTER TABLE qradar_domains ADD COLUMN native_id_status TEXT NOT NULL DEFAULT 'UNVERIFIED'
    CHECK (native_id_status IN ('UNVERIFIED','VERIFIED'));
ALTER TABLE qradar_domains ADD COLUMN native_id_source TEXT;

-- A native domain id is unique inside one console. It is never derived from
-- domain_name; an empty value stays NULL so the partial index ignores it.
CREATE UNIQUE INDEX IF NOT EXISTS ux_qradar_domains_native_id
    ON qradar_domains(instance_id, native_qradar_domain_id)
    WHERE native_qradar_domain_id IS NOT NULL AND native_qradar_domain_id <> '';

-- ---------------------------------------------------------------------------
-- Domain binding: the single authoritative ownership record
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qradar_domain_bindings (
    binding_id          TEXT PRIMARY KEY,
    domain_id           TEXT NOT NULL UNIQUE REFERENCES qradar_domains(domain_id),
    instance_id         TEXT NOT NULL REFERENCES qradar_instances(instance_id),
    client_id           TEXT REFERENCES clients(client_id),
    binding_kind        TEXT NOT NULL CHECK (binding_kind IN ('CLIENT','SHARED','UNASSIGNED')),
    verification_status TEXT NOT NULL CHECK (verification_status IN ('VERIFIED','UNVERIFIED')),
    -- Legacy attribution kept for reconciliation only. It never authorizes.
    inferred_client_id  TEXT REFERENCES clients(client_id),
    verified_by         TEXT REFERENCES users(user_id),
    verified_at         TEXT,
    evidence_reference  TEXT,
    revision            INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((binding_kind = 'CLIENT' AND client_id IS NOT NULL)
        OR (binding_kind IN ('SHARED','UNASSIGNED') AND client_id IS NULL)),
    CHECK ((verification_status = 'VERIFIED'
            AND verified_by IS NOT NULL AND verified_at IS NOT NULL AND evidence_reference IS NOT NULL)
        OR verification_status = 'UNVERIFIED')
);
CREATE INDEX IF NOT EXISTS idx_domain_bindings_client ON qradar_domain_bindings(client_id);
CREATE INDEX IF NOT EXISTS idx_domain_bindings_instance ON qradar_domain_bindings(instance_id);

-- ---------------------------------------------------------------------------
-- Append-only binding history
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS qradar_domain_binding_history (
    history_id              TEXT PRIMARY KEY,
    binding_id              TEXT NOT NULL REFERENCES qradar_domain_bindings(binding_id),
    domain_id               TEXT NOT NULL REFERENCES qradar_domains(domain_id),
    instance_id             TEXT NOT NULL REFERENCES qradar_instances(instance_id),
    native_qradar_domain_id TEXT,
    previous_kind           TEXT NOT NULL,
    previous_client_id      TEXT,
    previous_status         TEXT NOT NULL,
    new_kind                TEXT NOT NULL,
    new_client_id           TEXT,
    new_status              TEXT NOT NULL,
    actor_id                TEXT NOT NULL REFERENCES users(user_id),
    evidence_reference      TEXT NOT NULL,
    revision                INTEGER NOT NULL,
    created_at              TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_domain_binding_history_domain
    ON qradar_domain_binding_history(domain_id, created_at);

CREATE TRIGGER IF NOT EXISTS trg_domain_binding_history_no_update
BEFORE UPDATE ON qradar_domain_binding_history
BEGIN
    SELECT RAISE(ABORT, 'domain binding history is append-only');
END;
CREATE TRIGGER IF NOT EXISTS trg_domain_binding_history_no_delete
BEFORE DELETE ON qradar_domain_binding_history
BEGIN
    SELECT RAISE(ABORT, 'domain binding history is append-only');
END;

-- ---------------------------------------------------------------------------
-- Backfill: every existing domain gets an UNASSIGNED, UNVERIFIED binding.
-- The old chain client becomes inferred_client_id only — it is NOT promoted.
-- ---------------------------------------------------------------------------
INSERT INTO qradar_domain_bindings
    (binding_id, domain_id, instance_id, client_id, binding_kind, verification_status, inferred_client_id, revision)
SELECT 'qdb-legacy-' || d.domain_id, d.domain_id, d.instance_id, NULL, 'UNASSIGNED', 'UNVERIFIED', i.client_id, 1
FROM qradar_domains d
JOIN qradar_instances i ON i.instance_id = d.instance_id
WHERE NOT EXISTS (SELECT 1 FROM qradar_domain_bindings b WHERE b.domain_id = d.domain_id);

-- ---------------------------------------------------------------------------
-- Atomic cutover of tenant enforcement.
--
-- The 0011 triggers resolve the client through the instance chain, which is
-- wrong for a shared console. They are dropped and replaced in the SAME
-- transaction, so there is no window with neither enforcement active. The new
-- triggers require a VERIFIED CLIENT binding, so legacy UNASSIGNED domains
-- cannot receive tenant data until an administrator confirms them.
-- ---------------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_qradar_import_batch_client_match;
DROP TRIGGER IF EXISTS trg_qradar_field_definition_client_match;
DROP TRIGGER IF EXISTS trg_qradar_field_observation_client_match;
DROP TRIGGER IF EXISTS trg_qradar_field_mapping_client_match;

CREATE TRIGGER trg_qradar_import_batch_binding_match
BEFORE INSERT ON qradar_import_batches
BEGIN
    SELECT RAISE(ABORT, 'import batch client does not match a verified domain binding')
    WHERE NOT EXISTS (
        SELECT 1 FROM qradar_domain_bindings b
        WHERE b.domain_id = NEW.domain_id
          AND b.binding_kind = 'CLIENT'
          AND b.verification_status = 'VERIFIED'
          AND b.client_id = NEW.client_id
    );
END;

CREATE TRIGGER trg_qradar_field_definition_binding_match
BEFORE INSERT ON qradar_field_definitions
BEGIN
    SELECT RAISE(ABORT, 'field definition client does not match a verified domain binding')
    WHERE NOT EXISTS (
        SELECT 1 FROM qradar_domain_bindings b
        WHERE b.domain_id = NEW.domain_id
          AND b.binding_kind = 'CLIENT'
          AND b.verification_status = 'VERIFIED'
          AND b.client_id = NEW.client_id
    );
END;

CREATE TRIGGER trg_qradar_field_mapping_binding_match
BEFORE INSERT ON qradar_field_mappings
BEGIN
    SELECT RAISE(ABORT, 'field mapping client does not match a verified domain binding')
    WHERE NOT EXISTS (
        SELECT 1 FROM qradar_domain_bindings b
        WHERE b.domain_id = NEW.domain_id
          AND b.binding_kind = 'CLIENT'
          AND b.verification_status = 'VERIFIED'
          AND b.client_id = NEW.client_id
    );
END;

CREATE TRIGGER trg_qradar_field_observation_binding_match
BEFORE INSERT ON qradar_field_observations
BEGIN
    SELECT RAISE(ABORT, 'field observation client or field domain does not match a verified domain binding')
    WHERE NOT EXISTS (
        SELECT 1 FROM qradar_field_definitions f
        JOIN qradar_domain_bindings b ON b.domain_id = f.domain_id
        WHERE f.field_id = NEW.field_id
          AND f.client_id = NEW.client_id
          AND f.domain_id = NEW.domain_id
          AND b.binding_kind = 'CLIENT'
          AND b.verification_status = 'VERIFIED'
          AND b.client_id = NEW.client_id
    );
END;
