-- 0020_hunt_plan_item_integrity.sql
-- M7-D Phase 2B-4A security gate. Additive; 0001-0019 are not rewritten.
--
-- A plan item is a claim that a specific reviewed draft, for this client and
-- domain, with this native QRadar Domain ID, was attached. The service checks
-- this; the storage boundary proves it, so a direct SQL insert cannot create a
-- plan that mixes tenants or domains.
--
-- Scope: BEFORE INSERT only. Items are immutable after insert (0019).

CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_version_items_evidence
BEFORE INSERT ON hunt_plan_version_items
BEGIN
    SELECT RAISE(ABORT, 'plan item must reference a reviewed draft of the same client and domain')
    WHERE NOT EXISTS (
        SELECT 1
        FROM detection_translations t
        JOIN hunt_plan_versions p ON p.plan_id = NEW.plan_id
        WHERE t.translation_id = NEW.translation_id
          AND t.client_id = p.client_id
          AND t.domain_id = NEW.domain_id
          AND t.native_qradar_domain_id = NEW.native_qradar_domain_id
          AND t.status = 'READY_FOR_REVIEW'
          AND t.aql_sha256 <> ''
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_version_items_binding
BEFORE INSERT ON hunt_plan_version_items
BEGIN
    SELECT RAISE(ABORT, 'plan item domain is not a current verified client binding')
    WHERE NOT EXISTS (
        SELECT 1
        FROM qradar_domain_bindings b
        JOIN qradar_domains d ON d.domain_id = b.domain_id
        JOIN detection_translations t ON t.translation_id = NEW.translation_id
        WHERE b.domain_id = NEW.domain_id
          AND b.binding_kind = 'CLIENT'
          AND b.verification_status = 'VERIFIED'
          AND b.revision = t.binding_revision
          AND d.native_qradar_domain_id = NEW.native_qradar_domain_id
          AND d.native_id_status = 'VERIFIED'
    );
END;
