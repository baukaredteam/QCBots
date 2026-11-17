-- 0021_hunt_plan_item_binding_owner.sql
-- M7-D Phase 2B-4B SQL preflight. Additive; 0001-0020 are not rewritten.
--
-- Migration 0020 proved that plan, translation and item agree on client, domain
-- and native id, and that the domain binding is VERIFIED at the translation's
-- revision. It did not compare binding.client_id with translation.client_id, so
-- a binding reassigned to another client between the draft and the insert could
-- still satisfy every 0020 condition. This trigger closes that gap and also
-- requires the verification metadata that makes a binding evidence.

CREATE TRIGGER IF NOT EXISTS trg_hunt_plan_version_items_binding_owner
BEFORE INSERT ON hunt_plan_version_items
BEGIN
    SELECT RAISE(ABORT, 'plan item binding belongs to another client')
    WHERE NOT EXISTS (
        SELECT 1
        FROM qradar_domain_bindings b
        JOIN detection_translations t ON t.translation_id = NEW.translation_id
        WHERE b.domain_id = NEW.domain_id
          AND b.client_id = t.client_id
          AND b.binding_kind = 'CLIENT'
          AND b.verification_status = 'VERIFIED'
          AND COALESCE(b.verified_by, '') <> ''
          AND COALESCE(b.verified_at, '') <> ''
          AND COALESCE(b.evidence_reference, '') <> ''
          AND b.revision = t.binding_revision
    );
END;
