-- 0016_domain_binding_update_guards.sql
-- Phase 2A.1 trust hardening. Forward migration; 0001-0015 are not rewritten.
--
-- 0015 enforced consistency on INSERT only. These triggers enforce the same
-- invariants on UPDATE, so a service bug (or direct SQL) cannot produce an
-- inconsistent ownership state:
--   * a binding's domain/instance identity is immutable;
--   * kind and client must agree;
--   * VERIFIED requires actor, timestamp and evidence;
--   * a VERIFIED CLIENT binding requires a VERIFIED, non-empty native domain id
--     on the domain row;
--   * a native id that a verified client binding depends on cannot be cleared or
--     invalidated;
--   * a VERIFIED native id must keep an id and a provenance source.

CREATE TRIGGER IF NOT EXISTS trg_domain_binding_update_guard
BEFORE UPDATE ON qradar_domain_bindings
BEGIN
    SELECT RAISE(ABORT, 'binding domain identity is immutable')
    WHERE NEW.domain_id <> OLD.domain_id OR NEW.instance_id <> OLD.instance_id;

    SELECT RAISE(ABORT, 'binding kind and client disagree')
    WHERE (NEW.binding_kind = 'CLIENT' AND NEW.client_id IS NULL)
       OR (NEW.binding_kind IN ('SHARED','UNASSIGNED') AND NEW.client_id IS NOT NULL);

    SELECT RAISE(ABORT, 'verified binding requires actor, timestamp and evidence')
    WHERE NEW.verification_status = 'VERIFIED'
      AND (NEW.verified_by IS NULL OR NEW.verified_at IS NULL OR NEW.evidence_reference IS NULL
           OR TRIM(NEW.evidence_reference) = '');

    SELECT RAISE(ABORT, 'verified client binding requires a verified native domain id')
    WHERE NEW.verification_status = 'VERIFIED'
      AND NEW.binding_kind = 'CLIENT'
      AND NOT EXISTS (
          SELECT 1 FROM qradar_domains d
          WHERE d.domain_id = NEW.domain_id
            AND d.native_qradar_domain_id IS NOT NULL
            AND TRIM(d.native_qradar_domain_id) <> ''
            AND d.native_id_status = 'VERIFIED'
      );
END;

CREATE TRIGGER IF NOT EXISTS trg_qradar_domain_native_id_update_guard
BEFORE UPDATE OF native_qradar_domain_id, native_id_status, native_id_source ON qradar_domains
BEGIN
    SELECT RAISE(ABORT, 'verified native id requires an id and a provenance source')
    WHERE NEW.native_id_status = 'VERIFIED'
      AND (NEW.native_qradar_domain_id IS NULL OR TRIM(NEW.native_qradar_domain_id) = ''
           OR NEW.native_id_source IS NULL OR TRIM(NEW.native_id_source) = '');

    SELECT RAISE(ABORT, 'cannot invalidate a native id used by a verified client binding')
    WHERE (NEW.native_qradar_domain_id IS NULL OR TRIM(NEW.native_qradar_domain_id) = ''
           OR NEW.native_id_status <> 'VERIFIED')
      AND EXISTS (
          SELECT 1 FROM qradar_domain_bindings b
          WHERE b.domain_id = NEW.domain_id
            AND b.binding_kind = 'CLIENT'
            AND b.verification_status = 'VERIFIED'
      );
END;

-- A domain may not be inserted with a VERIFIED native id that has no provenance.
CREATE TRIGGER IF NOT EXISTS trg_qradar_domain_native_id_insert_guard
BEFORE INSERT ON qradar_domains
BEGIN
    SELECT RAISE(ABORT, 'verified native id requires an id and a provenance source')
    WHERE NEW.native_id_status = 'VERIFIED'
      AND (NEW.native_qradar_domain_id IS NULL OR TRIM(NEW.native_qradar_domain_id) = ''
           OR NEW.native_id_source IS NULL OR TRIM(NEW.native_id_source) = '');
END;
