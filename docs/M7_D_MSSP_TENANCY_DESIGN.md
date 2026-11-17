# M7-D — MSSP QRadar Tenancy Model (implemented contract, Phase 2A.1)

Status: **IMPLEMENTED** in migration `0015_qradar_domain_bindings.sql` and
`backend/domain_binding.go`. This document is the single contract; the earlier
"design only" text, including the rejected idea of inferring a native Domain ID
from `domain_name`, is superseded.

## 1. Problem

`qradar_instances(client_id)` says an instance belongs to one client, and domains
inherited that client through the instance. A shared MSSP console (one QRadar
instance, one domain per client) cannot be represented that way: every domain
would be attributed to one client.

## 2. Model

```
qradar_instances            one physical console (legacy client_id = creator/owner metadata only)
  └── qradar_domains        internal domain_id + native_qradar_domain_id + native_id_status
        └── qradar_domain_bindings   THE authoritative ownership record
              └── qradar_domain_binding_history   append-only decisions
```

**Ownership rule:** a domain belongs to a client only through its binding, and
only when `binding_kind = 'CLIENT'` **and** `verification_status = 'VERIFIED'`.
Instance ownership never grants domain access. Unverified legacy attribution is
kept as `inferred_client_id` and never authorizes anything.

Identifiers stay distinct and are never derived from each other:
`client_id`, internal `instance_id`, internal `domain_id`,
`native_qradar_domain_id`, `devicetype`, `logsourceid`, `qid`, `native_event_id`.
In particular the native Domain ID is **never** taken from `domain_name`.

## 3. Schema (0015, additive)

`qradar_domains`
- `native_qradar_domain_id TEXT` — from QRadar metadata or an administrator decision
- `native_id_status` — `UNVERIFIED` | `VERIFIED`
- `native_id_source` — provenance (`ADMIN_CONFIRMED`, `SEED_SYNTHETIC`, …)
- `UNIQUE INDEX (instance_id, native_qradar_domain_id) WHERE native_qradar_domain_id IS NOT NULL AND <> ''`
  → duplicates rejected on one console, allowed across consoles.

`qradar_domain_bindings` (one row per domain, `domain_id UNIQUE`)
- `binding_kind` — `CLIENT` | `SHARED` | `UNASSIGNED`
- `client_id` (NULL for SHARED/UNASSIGNED), `inferred_client_id` (reconciliation only)
- `verification_status`, `verified_by`, `verified_at`, `evidence_reference`
- `revision` — optimistic concurrency token
- CHECK: CLIENT ⇒ client not null; SHARED/UNASSIGNED ⇒ client null;
  VERIFIED ⇒ actor + timestamp + evidence present.

`qradar_domain_binding_history` — append-only (BEFORE UPDATE/DELETE triggers
raise ABORT); records previous/new kind, client and status, native ID, actor,
evidence and revision.

Backfill: every pre-existing domain becomes `UNASSIGNED`/`UNVERIFIED` with the old
chain client stored as `inferred_client_id`. No automatic promotion, no invented
native ID, no rewritten attribution.

## 4. Tenant enforcement

The four 0011 triggers (`*_client_match`) resolved the client through the instance
chain. They are dropped and replaced **in the same transaction** by
`*_binding_match` triggers that require a VERIFIED CLIENT binding:

- `qradar_import_batches`, `qradar_field_definitions`, `qradar_field_mappings`
  → `binding.client_id = NEW.client_id` for `NEW.domain_id`
- `qradar_field_observations` → additionally requires the field definition to
  belong to the same client **and** domain

Atomic cutover: there is no window in which neither old nor new enforcement is
active, because both statements live in one migration transaction. Legacy
UNASSIGNED domains therefore cannot receive tenant data until confirmed.

## 5. Resolver

`ClientOfDomain(domainID)` → binding → `(CLIENT, VERIFIED)` → client, else
`DOMAIN_NOT_ASSIGNED` / `DOMAIN_BINDING_MISSING`.

`requireDomainAccess(userID, domainID, claimedClientID, capability)`:
1. resolve the owner (deny by default),
2. reject a claim that disagrees with the binding (`409 CONFLICT`),
3. enforce the operation capability,
4. enforce the caller's client grant (administrators included).

Every field-intel service path uses it: instances (listing), domains, log source
types, log sources, QIDs, field definitions, mappings, observations, import
batches, review, publish and mapping approval. Nested entities resolve their
domain through the parent chain (`domainOfLogSourceType`, `domainOfLogSource`,
`domainOfQID`).

Import batches additionally verify historical integrity: `batchClient` compares
`batch.client_id` with the domain's current binding and returns `409` on a
mismatch instead of re-attributing the batch.

## 6. Binding management

`PUT /api/v1/qradar/domains/{domain_id}/binding` — administrator only
(`CanManageQRadarBindings`), routed and service-enforced.

- actor identity and timestamps are taken from the session, never the request;
- evidence ≥ 12 chars and not generic;
- native ID validated as digits, unique per instance;
- `expected_revision` makes concurrent confirmations deterministic: one wins,
  the other gets `409 BINDING_CONFLICT`;
- history row + audit row are written in the same transaction as the change.

`GET /api/v1/qradar/domain-bindings?instance_id=` — administrators see all
domains (including unassigned, for reconciliation); other users see only
VERIFIED CLIENT bindings for clients they are granted.

`GET /api/v1/qradar/domains/{domain_id}/binding-history` — administrators, or a
user with verified access to that domain.

## 7. Historical data

Existing batches keep `client_id`, `domain_id`, timestamps and review history.
If a domain is rebound, the batch is not moved, edited or deleted; reads and
review/publish fail with an integrity conflict until an administrator resolves it.

## 8. Remaining work (out of scope for 2A.1)

- Dropping the legacy `qradar_instances.client_id` column (destructive; separate
  migration once nothing reads it).
- Automatic discovery of native Domain IDs from the QRadar API (no live API in
  this milestone; values are entered by an administrator with evidence).
- Binding management UI beyond the Field Intelligence panel (list, confirm,
  history are implemented there).
