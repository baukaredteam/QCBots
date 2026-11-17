# Sentinel Atlas — M6 Frontend Design Specification v1.1

**Status:** Design — Pending Stakeholder Approval  
**Mode:** READ-ONLY DESIGN (no code changes to existing project)

---

## 1. Design Corrections (v1.0 → v1.1)

| # | Issue in v1.0 | Correction in v1.1 |
|---|---------------|-------------------|
| 1 | Case Lifecycle Status and Human Review Decision were conflated | **Separated**: Case Status (OPEN/IN_PROGRESS/REVIEW/CLOSED/ARCHIVED) vs Review Decision (APPROVED/REJECTED/NEEDS_MORE_DATA). They are distinct enums with distinct permissions. |
| 2 | APPROVED used as a Case Status | **Removed**: APPROVED is NOT a valid Case Status. Case Status values: OPEN, IN_PROGRESS, REVIEW, CLOSED, ARCHIVED. Review Decision values: APPROVED, REJECTED, NEEDS_MORE_DATA. |
| 3 | Permissions were not granular | **Split**: VIEW / CREATE / EDIT / REVIEW are four distinct permission checks per screen. RBAC role mapping updated accordingly. |
| 4 | Hypothesis ↔ Case was implicit one-to-many | **Many-to-Many**: New `case_hypotheses` link table. A hypothesis can be linked to multiple cases; a case can link to multiple hypotheses. |
| 5 | Per-client hypothesis review results missing | **Added**: Each client linked to a hypothesis gets its own review result (client-specific verification). |
| 6 | Cross-client authorization not explicit | **Added**: Every screen shows client isolation badges; every API call enforces user→client grant; cross-client access returns generic "access denied" (no enumeration). |

---

## 2. Permission Model (VIEW / CREATE / EDIT / REVIEW)

| Permission | Role: READ_ONLY | Role: CTI_ANALYST | Role: HYPOTHESIS_WRITER | Role: REPORT_GENERATOR | Role: ADMINISTRATOR |
|------------|-----------------|-------------------|-------------------------|------------------------|---------------------|
| Case VIEW | ✅ | ✅ | ✅ | ✅ | ✅ |
| Case CREATE | ❌ | ✅ | ❌ | ❌ | ✅ |
| Case EDIT | ❌ | ✅ (owner/participant) | ❌ | ❌ | ✅ |
| Case REVIEW | ❌ | ❌ | ❌ | ❌ | ✅ |
| Artifact VIEW | ✅ | ✅ | ✅ | ✅ | ✅ |
| Artifact CREATE | ❌ | ✅ | ❌ | ❌ | ✅ |
| Artifact EDIT | ❌ | ✅ (owner) | ❌ | ❌ | ✅ |
| Artifact REVIEW | ❌ | ❌ | ❌ | ❌ | ✅ |
| Hypothesis VIEW | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hypothesis CREATE | ❌ | ❌ | ✅ | ❌ | ✅ |
| Hypothesis EDIT | ❌ | ❌ | ✅ (owner) | ❌ | ✅ |
| Hypothesis REVIEW | ❌ | ❌ | ❌ | ❌ | ✅ |
| Note CREATE | ❌ | ✅ | ✅ | ✅ | ✅ |
| Note EDIT | ❌ | ✅ (own) | ✅ (own) | ✅ (own) | ✅ |

**Client isolation**: Every operation also requires `CanAccessClient(userID, clientID)` — ADMINISTRATOR does NOT bypass explicit client grant.

---

## 3. Case Lifecycle vs Review Decision (Separated)

### Case Lifecycle Status (5 values)
| Status | Meaning | Who can transition |
|--------|---------|-------------------|
| `OPEN` | Case created, not yet worked | CTI_ANALYST, ADMINISTRATOR → IN_PROGRESS or CLOSED |
| `IN_PROGRESS` | Analyst actively investigating | CTI_ANALYST, ADMINISTRATOR → REVIEW or CLOSED |
| `REVIEW` | Submitted for human review | ADMINISTRATOR → CLOSED or ARCHIVED |
| `CLOSED` | Case resolved | ADMINISTRATOR → ARCHIVED |
| `ARCHIVED` | Case archived, read-only | — (terminal) |

### Human Review Decision (3 values, applied to Artifacts)
| Decision | Meaning | Who can set |
|----------|---------|-------------|
| `APPROVED` | Artifact verified as accurate | ADMINISTRATOR (REVIEW permission) |
| `REJECTED` | Artifact inaccurate, needs rework | ADMINISTRATOR (REVIEW permission) |
| `NEEDS_MORE_DATA` | Insufficient evidence | ADMINISTRATOR (REVIEW permission) |

**Rule**: APPROVED is NEVER a Case Status. It is only a Review Decision on artifacts/hypotheses.

---

## 4. UI → API Dependency Matrix (v1.1)

| UI Feature | Endpoint | Method | Auth | Exists? |
|------------|----------|--------|------|---------|
| Case List | `GET /api/v1/cases` | GET | VIEW + client grant | ❌ MISSING |
| Create Case | `POST /api/v1/cases` | POST | CREATE | ❌ MISSING |
| Case Detail | `GET /api/v1/cases/{case_id}` | GET | VIEW + client grant | ✅ EXISTS |
| Case Status Transition | `PUT /api/v1/cases/{case_id}/status` | PUT | EDIT + case access | ❌ MISSING |
| Add Participant | `POST /api/v1/cases/{case_id}/participants` | POST | EDIT + case owner | ❌ MISSING |
| List Participants | `GET /api/v1/cases/{case_id}/participants` | GET | VIEW + case access | ❌ MISSING |
| Remove Participant | `DELETE /api/v1/cases/{case_id}/participants/{user_id}` | DELETE | EDIT + case owner | ❌ MISSING |
| Artifact Review | `PUT /api/v1/cases/{case_id}/artifacts/{id}/review` | PUT | REVIEW | ❌ MISSING |
| Add Note | `POST /api/v1/cases/{case_id}/notes` | POST | CREATE | ❌ MISSING |
| List Notes | `GET /api/v1/cases/{case_id}/notes` | GET | VIEW | ❌ MISSING |
| List Activity | `GET /api/v1/cases/{case_id}/activity` | GET | VIEW | ❌ MISSING |
| Link Hypothesis (M2M) | `POST /api/v1/cases/{case_id}/hypotheses/{id}` | POST | EDIT + case access | ❌ MISSING |
| Unlink Hypothesis | `DELETE /api/v1/cases/{case_id}/hypotheses/{id}` | DELETE | EDIT + case access | ❌ MISSING |
| Create Investigation | `POST /api/v1/cases/{case_id}/investigations` | POST | CREATE | ❌ MISSING |
| List Clients | `GET /api/v1/clients` | GET | VIEW | ✅ EXISTS |

**Critical gaps**: Case List, Create Case, and all mutation endpoints are missing. These must be implemented before M6 frontend can function.

---

## 5. Questions Requiring Approval Before M6 Implementation

1. **Hypothesis ↔ Case relationship**: Use many-to-many link table (`case_hypotheses`) vs nullable `case_id` on `hunt_hypotheses`? Recommendation: M2M link table.
2. **Case Status transitions**: Should REVIEW→CLOSED require ADMINISTRATOR only, or can CTI_ANALYST with REVIEW permission close?
3. **Artifact Review visibility**: Should REJECTED artifacts be hidden from non-admin users, or shown with DATA_TYPE_DENIED styling?
4. **Note editing**: Can analysts edit their own notes after 5 minutes? Or is edit window indefinite?
5. **Case deletion**: Is there a soft-delete/archive flow, or is ARCHIVED terminal with no restore?
6. **API pagination**: Should Case List use offset/limit pagination or cursor-based?
7. **Cross-client case visibility**: Can an ADMINISTRATOR see all cases across all clients, or only cases for clients they are explicitly granted?

---

## 6. Component Inventory (v1.1)

| Component | Purpose | Permission Gate |
|-----------|---------|-----------------|
| `CaseStatusBadge` | Shows OPEN/IN_PROGRESS/REVIEW/CLOSED/ARCHIVED | VIEW |
| `ReviewDecisionBadge` | Shows APPROVED/REJECTED/NEEDS_MORE_DATA | VIEW |
| `PermissionChip` | Shows VIEW/CREATE/EDIT/REVIEW for current user | VIEW |
| `ClientChip` | Shows client ID with client-specific color | VIEW |
| `EvidenceCard` | Artifact with provenance, confidence, review status | VIEW / REVIEW |
| `IOCCard` | Indicator of compromise card | VIEW |
| `HypothesisCard` | Hunt hypothesis with client-specific review results | VIEW / CREATE / EDIT |
| `ClientRelevanceCard` | Client sector, affected assets, relevance score | VIEW |
| `ReviewPanel` | Approve/Reject/Needs More Data + reason | REVIEW |
| `ProvenanceIndicator` | Source, checksum, link to origin | VIEW |
| `ActivityTimeline` | Chronological activity feed | VIEW |
| `EmptyState` / `LoadingState` / `ErrorState` / `AccessDeniedState` | Standard states | — |

---

## 7. Files Created

| File | Description |
|------|-------------|
| `frontend/prototypes/m6-spec-v11.md` | This specification document |
| `frontend/prototypes/analyst-overview.html` | Analyst Overview prototype |
| `frontend/prototypes/research-cases-list.html` | Research Cases List prototype |
| `frontend/prototypes/research-case-detail.html` | Research Case Detail Workspace prototype |

**No existing project files were modified.** These are isolated prototypes for visual approval only.