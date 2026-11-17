# Specification Recovery Report — MSSP Intelligence Workbench

**Review type:** Read-only specification recovery investigation  
**Status:** Pre-Phase 1 gate — specification recovery  
**Restrictions honored:** No Git, no external services, no production access, no credential changes, no code modifications, no container restarts

---

## 1. Locations Searched

The following authorized local project locations were searched for `TECHNICAL_SPECIFICATION.md`, previous versions, backups, or original requirement documents:

| Location | Search Method | Result |
|----------|--------------|--------|
| Project root (`C:\Users\Бауыржан\Desktop\QC_Bots\`) | Glob `**/*SPECIFICATION*` | No match |
| Project root | Glob `**/*spec*` | No match |
| Project root | Glob `**/*backup*` | No match |
| Project root | Glob `**/*.bak` | No match |
| Project root | Glob `**/*` (all files) | No TECHNICAL_SPECIFICATION.md found |
| `/docs/` directory | Glob `**/*.md` | 18 markdown files, none is TECHNICAL_SPECIFICATION.md |
| `/config/` directory | Directory listing | 8 YAML config files, no specification |
| `/migrations/` directory | Directory listing | 1 SQL migration file, no specification |
| `/backend/` directory | Directory listing | go.mod and main.go only, no specification |
| `/frontend/` directory | Directory listing | package.json only, no specification |
| `/.agents/` directory | Directory listing | Agent configurations only, no specification |

**Finding:** No file named `TECHNICAL_SPECIFICATION.md` exists anywhere in the project directory tree. No backup files, versioned copies, or alternative specification documents were found.

---

## 2. Candidate Documents Found

One candidate source for the specification content was identified outside the project file tree:

### Candidate: Conversation Context (pasted-context-2.txt)

**Location:** Provided as conversation context at the start of the session (not a file in the project directory tree)

**Title:** `# MSSP INTELLIGENCE WORKBENCH / Финальное техническое задание (Technical Specification)`

**Version/Date:** Version 1.0, Status: "Final Specification / Implementation Baseline"

**Content:** Contains all 29 sections of the technical specification:
1. PROJECT OVERVIEW
2. ARCHITECTURAL PRINCIPLES
3. HIGH-LEVEL ARCHITECTURE
4. MAIN SYSTEM COMPONENTS
5. MULTI-HARNESS ARCHITECTURE
6. CTI INGESTION ENGINE
7. ADVERSARY BRAIN ENGINE
8. ADMIRALTY SYSTEM
9. SECTOR RELEVANCE ENGINE
10. MSSP TENANT MANAGEMENT
11. QRADAR DATA INVENTORY
12. DETECTION COVERAGE ENGINE
13. HUNT HYPOTHESIS ENGINE
14. FEEDBACK LOOP AND CONTROLLED LEARNING
15. AI SKILLS AND WORKFLOWS
16. ACTIF AND DETECTION ENGINEERING METHODOLOGY
17. KNOWLEDGE MANAGEMENT AND RAG
18. USER INTERFACE SPECIFICATION
19. AGENT SECURITY CONTROL PLANE
20. DATABASE SCHEMA
21. API SPECIFICATION
22. OBSERVABILITY AND MONITORING
23. MVP SCOPE
24. OUT OF SCOPE FOR MVP
25. ACCEPTANCE CRITERIA
26. TESTING STRATEGY
27. IMPLEMENTATION INSTRUCTIONS FOR OPENCODE
28. FINAL ARCHITECTURAL DECISIONS
29. PROJECT SUCCESS CRITERIA

**Evidence:** This candidate contains the complete specification content referenced by AGENTS.md and all 15 supporting documents. Every document in `/docs/` cites specific sections of `TECHNICAL_SPECIFICATION.md` (e.g., "Section 5.3", "Section 10.4", "Section 19", "Section 23"), confirming this is the referenced source document.

**Important caveat:** This candidate was provided as conversation context, not as a file in the project directory tree. It does not exist as `TECHNICAL_SPECIFICATION.md` in the project. It has not been placed in the project and should not be treated as the recovered project file until explicitly approved and added by the user.

---

## 3. Evidence: Original Was / Was Not Recovered

### Was not recovered as a project file

`TECHNICAL_SPECIFICATION.md` does not exist as a file in the project directory. No backup, versioned copy, or alternative original specification document was found in any authorized project location.

### Content was found in conversation context

The complete specification content (29 sections, Version 1.0) was provided as conversation context at the start of this session (pasted-context-2.txt). This content matches all references in AGENTS.md and the 15 supporting documents.

**Conclusion:** The original specification content is available from conversation context but is not present as a project file. The project cannot treat it as authoritative until it is formally placed at `C:\Users\Бауыржан\Desktop\QC_Bots\TECHNICAL_SPECIFICATION.md` and approved.

---

## 4. Requirements Reconstructable from Existing Documents

The 15 supporting documents plus AGENTS.md collectively reconstruct the following specification requirements:

| Specification Section | Reconstructed In | Coverage |
|----------------------|------------------|----------|
| Section 1: Project Overview | AGENTS.md, PROJECT_ARCHITECTURE.md | Complete |
| Section 2: Architectural Principles | AGENTS.md, PROJECT_ARCHITECTURE.md | Complete |
| Section 3: High-Level Architecture | PROJECT_ARCHITECTURE.md | Complete |
| Section 4: Main System Components | PROJECT_ARCHITECTURE.md | Complete |
| Section 5: Multi-Harness Architecture | MULTI_HARNESS_SPEC.md | Complete |
| Section 6: CTI Ingestion Engine | AI_WORKFLOW_SPEC.md (partial) | Partial — no dedicated document |
| Section 7: Adversary Brain Engine | ADVERSARY_BRAIN_SPEC.md | Complete |
| Section 8: Admiralty System | ADVERSARY_BRAIN_SPEC.md | Complete |
| Section 9: Sector Relevance Engine | AI_WORKFLOW_SPEC.md (partial) | Partial — no dedicated document |
| Section 10: MSSP Tenant Management | SECURITY_REQUIREMENTS.md, DATABASE_SCHEMA.md | Complete |
| Section 11: QRadar Data Inventory | DATABASE_SCHEMA.md, config/yaml files | Complete |
| Section 12: Detection Coverage Engine | DATABASE_SCHEMA.md, config/yaml files | Complete |
| Section 13: Hunt Hypothesis Engine | AI_WORKFLOW_SPEC.md (partial) | Partial — no dedicated document |
| Section 14: Feedback Loop and Controlled Learning | DATABASE_SCHEMA.md | Complete |
| Section 15: AI Skills and Workflows | AI_WORKFLOW_SPEC.md | Complete |
| Section 16: ACTIF Methodology | Not covered | Missing |
| Section 17: Knowledge Management and RAG | DATABASE_SCHEMA.md (partial) | Partial |
| Section 18: User Interface Specification | UI_SPECIFICATION.md | Complete |
| Section 19: Agent Security Control Plane | SECURITY_REQUIREMENTS.md | Complete |
| Section 20: Database Schema | DATABASE_SCHEMA.md | Complete |
| Section 21: API Specification | API_SPECIFICATION.md | Complete |
| Section 22: Observability and Monitoring | DEPLOYMENT_GUIDE.md (partial) | Partial |
| Section 23: MVP Scope | IMPLEMENTATION_PLAN.md | Complete |
| Section 24: Out of Scope for MVP | IMPLEMENTATION_PLAN.md (implicit) | Partial |
| Section 25: Acceptance Criteria | Not covered as document | Missing |
| Section 26: Testing Strategy | TESTING_STRATEGY.md | Complete |
| Section 27: Implementation Instructions | IMPLEMENTATION_PLAN.md, AGENTS.md | Complete |
| Section 28: Final Architectural Decisions | PROJECT_ARCHITECTURE.md, AGENTS.md | Complete |
| Section 29: Project Success Criteria | Not covered as document | Missing |

**Reconstructable:** Sections 1-15, 17-24, 26-28 are substantially covered by existing documents.

**Not reconstructable from existing documents alone:** Sections 16 (ACTIF methodology details), 25 (Acceptance Criteria), 29 (Project Success Criteria) — these exist only in the conversation-context specification candidate.

---

## 5. Requirements That Remain Ambiguous

The following requirements from the specification candidate cannot be fully verified against existing project documents:

| Ambiguous Item | Source | Reason |
|---------------|--------|--------|
| Exact acceptance criteria thresholds | Section 25 | No dedicated Acceptance Criteria document exists in `/docs/` |
| ACTIF methodology stage details | Section 16 | No dedicated document covers ACTIF workflow stages in detail |
| Project success criteria metrics | Section 29 | No dedicated document defines measurable success criteria |
| QRadar field/rule real-world values | Section 11 | Config files contain placeholder data, not real QRadar export |
| ThreadLinqs MCP transport/auth specifics | Section 6 | Not verified; subject to security policy |
| Local LLM model selection | Section 4.3 | No provider selected; `model_providers.yaml` shows `status: not_configured` |
| HarnessRouter API interface | Section 5.2 | HarnessRouter not installed; interface not confirmed |
| Octop full API surface beyond health/auth/agents | Section 5 | Only health, auth/login, auth/me, agents, acp, providers endpoints verified; task submission not tested |

---

## 6. Decisions Requiring Explicit Human Approval

| # | Decision | Why Approval Needed |
|---|----------|---------------------|
| D1 | Accept conversation-context specification (pasted-context-2.txt) as the authoritative TECHNICAL_SPECIFICATION.md content | Content was provided as conversation context, not as a project file. Must be formally placed and approved before use as source of truth. |
| D2 | Place specification content at `TECHNICAL_SPECIFICATION.md` in project root | The file does not exist; creating it is a project-structure decision. |
| D3 | Resolve reconstructable vs. non-reconstructable gaps (Sections 16, 25, 29) | Missing sections need either extraction from specification candidate or new definition. |
| D4 | Verify placeholder config data against real QRadar export | `config/rules_inventory.yaml` and `config/custom_fields_qradar.yaml` contain placeholder values. |
| D5 | Approve ThreadLinqs MCP integration per security policy | Default network policy denies outbound; ThreadLinqs requires explicit approval. |
| D6 | Select local LLM provider and model | No provider selected; required before AI workflows can operate. |
| D7 | Confirm Octop as the sole verified harness for MVP | Only Octop has passed PoC (localhost only); production readiness not established. |

---

## 7. Authoritative Version Determination

**No authoritative version exists as a project file.**

The specification content from conversation context (pasted-context-2.txt, Version 1.0, "Final Specification / Implementation Baseline") is the only available source. It matches all cross-references in AGENTS.md and the 15 supporting documents. However:

- It is not present as `TECHNICAL_SPECIFICATION.md` in the project directory
- It has not been formally verified as a project file
- It has not been approved as the authoritative source

**Recommendation:** The user must approve placing the conversation-context specification content at `TECHNICAL_SPECIFICATION.md` in the project root before any implementation proceeds. Until then, all existing documents remain unverified against the source of truth.

---

## 8. Phase 1 Readiness Impact

Without `TECHNICAL_SPECIFICATION.md` as a project file:

- All agent configs cite unverifiable section references
- All 15 supporting documents cite unverifiable section references
- The migration schema (0001_initial.sql) claims alignment with Section 20 but cannot be verified
- No acceptance criteria can be validated against the source
- Phase 1 implementation cannot be spec-traceable (mandatory governance rule)

**Conclusion:** The project remains NOT READY FOR PHASE 1 until the specification is recovered as a project file and approved.

---

## 9. Files Created by This Investigation

- `docs/SPECIFICATION_RECOVERY_REPORT.md` — this document (read-only, no code changes)
- `docs/SECURITY_APPROVAL_CHECKLIST.md` — security decisions requiring approval (next document)

No application code, database schemas, migrations, credentials, or container configurations were modified during this investigation.