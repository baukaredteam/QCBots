# Adversary Brain Specification — MSSP Intelligence Workbench

## Objective

Implement a structured model of threat actor or campaign behavior. Per TECHNICAL_SPECIFICATION.md Section 7: analyze not only individual IOCs but interconnected behavioral indicators. Never claim activity belongs to a threat actor based on a single IOC match.

## Data Structure

Tables (per spec Section 7.2):

- **adversary_brains** — brain records (actor, campaign, version, status)
- **brain_versions** — version history with change summary and approver
- **brain_sources** — provenance for each data source
- **brain_hypotheses** — competing hypotheses within the brain
- **brain_observables** — IOCs, TTPs, infrastructure observables
- **brain_relationships** — logical connections between entities
- **brain_evidence** — supporting and contradicting evidence
- **brain_assessments** — analyst assessments with confidence

Each record supports provenance (source reference, collection date, reliability).

## Relationship Types

```text
USES, TARGETS, ASSOCIATED_WITH, EXPLOITS, COMMUNICATES_WITH,
OBSERVED_IN, RELATED_TO
```

No relationship is considered proven without a corresponding source.

## Logical Signature Structure

```
Threat Actor
    |
Campaign
    |
    +-- TTP A
    |
    +-- TTP B
    |
    +-- Malware
    |
    +-- Infrastructure
    |
    +-- Target Sector
```

## Analysis of Competing Hypotheses (ACH)

Per spec Section 7.4: compare multiple explanations for observed activity.

Example hypotheses:
- H1: Activity linked to known APT campaign
- H2: Activity linked to legitimate administrative operation
- H3: Independent malicious activity without established attribution

For each hypothesis store:
- Supporting Evidence
- Contradicting Evidence
- Missing Evidence
- Source Reliability (Admiralty A-F)
- Information Credibility (Admiralty 1-6)
- Analyst Assessment
- Current Status

AI may suggest assessment but cannot assert final attribution.

## Admiralty System (Section 8)

**Source Reliability**: A (Completely reliable) to F (Cannot be judged)
**Information Credibility**: 1 (Confirmed) to 6 (Cannot be judged)

Stored per source + claim:
- source_id, claim_id, reliability_rating, credibility_rating,
  assessment_reason, assessed_by, assessment_date

AI may propose preliminary assessment; analyst confirms.

## Versioning

Each Adversary Brain supports version history:
- version_number, change_summary, approved_by, approved_at
- Analyst can review and approve changes
- No automatic trusted knowledge modification without approval

## UI Display (Section 18.4)

Adversary Brains page shows:
- Threat Actor, Associated Campaigns, Behavioral Signatures, TTP, IOC,
  Malware, Infrastructure, Evidence, Confidence, Version History, Last Updated
- Graphical relationship display (only real stored relationships)

## Constraints

- Cannot auto-assert threat actor from single IOC
- AI cannot assert final attribution
- Every claim needs provenance
- Human approval for trusted knowledge changes
- Read-only QRadar in MVP