# AI Workflow Specification — MSSP Intelligence Workbench

## Objective

Prefer Skills/Workflow Stages with clear inputs and outputs over many independent agents. Per TECHNICAL_SPECIFICATION.md Section 15.

## Workflow Stages (Skills)

### 1. Chief CTI Coordinator
- Accept analytical tasks
- Break into stages
- Select necessary Skills
- Determine suitable harness
- Control execution
- Combine results
- Launch Quality Gate

### 2. CTI Collector
- Receive CTI materials
- Normalize
- Deduplicate
- Save provenance

### 3. CTI Analyst
- Analyze reports
- Identify threat actors
- Extract IOC, TTP, CVE
- Analyze campaigns
- Form analytical conclusion

### 4. Admiralty Reviewer
- Preliminary source assessment
- Information credibility assessment
- Find confirmations
- Find contradictions

### 5. Adversary Brain Builder
- Build structured behavior model
- Link TTP, IOC, malware, campaigns
- Save evidence
- Version the model

### 6. ACH Analyst
- Create competing hypotheses
- Match evidence
- Find contradictions
- Formulate uncertainties

### 7. Sector Relevance Analyst
- Determine target sectors
- Map to MSSP clients
- Explain relevance
- Indicate missing information

### 8. Detection Context Analyst
- Work with Global QRadar Inventory
- Analyze rules and fields
- Check log sources
- Identify detection gaps

### 9. Hunt Hypothesis Generator
- Form testable hypotheses
- Determine required data
- Generate AQL drafts
- Prepare analyst recommendations

### 10. Quality Gate
- Check structure
- Check evidence
- Check sources
- Check client isolation
- Check facts vs conclusions
- Form warnings

## Execution Modes

- **Harness-managed** (MVP): One confirmed harness coordinates subagents. Workbench receives status, results, telemetry.
- **Workbench-managed** (future): Workbench splits task into stages, routes between harnesses.

## Task Contract (internal)

Input:
```json
{
  "task_id": "task-001",
  "task_type": "CTI_ANALYSIS",
  "client_id": "client-001",
  "priority": "normal",
  "input": {},
  "expected_output": ["summary", "iocs", "ttps", "sources"],
  "human_review_required": true
}
```

Output:
```json
{
  "task_id": "task-001",
  "agent_id": "agent-001",
  "status": "completed",
  "result": {},
  "sources": [],
  "warnings": [],
  "errors": [],
  "execution_id": "execution-001"
}
```

## Task Routing Modes

- AUTO — Workbench selects suitable available harness
- MANUAL — analyst selects harness
- USER_PREFERRED — user's stored preference
- WORKFLOW_DEFINED — harness from process configuration

## Constraints

- No multiple independent agents without need
- Skills have clear inputs and outputs
- Human-in-the-loop for all write/trust decisions
- AI cannot assert final attribution
- No auto-training of LLM on all data
- Controlled feedback loop in MVP