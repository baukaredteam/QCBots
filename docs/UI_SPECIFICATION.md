# UI Specification — MSSP Intelligence Workbench

## Main Menu

Dashboard, CTI Feed, Threat Intelligence, Adversary Brains, Sector Relevance,
Hunt Hypotheses, Detection Coverage, QRadar Inventory, Investigations,
Agent Registry, Execution History, Reports, Administration.

## Dashboard

Cards: New CTI Reports, Analyzed Reports, High Relevance Threats, Threats by
Sector, Active Adversary Brains, Pending Hunt Hypotheses, Approved Hypotheses,
Detection Gaps, Active Investigations, Harness Health Status.

Each card opens the corresponding section with filters. No fabricated metrics
when no data.

## CTI Feed

Columns: Report Title, Source, Publication Date, Collection Date, Threat Actor,
Sector, Severity/Priority, Analysis Status.

Actions: Import Report, Refresh Feed, Analyze, View Original Source, View
Extracted IOCs, View TTPs, View Evidence.

## Threat Intelligence

Displays: Threat Actors, Campaigns, Malware, Tools, CVEs, IOCs, MITRE Techniques,
Source Assessments. Search and filter.

## Adversary Brains

Displays: Threat Actor, Associated Campaigns, Behavioral Signatures, TTP, IOC,
Malware, Infrastructure, Evidence, Confidence, Version History, Last Updated.
Graphical relationship display (only real stored relationships).

## Sector Relevance

Displays: Threat, Target Sector, Matching MSSP Clients, Relevance Level,
Matching Technologies, Relevant TTPs, Relevant CVEs, Missing Information.

## Hunt Hypotheses

Displays: Hypothesis Title, Threat Actor, Client, Sector, MITRE Technique,
Priority, Confidence, Required Log Sources, Required Fields, Detection Coverage,
Evidence, Status.

Buttons: View Details, Approve, Reject, Request More Data, Start Investigation,
Generate AQL Draft, Export Report.

Approve/Reject save analyst identity and reason.

## Detection Coverage

Matrix: MITRE Technique, Required Telemetry, Required Fields, Existing Rules,
Client Availability, Coverage Status, Evidence.

Filters: Client, Sector, MITRE Tactic, MITRE Technique, Coverage Status.

## QRadar Inventory

Tabs: Global Fields, Detection Rules, Rule-Field Mapping, MITRE Mapping,
Log Source Types, Client Telemetry.

Excel/CSV import with column mapping, duplicate checking, error display,
confirmation, and cancel-before-commit. Change log.

## Agent Registry

Displays: Agent Name, Harness, Status, Version, Capabilities, Permissions,
Allowed Clients, Last Seen.

Buttons: Add Agent, Edit, Enable, Disable, Health Check, View Executions.

## Execution History

Displays: Task ID, Harness, Agent, Task Type, Client, Start Time, Duration,
Status, Result, Error, Retry Count.

View execution events and available traces.

## Reports

Generate: CTI Report, Threat Relevance Report, Adversary Brain Report,
Hunt Hypothesis Report, Detection Coverage Report, Investigation Report,
Management Summary.

Export: PDF, JSON, CSV, Markdown.

## UI Principles

- Understandable by SOC Analyst without direct API work
- No fake/mock data in production
- No fabricated metrics
- All client data isolated server-side
- Error handling and loading states