# V3-F3 Cases Workspace — Notes

Case detail shows Overview (owner, timestamps, linked hypotheses, evidence summary, recent activity), Hypotheses, Evidence, Investigations, Notes and Timeline tabs.
CTI Context explains the backend gap (no Case↔CTI junction) and never invents reports.
Lifecycle, participants, artifact review, hypothesis review and investigation creation are executed through contextual drawers (not inline forms).
Client context switch clears selected hypothesis/artifact/investigation and Inspector (stale content is discarded) — no cross-client leakage via DOM.
All fetches are grant-filtered server-side; GLOBAL context = metadata only.
