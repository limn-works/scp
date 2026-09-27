# Architect Memory

- [blockedBy means "cannot start"](decision_blockedby_cannot_start_not_cannot_finish.md) — express "cannot finish without" through the description and a downstream story's `blockedBy`; inverting an edge makes a cycle.
- [An issue number is not provenance](finding_phantom_provenance_issue_number_is_the_prd.md) — a comment citing "#NNNN owns this" counts only when a story in that artifact covers the named capability; grep the artifact for the capability.
- [Readiness gate vs observability accessor](decision_readiness_gate_vs_observability_accessor.md) — for a late-bound resource, schedule unconditionally, fail closed, and back off; delete the gate but keep a read-only count accessor.
- [A story rewritten mid-branch goes stale](finding_prd_code_desync_after_story_rewrite.md) — re-run every acceptance-criterion grep against HEAD before editing or marking a story done; quote zsh `git show "${M}:path"`.
