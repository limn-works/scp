---
name: saga-participant-unavailable-13068
description: SagaAbortReason::ParticipantUnavailable (SCP-SAGA-13068) taxonomy review — fieldless retryable Prepare-phase abort; FFI retryability is code-string-only
metadata:
  type: project
---

`SagaAbortReason::ParticipantUnavailable` (code `SCP-SAGA-13068`) added on branch `fix/121-mailbox-saturated-saga-terminal`. Classifies transient Prepare-phase `ContextError::ActorBusy` (inbox closed/terminated, dropped reply channel, mailbox-full timeout) as retryable, vs the permanent `Rejected` (13067).

Review verdict: APPROVED. Taxonomy decisions all correct and permanent (no-DOA):
- Name abstracts over all ActorBusy producers; uses protocol noun "participant" not impl term "actor".
- Extends `SagaAbortReason` axis (not new terminal, not `Busy` — `contended_context` wouldn't apply).
- Fieldless is honest: no drain instant exists (unlike RateLimited's `Option<u64>`); always-None field would be noise.

**Why (the one real finding):** `decompose_saga_error` folds `ParticipantUnavailable | Rejected => Aborted{retry_after_ms:None}`. So the FFI/SDK surface (`SagaErrorKind::Aborted{retry_after_ms}`) exposes the retryable-vs-permanent distinction ONLY via the `SCP-SAGA-*` code STRING, not structurally. Named misuse: the obvious heuristic "retry iff retry_after_ms present" (natural read of the type) silently drops this retryable terminal. Consistent with pre-existing saga-terminal code-as-discriminant contract (13067-timeout vs 13050-membership already conflate transient/permanent under None), so not a NEW trap — but the agent-first ideal is a structural `retryable: bool` / distinct subclass. Flag as MAJOR observation, non-blocking. Follow-up #1967 is FILED targeting a structural retryable discriminant — accept now as tracked. WHEN #1967 LANDS: the 6 SDK docstrings that now say "distinguished by the SCP-SAGA-* code" must be revised to point at the structural discriminant, else they pin the code-string contract.

**How to apply:** When reviewing future saga-terminal taxonomy additions, check whether a new retryability/transience signal is surfaced STRUCTURALLY at the FFI `SagaErrorKind` boundary or only via the code string. The latter is the recurring weak point. SDK `SagaAbortedError` carries both `.code` and `.retry_after_ms`. See [[eventlog_substrate_phase2_final]] for the related saga/EventType taxonomy work.
