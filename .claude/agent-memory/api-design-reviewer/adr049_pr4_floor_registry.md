---
name: adr049-pr4-floor-registry
description: API review of ADR-049 PR-4 (#2109/#2075 series, HEAD 26a5820dd) supervisor-owned Class-M floor registry — forward-parity judgment call, (u64,u64) transposition finding, OpenedEnvelope field
metadata:
  type: project
---

ADR-049 PR-4 "Supervisor-owned floor registry (epoch side), non-authoritative follower." Files: crates/scp-runtime/src/context/supervisor/floors.rs (new, ContextFloors + FloorAdvanceError + check_and_advance_* + validate_and_merge_* + seed_context_floors), handle.rs (+7 pub(in crate::context) accessors, all take &[u8;32]), scp-protocol builder.rs (OpenedEnvelope gains receive_floor: (u64,u64)).

Registry is write-only-until-PR-6 (follower). PR-6 = atomic read-authority switch + provider floor-map delete. PR-7 = key move (take_crypto_state, 0 prod callers today).

**Judgment call (endorsed KEEP):** validate_and_merge_* keep unused max_advance/trusted_local + a never-Err Result, silenced with #[allow(clippy::unnecessary_wraps, unused_variables)], for signature parity with the provider twin so PR-6 retarget is churn-free. Right call under this repo's "no deferral / no DOA / agent-first identical-shape" tenets AND because PR-6 is specced+imminent (not speculative YAGNI). CAVEAT that weakens "churn-free": parity is only PARTIAL — provider twins return Result<(),ContextError>, registry returns Result<(),FloorAdvanceError>; param names differ (local_floors/max_advance_per_sender vs incoming/max_advance). So PR-6 must still reconcile error types at every retargeted call site. Recommend either unify error type now or doc the error-type seam as the residual.

**Strongest API finding (MODERATE):** the new surface reintroduces bare (u64,u64) = (epoch,sequence) as receive_floor field, `next` param, and Vec<(String,(u64,u64))> returns — a positional transposition hazard. This runs against the direction PR #127 set when InnerEnvelopeParams was introduced specifically to kill u64 transposition risk. A ReceiveFloor{epoch,sequence} newtype would be self-documenting + misuse-resistant. Tension: mirrors provider's existing (u64,u64) shape (consistency vs safety).

**Other:** handle.rs header comment says "These six accessors" but 7 fns added (seed_context_floors uncounted). OpenedEnvelope.receive_floor is documented follower-only ("NOTHING reads for enforcement") but that's a comment, not a type guarantee (CLAUDE.md: enforce mechanically). Field only consumed on OpenResult::Application arm at messaging_helpers.rs:2925, non-fatal Err (log+drop) — correct follower semantics. Verdict: APPROVED with minor revisions (none blocking).
