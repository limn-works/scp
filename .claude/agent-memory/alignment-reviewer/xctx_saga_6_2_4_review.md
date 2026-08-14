---
name: xctx-saga-6-2-4-review
description: §6.2.4 cross-context tool-invocation saga spec-conformance reviews (in-core; FFI surface not yet). Round-2 at HEAD 73010c2a9 — prior HIGH closed; 2 residual.
metadata:
  type: project
---

# §6.2.4 Cross-Context Tool Invocation Saga — Spec-Conformance Review

## Round 2 (2026-06-18) — HEAD 73010c2a9 on branch feat/actor-2c-6.2.4-xctx-saga
34 files +9452/-279 (vs +7319 at round-1 3e2038d84). Wave-1/2/3 fix commits landed since round-1.
In-core saga only (slices 1-6 + supervisor FSM); FFI saga surface still NOT wired (BroadcastHostingHandshake + StandingPairCreate remain `NotImplemented`, correctly later-phase).

**Prior round-1 HIGH is CLOSED.** §17.16.4 Commit-in-progress recovery now re-drives BOTH sides:
`recover_committing_entry` → `redrive_xctx_commit_in_progress` (CommitBReserve → `AlreadyCommitted` re-emits stored output, never re-invoke) → `redrive_commit_a_witness` (CommitACheckWitness reads durable `xctx_committed_invocations`). New `CommitInProgressResolution::{Committed,NeedsRepair}`: resolves `Committed` when BOTH committed (no false NeedsRepair), `NeedsRepair` only on genuine one-sided / unreachable. `commit_a_check_witness` actor handler is the read-only A-side witness. Well-tested (xctx_commit_in_progress_with_witness_resolves_committed; absent-witness contrast).

**Prior round-1 MED CLOSED.** §6.2.0.2 per-interface + per-caller sliding-window enforced in `consume_outbound_interface_rate_limit` (both windows, invoke_cross_context order). `allowed_source_roles` enforced in `validate_inbound_policy` against supervisor-resolved channel-authenticated `caller_source_role` (member_role, NOT envelope). Both authorize-before-reserve gates present (caller-axis is_member + target-axis has_established_tool_interface) before try_reserve_context_set.

**Prior round-1 LOW CLOSED.** `declared_cost` dead plumbing gone — escrow uses REGISTERED cost via reserve_tool_economy/economy_pre_check; only a comment mentions it at supervisor.rs:9236.

### RESIDUAL FINDINGS (round 2)
- **MED — §6.2.4 "NeedsRepair ⇒ both sides MUST emit a signed CrossContextDivergenceMarker" NOT honored on the CRASH-RECOVERY path.** `recover_committing_entry` NeedsRepair arm (supervisor.rs ~5293-5311) only appends a NeedsRepair journal entry — no `emit_divergence_markers`, no `record_supervisor_repair`. The live FSM path DOES emit markers (run_saga_fsm 5650-5672 → divergence_marker_plan/emit_divergence_markers, correctly None-guarded for no-committed-side). But on recovery the redrive can DETECT a true one-sided commit (B `AlreadyCommitted` + A witness `false` → genuine Target-committed divergence) yet emits NO durable marker. ROOT CAUSE: signing keys are caller-supplied per-call (ADR-049 actor holds no key) and die with the crash; reconstruct_xctx_prepared yields context ids + provenance but NO keys, so the supervisor cannot drive EmitDivergenceMarker on recovery. The spec-honest fallback is the supervisor-level `saga_repair_records` (the "or a supervisor-level repair journal if one side is unreachable" clause — here the side is reachable but UN-SIGNABLE, the same effect). Recommend: in the recovery one-sided case call `record_supervisor_repair` (committed_side=Target, the re-emitted ToolInvoked event id, nonce) so the divergence is durably auditable post-crash, matching the live path's guarantee.
- **LOW — §17.16.4 line 968 names a METRIC ("surface via a metric (e.g., `saga_repair_needed`)") as the NeedsRepair surfacing mechanism; implementation uses only `tracing::error!`.** No saga-repair metric exists in crates/scp-runtime/src/metrics.rs (7 record_/set_ fns, none saga). Both the live NeedsRepair tail (run_saga_fsm) and the recovery NeedsRepair arms surface via tracing only. A metrics facility EXISTS (crate::metrics::record_persistence_failure etc.). Recommend a `record_saga_repair_needed()` counter incremented at every NeedsRepair journal append so operators can alert (the spec explicitly calls for a metric, not a log line).

### VERIFIED SPEC-FAITHFUL (round 2, unchanged-good)
Receipt/marker signed types byte-exact (SCP-XCTX-RECEIPT-V1: / -DIVERGENCE-V1:, §9.5.1 canonical_hash field order, output_jcs carried so verifier recomputes output_hash with no re-canonicalize, splice-resistance tests, wrong-signer→fail). Signer authorization: verify_commit_b_receipt checks against ctx.target_signing_key BEFORE settle (13041). Confused-deputy rebind (validate_ucan_rebind to caller_did+tool, AudienceMismatch). Target-context binding (13014). Freshness/nonce-dedup on B (xctx_nonce_dedup, Class-S persisted). Chain-depth B-re-derived incoming+1 (never asserted). Staged recorded_{nonce,chain_depth,timestamp_ms} for replay determinism. Exactly-once durable output capture keyed by SagaId (commit_b_first_settle / reemit_committed_settle). Dual event-log (ToolInvoked + CrossContextToolInvoked share nonce). NeedsRepair reservation semantics: concurrency slot released (_reservation drop) + escrow HELD (hold_external_for_repair, reached_needs_repair). RAII release on every terminal (abort + drain tail). Co-resident scoping (lookup caller+target; ContextNotRegistered 13052). New CI gate check-class-s-fail-closed.sh self-tested + additive (saga_pending.insert/remove + xctx_nonce_dedup.record markers). clippy clean expected.

### LESSONS
- For a saga that has BOTH a live-NeedsRepair path AND a crash-recovery NeedsRepair path: the divergence-marker / audit obligation must be checked on BOTH. The live path may emit signed markers while the recovery path (which has no per-call signing keys after a crash) silently drops the obligation — the spec-honest substitute is the supervisor-level repair record, not nothing.
- When the spec names a specific surfacing MECHANISM (here a metric `saga_repair_needed`), a `tracing::error!` is not a substitute even if it conveys the same info — grep the metrics module to confirm the named counter exists.
