---
name: review-xctx-saga-6-2-4
description: Security review of §6.2.4 cross-context tool invocation saga (branch feat/actor-2c-6.2.4-xctx-saga, HEAD 2b1894e28) — auth/escrow/replay surface
metadata:
  type: project
---

# §6.2.4 Cross-Context Tool Invocation Saga — security review (2026-06-19)

Branch `feat/actor-2c-6.2.4-xctx-saga`, HEAD 2b1894e28. ~10.4k LOC diff. Reviewed auth/escrow/replay/freshness/inbound-policy surface. Spec `.docs/specs/06-cross-context-communication.md` §6.2.4.

**Why:** orchestrator asked for the SECURITY/authorization review pass on this saga PR.
**How to apply:** if re-reviewing this branch, the two open findings below are the live items; everything else confirmed sound.

## Verdict: STRONG. Two MEDIUM findings, no CRITICAL/HIGH.

### MEDIUM-1 (test fidelity): nonce-dedup TTL is 600s in prod but 300s in test fixtures
- Prod spawn (`lifecycle_helpers.rs` ~1269, ~1850) + restore (~2295) build `xctx_nonce_dedup` with `NonceDedup::with_ttl(SAGA_NONCE_DEDUP_TTL_SECS)` / `from_entries_with_ttl(...)` = 600s (2× DEFAULT_CLOCK_SKEW_TOLERANCE_SECS=300). Correct — BLACK-XCTX-01 coterminous-window invariant holds in PROD.
- BUT `PerContextState::new()` (state.rs:1256, test-only, 0 non-test callers) AND `new_for_test_with_mode` (used by saga.rs `target_state` test helper) build with `NonceDedup::new()` = 300s = EQUAL to the freshness skew. So handler tests run the coterminous window the spec forbids; no test exercises prod 600s object through prepare_b. `nonce_dedup_replay_bound_holds` only asserts the CONSTANT relationship, not the runtime object's TTL. Regression in prod spawn back to `new()` would not be caught. Fix: seed saga TTL in `new_for_test_*` or assert TTL at spawn sites.

### MEDIUM-2 (durability): supervisor-level divergence repair journal is in-memory only
- `saga_repair_records: DashMap` (supervisor.rs:783) — fallback witness for the UNREACHABLE side of a NeedsRepair divergence (spec: "supervisor-level repair journal if one side is unreachable"). Field doc: "In-memory only (lost on restart)". If supervisor crashes before operator reads it, the unreachable-side divergence record is lost.
- Mitigation: the COMMITTED side (target, reachable since Commit-B landed) DOES get a durable signed `CrossContextDivergenceMarker` in its own event log (committed_side=Target + nonce + event id), and escrow stays HELD (not auto-voided), so operator can still reconcile. So it's reduced-auditability / defense-in-depth, NOT a repudiation hole. Still weakens "durably auditable" for the unreachable leg.

## Confirmed SOUND (explicit):
- Authorize-before-reserve BOTH axes BEFORE try_reserve_context_set: gate1 `is_member(caller_ctx, caller_did)`, gate2 `has_established_tool_interface` (requires approved_by_source AND approved_by_target — unaccepted offer can't be ridden). supervisor.rs:4894/4911.
- caller_source_role resolved supervisor-side via `member_role(caller_hex,...)` (role in SOURCE ctx — matches InboundPolicy.allowed_source_roles semantics "roles in source context"), carried to Prepare-B, ACTIVELY enforced (stronger than single-ctx advisory path). saga.rs:796.
- Caller auth channel-authenticated, target-context-binding (`req.target_context_id != state.context_id` → reject). saga.rs:682.
- Escrow lifecycle: ToolEconomyTicket `#[must_use]` + Drop debug-assert; EVERY terminal balances: send-fail recovers reservation to ctx (`send_recover_on_failure` + extract_*), delivered-err leaves actor owning, actor-gone voids external+consume, NeedsRepair `hold_external_for_repair` (NOT voided — partial-commit), success consumes. Generation-checked rollback (`rollback_tool_economy_generation_checked`) on Commit-A replay + in-actor abort (mismatch → void external only, no confused-deputy local write). supervisor.rs:5036, saga.rs:1368/1480, tools_helpers.rs.
- Exactly-once: executor stashed before settle, replay re-emits stored receipt/output (`xctx_committed_outputs`), SagaId-stable event id, capture+persist BEFORE event-log append (ordering avoids double-append). Verify-before-settle: B receipt verified against target_signing_key BEFORE Commit-A (supervisor.rs:6039).
- Freshness: skew check + B-owned nonce dedup; record THEN persist-fail-closed (Class-S, new gate `check-class-s-fail-closed.sh`); on persist-fail nonce stays recorded (fail-closed). Per-set gating (caller+target in participant set) serializes → no dedup TOCTOU. Crash-survival: dedup IS in Class-S snapshot.
- Protocol signed types `cross_context_saga.rs`: §9.5.1 canonical, length-prefixed VarBytes (splice-resistant), signer-authorization requires caller-passed authorized key (no self-named key trust). Clean, well-tested.
- NeedsRepair: concurrency slot released (reservation drops on scope exit), escrow HELD, initiation budget non-refundable (`hold_external_for_repair` clears hard-RL refund). No attribution oracle.
