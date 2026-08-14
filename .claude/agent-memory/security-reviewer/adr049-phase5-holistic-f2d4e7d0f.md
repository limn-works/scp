---
name: adr049-phase5-holistic-f2d4e7d0f
description: ADR-049 Phase 5 FINAL holistic security re-review (actor-per-context refactor) at origin/main f2d4e7d0f — 3 cross-cutting findings (2 HIGH, 1 MEDIUM)
metadata:
  type: project
---

# ADR-049 Phase 5 holistic security re-review (f2d4e7d0f) — 2026-07-07

Lane: actor lifecycle (supervisor/) + async-trait FFI surface + crypto boundaries.
Cross-cutting theme: **core safety machinery is correct + well-tested in scp-runtime, but the operator/SDK invocation path is missing, stubbed, or unsafe at the FFI boundary.** Per-PR reviews couldn't see this; only holistic could.

## HIGH-1 — Guard-across-block_on regression (#2056/#1940 class), ~20 prod sites, all 3 native bridges
- `with_identity`/`with_identity_mut` (scp-ffi/src/runtime.rs:1996/2015) pass a live DashMap `Ref`/`RefMut` shard guard (`entry`, bound in helper frame) into a `FnOnce`; guard drops only when the CLOSURE returns. Any `block_on` written INSIDE the closure body holds the identity-registry shard guard across the whole async op. Same for `with_context`/`with_ucan_state`.
- **Correct pattern exists adjacent**: `resolve_signing_key` (context.rs:1514-1518) clones `(custody,handle)` OUT, closure returns (guard drops), THEN block_on — with an explicit #1940 comment. `create_identity_link_attestation` (identity.rs:2136) has textbook Phase1/2/3 lock→clone→drop→sign→relock.
- **Divergent (held-across) confirmed by reading:** resolve_verifying_key (context.rs:1539), derive_member_pseudonym (context.rs:1630, borrows `entry` INSIDE the future), and worst case **identity_rotate_key (identity.rs:1505)** — holds a `with_identity_mut` **WRITE** guard across `did_method.initialize_sequence`+`rotate_active_key` = DID-DHT **network** publish. Deadlock if the async work re-touches the same shard (DashMap RefMut non-reentrant → block_on can't progress); at minimum serializes the shard across a network round-trip = DoS.
- Systemic twin: event-log **checkpoint signing** reproduces it in all 3 bridges (src/event_log.rs:742, napi/event_log.rs:496/555, uniffi/bridge.rs:5319/5444, with_ucan_state write guard). Agent counted 20 YES (all non-test). Full list in the a7518 sweep.
- **Why mechanical checks miss it:** clippy `await_holding_lock` only fires on `.await`, NOT on `block_on` (synchronous). This whole class is invisible to that lint.
- Real-actionable. Fix = clone-out-then-drop-then-block_on at every site (the resolve_signing_key shape).

## HIGH-2 — Compromise recovery (spec §9.12) is a silent no-op at EVERY FFI bridge
- `identity_execute_recovery` in PyO3 (src/identity.rs:2341 FfiRecoveryBackend), UniFFI (uniffi/bridge.rs:16591 UniffiRecoveryBackend), napi (napi/scp.rs:1173 NapiRecoveryBackend): every backend method (mls_update, revoke_ucans, rotate_key_packages, notify_contacts, rotate_psk) is a no-op `Ok(())`/`true`. Even step-1 KeyRotationOutcome is FABRICATED by `agent_key_rotation_outcome`/`active_key_rotation_outcome` (recovery.rs) — a plain struct ctor, `did_changed:false`, no real custody rotation. `contact_dids`=HashSet::new(), `psk_params`=None hardcoded.
- Returns a SUCCESS RecoveryResult while nothing rotates/revokes/notifies → false assurance the attacker is locked out after "recovery." Exposed + callable from all 4 SDKs. Untracked stub (no SCP-NNN; docstring "local stub pending SDK-layer wiring") — violates CLAUDE.md no-stub policy.
- The scp-runtime CompromiseRecoveryOrchestrator (recovery.rs) itself is correct + well-tested; only the FFI backend wiring is hollow. Real-actionable.

## MEDIUM-3 — commit_fault fail-closed gate has NO reachable release valve
- `acknowledge_commit_fault` (governance_helpers.rs:356) + `GovernanceCommand::AcknowledgeCommitFault` (commands.rs:1315) + handler (handlers/governance.rs:108) all exist, but NOTHING constructs/sends the command: no ContextManager method, no FFI export (empty grep across scp-ffi/ + bindings/), no SDK wrapper. supervisor.rs:12582 only destructures for routing. state.rs:243 docstring cites non-existent `ContextManager::acknowledge_commit_fault` = phantom provenance.
- commit_fault is set fail-closed on LOCAL outbound commit-broadcast failure — reachable by a SINGLE sender-key step failure after member removal (fail_close_remove_member, gov_helpers.rs:752) or 50 broadcast failures (MAX_PENDING_COMMITS). No adversary needed — transport flakiness. Marker is persisted (survives restart). Once tripped, governance+lifecycle+sends are wedged with no exposed recovery. Availability defect. Real-actionable (violates Integration Checklist: handled but unreachable from ContextManager/FFI/SDK).

## SOUND verdicts (no findings)
- Lane1 respawn/poison (supervisor.rs 810-4392): CrashWindow sliding-window (3 crashes/60s → sticky poison), payload-free panic logging (never reads JoinError payload — key-material defense), guards copied-out+dropped before await, anti-resurrection (only Active snapshot respawns), bootstrap_spawn_lock across whole respawn. Obs: a panic-pill message from a malicious member is bounded to per-context DoS by design (poison-after-3), not infinite loop.
- Lane2 commit_fault triggerability: NOT remotely triggerable — pending_commits grows ONLY from local outbound commit broadcasts (apply/keep_broadcast_failure, called from lifecycle/trust_recovery). Remote party can't inflate another node's queue.
- Lane3 saga journal (saga_journal.rs): len+CRC32 framing = torn-write detection (documented NOT a security primitive; correct for local disk — a disk attacker can rewrite CRC too). Flag-and-skip corrupt entries = fail-safe (saga stays unresolved, not mis-applied). Restore-THEN-replay ordering type-system-sealed via `RestoredContexts` witness (private field, module-priv ctor, no Default/Clone, test-mint behind saga-witness-test-mint feature no prod build enables) — same pattern as OwnedIdentityDid.
- Lane4 ?Send recovery single-task: HELD. Orchestrator driven only via `rt.block_on` at FFI (uniffi bridge.rs:16636, pyo3 identity.rs:2384, napi), NEVER tokio::spawn'd; backend is a local ZST. `#[allow(clippy::future_not_send)]` intentional. No data-race path.
- Lane6 secret logging: CLEAN (agent ad2823 read ~200 tracing sites + all ContextError ctors). Structural: SigningKeyBytes (commands.rs:575, Zeroizing) + containing payloads have NO Debug derive → `{:?}` of a key-carrying command is a COMPILE error. Errors interpolate only `{e}` generic phase/length, never operands. Strong positive.
