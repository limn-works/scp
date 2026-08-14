---
name: pr2186-birth-into-actor-round2
description: Round-2 security re-review of SCP PR#2186 (#2148 birth-into-actor) fixes — all findings RESOLVED, no new issues
metadata:
  type: project
---

# PR#2186 / #2148 birth-into-actor — Round-2 fix verification (2026-08-01)

Round-1 found the change (provider per-context crypto dissolved onto the actor's `PerContextState`) SOUND. Round-2 verified the fixes for F1/F2/F6/F10 (+ancillary F5/F7). ALL RESOLVED, NO new security issue. READ-ONLY (cargo build was running).

**Why:** #2148 completes ADR-049 §6 — provider holds NO per-context crypto (contexts/taken_context_ids/broadcast_keys maps deleted), actor `PerContextState` is sole home. Closes #2167 cross-map TOCTOU by construction.

- **F1 fault-seam prod-unreachable — RESOLVED.** `force_rotation_failure` re-homed from deleted provider (was `AtomicBool`+`pub` method) to actor as plain `bool`+`pub(crate)` method (TIGHTER). All 6 touchpoints `#[cfg(any(test, feature="testing"))]`: field decl state.rs:513, Debug field 557, Default init 574, seed init 2223, read-branch in rotate_sender_key 2717, arm_rotation_failure_once 2237. `testing` feature non-default, Cargo.toml:16 "Production builds must never enable", not FFI-exported (pub(crate)). Production build compiles seam+branch away entirely. Read-branch placed BEFORE any mutation (fail-closed, epoch not incremented).
- **F2 sole-guard comment fix — RESOLVED.** lifecycle_helpers.rs:1768 + supervisor.rs:13774/13907 now attribute double-birth/durable-divergence authority to `bootstrap_spawn_lock` (13423) + Precheck A live-actor (13578) + Precheck D durable first-writer-wins (13640) TOGETHER WITH registry insert — not registry insert alone. Notes WELCOME persists step-4 (13898) BEFORE register step-5 (13918). Comments-only, NO reorder.
- **F6 dispose-on-failed-spawn — RESOLVED.** `dispose_secrets` on 4 error branches: supervisor.rs:4548 (dup-birth reject in spawn_actor_with_watchdog — only pre-consume Err path), 13913 (WELCOME persist-fail); builder.rs:999 (step-4 eventlog init fail), 1033 (step-6 transition fail). Zeroizes OpenMLS Ed25519 signer via `destroy_group` (SignatureKeyPair has no Zeroize — scp-mls #82); SenderKey ZeroizeOnDrop. 3 impls: OwnedMlsCryptoState::dispose_secrets (provider.rs:392), ContextCryptoState (state.rs:2130), PerContextState delegating (state.rs:2249). Each branch returns Err; state consumed/moved; no double-dispose; no live actor with disposed secrets.
- **F10 attestation doc — RESOLVED.** key_destruction.rs:76 documents `destroy_ephemeral_keys` true/true as observability MARKERS guaranteed by actor's separate `dispose_secrets`, not verified in-fn. Behavior unchanged (values were already hardcoded true). Honest; hedges gating as separate concern.
- **F5 (ancillary) — CLEAN.** check-deleted-primitives.sh removes 6 ban entries; fully covered by scoped typed test `provider_steady_state_crypto_methods_are_deleted` (crates/scp-testing/tests/integration/pipeline_wiring.rs — PROVIDER_SRC=include_str! of provider.rs only; checks both `fn NAME(` method-defs AND `name: Type` field-absence for contexts/taken_context_ids/broadcast_keys) + compiler. Also removes anyhow `.with_context()` false-positive landmine. CLAUDE.md-blessed redundant-scanner removal, NOT a bypass.
- **F7 (ancillary) — CLEAN.** `#[must_use]` on struct OwnedMlsCryptoState (provider.rs:307) — flags a birth path that binds-and-drops without seeding (half-keyed actor). Hardening.
