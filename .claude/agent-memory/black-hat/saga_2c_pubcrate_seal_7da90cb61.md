---
name: saga-2c-pubcrate-seal-7da90cb61
description: Saga crash-recovery restore-implies-replay pub(crate) narrowing (commit 7da90cb61) — all 7 compiled probes confirm both seams sealed; doc-accuracy correct; latent prod no-op replay gap surfaced honestly
metadata:
  type: project
---

# Saga 2C restore-implies-replay seal @ 7da90cb61 — ALL BARRIERS HOLD

Final hardening commit of §17.16.4 restore-then-replay recovery PR. FIX C narrows
`Supervisor::restore_all_contexts` from `pub` to `pub(crate)` (supervisor.rs:8037).
FIX A/B = doc corrections.

**Why:** the restore-then-replay invariant must be unforgeable at the compiler, not
just by source-text gate + behavioral test.
**How to apply:** if this seam is touched again, re-run the 7 probes below.

## Compiled probes (all PASSED, all reverted to zero-diff)
1. Cross-crate bare-leg call `Supervisor::restore_all_contexts(sup)` from scp-ffi → **E0624 private**.
2. `lifecycle_helpers::restore_all_contexts` (the pub FREE helper doing real restore work, returns Vec<String>, NO witness) → unreachable cross-crate: `pub(crate) mod lifecycle_helpers` (context/mod.rs:42) → **E0433 not found** via scp-core. The `pub` on the fn is dead cross-crate.
3a/b. Witness forge from scp-ffi: `RestoredContexts::default()`→E0599, `{ids:vec![]}`→**E0451 private field**, `::new()`→E0624 private, `::for_test()`→E0599 (feature off).
4. Same forge set under `allow_in_memory_custody,testing` (the `scp-ffi→scp-testing→scp-core/testing→scp-runtime/testing` chain) → for_test still E0599 (saga-witness-test-mint NOT implied by testing; only the 2 saga test targets' required-features enable it), bare leg E0624.
5a. Mutate `CoreFields::restore_all_persisted_contexts` (scp-ffi-common) to UFCS bare-restore → now **UNWRITEABLE: E0624**. Before FIX C this compiled; now type-sealed. Behavioral test becomes defense-in-depth for this evasion.
5b. Compilable restore-without-replay (added a fake `pub blackhat_restore_only`, pointed bridge at it) → bootstrap test `bridge_restore_entry_runs_restore_and_replay_legs` FAILS at LEG2 (saga_bridge_bootstrap.rs:330). Behavioral test has real teeth for evasions the type seal can't catch (future pub restore-only method).

## Doc accuracy (FIX A/B) — VERIFIED TRUE
All 6 prod supervisor-construction sites use `Supervisor::with_providers` (pyo3/uniffi/napi runtime.rs, common bridge_instance.rs:2876/4260, scp-node self_host.rs:615). `with_providers` hardcodes `Arc::new(NoopSagaJournal)`. NO prod site calls with_providers_and_journal or injects ProtocolRepositorySagaJournal. No residual "durable journal attached at bridge" misleading doc survives.

## LATENT FUNCTIONAL GAP (pre-existing, NOT a regression — commit surfaces it honestly)
Prod replays over `NoopSagaJournal` whose `load_unresolved` returns `Ok(Vec::new())` (supervisor.rs:10843) and `append` no-ops → **crash-recovery saga reconciliation is a structural no-op in every shipping bridge today.** The §17.16.4 machinery + type seal are all built and correct, but inert in prod until durable journal wired via with_providers_and_journal (Phase 2D/PR-7). FIX A is exactly the honest doc that surfaces this (old doc hid it by falsely claiming "durable journal attached at bridge"). Per "legibility before opt-in" this is the right posture.

## Nothing broken by narrowing
Only cross-crate caller was persistence_sdk.rs, redirected to restore_on_startup (replay over NoopSagaJournal = no-op, restore semantics preserved). runtime+ffi+ffi-common+node all compile clean. WASM restore_all_contexts is a hard-error stub (ephemeral, ADR-034) — not a seam.

## Pre-existing flake (NOT this commit)
persistence_sdk::full_lifecycle_suspend_restore_roundtrip fails locally at line 339 (Phase 2 sqlite advisory-lock os error 35, macOS flock) — reproduces identically on parent d4f7a7aea. Independent of the restore redirect (line 395, never reached).
