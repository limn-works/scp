---
name: pr1883-restore-then-replay-typestate
description: PR #1883 Phase 2D — RestoredContexts witness token type-encodes restore-before-replay so reorder won't compile; restore_all_contexts stays pub
metadata:
  type: project
---

PR #1883 (branch `feat/2c-saga-dispatch`, worktree `saga-2c`) makes the §17.16.4 restore-then-replay startup ordering unbreakable by construction.

**Design:** `Supervisor::restore_all_contexts` returns a `RestoredContexts` witness token (private `ids` field, module-private `fn new`, mirrors `CrossContextSagaSeal` idiom at supervisor.rs:92). `replay_unresolved_sagas(&self, restored: &RestoredContexts)` requires the token as proof restore ran → calling replay first does not compile (no token to pass). `restore_on_startup` is the sole site that threads it. A `compile_fail` doctest pins the non-compile.

**Why:** black-hat proved the text gate `restore_on_startup_runs_replay_before_restore` was the SOLE order enforcement and was evadable — `extract_fn_body` (pipeline_wiring.rs:~173) stripped `//` and `""` but NOT `/* */`/char/raw strings, so a `/* restore_all_contexts() */` decoy false-passed against replay-first code. Type encoding is the durable fix (same lesson as OwnedIdentityDid compile-enforcement).

**Visibility decision:** `restore_all_contexts` STAYS `pub` (NOT narrowed to pub(crate)) because `scp-testing` (separate crate) legitimately calls it directly in `persistence_sdk.rs` E2E. scp-ffi bridges (pyo3/napi/uniffi/common bridge_instance) all route through `restore_on_startup` only. The text gate (hardened for `/* */`/char/raw-string evasions) stays as the bridge-routing negative assertion.

**Test-token constructor:** `RestoredContexts::for_test(ids)` gated `#[cfg(feature = "testing")]` (NOT `#[cfg(test)]` — integration tests in `crates/scp-runtime/tests/` compile against public API + require `testing` feature; cfg(test) wouldn't reach them). Production release builds lack `testing` so it can't leak. ~10 external-test call sites in actor_saga_crash_recovery.rs / actor_saga_coordinator.rs use it.

**How to apply:** if revisiting saga recovery ordering, the type system is the authority; the gate is defense-in-depth. Don't re-narrow restore_all_contexts without relocating the scp-testing E2E.
