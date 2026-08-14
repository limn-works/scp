---
name: review-saga2c-restored-contexts-witness
description: Security review of d0c57bd75 (feat/2c-saga-dispatch) — RestoredContexts witness token type-encoding restore-then-replay crash-recovery ordering; CLEAN
metadata:
  type: project
---

# §17.16.4 RestoredContexts witness — restore-then-replay ordering (commit d0c57bd75, branch feat/2c-saga-dispatch)

CLEAN — zero findings across all 5 audited items. Read-only review at worktree saga-2c.

**What it does:** `RestoredContexts` witness token (private `ids` field, module-private `const fn new`) type-encodes the §17.16.4 crash-recovery ordering. `restore_all_contexts` returns it; `replay_unresolved_sagas(&RestoredContexts)` requires it. A reorder ("replay first") has no token to pass → does NOT compile (compile_fail doctest PASSES at supervisor.rs:5529). Mirrors CrossContextSagaSeal / OwnedIdentityDid forge-resistance discipline.

**Item 1 — exactly-once economic integrity (VERIFIED).** Reaper predicate `caller_context_deleted_from_persistence` (supervisor.rs:6037): `Ok(None)`→true (reap; permanently-deleted snapshot), `Ok(Some(_))`→false (not-yet-restored, recoverable), `Err(_)`→false (transient read failure, never mistaken for deletion). Fail-closed both ways: never strand AND never falsely-terminal. Reaper only runs AFTER a `ReversalOutstanding` verdict (recover_preparing_b_entry:5754-5797). PreparingA + PreparingB both route through same record-keyed reversal-and-confirm (recover_saga_entry:5590-5617). Terminal-Aborted asserts "fully compensated" — NEVER written while refund outstanding (the wave-15 invariant, symmetric with abort_saga). Direct unit test `caller_context_deleted_predicate_reaps_only_on_confirmed_absence` pins all 3 arms; PASSES.

**Item 2 — fail-closed restore error (VERIFIED).** `restore_on_startup` (supervisor.rs:8023): `restore_all_contexts().await?` short-circuits with `?` BEFORE `replay_unresolved_sagas(&restored)`. Restore failure → no saga reconciled.

**Item 3 — token integrity (VERIFIED).** `for_test` is `#[cfg(feature="testing")]`-gated. Production constructor is module-private `new`, called ONLY by `restore_all_contexts`. EMPIRICALLY PROVEN: `cargo check -p scp-runtime --no-default-features` (testing OFF) compiles clean WITH `for_test` absent — production `restore_on_startup` uses the real `&restored` witness (NOT for_test). `RestoredContexts::for_test` appears ONLY in: the gated def, doc-comments, and `crates/scp-runtime/tests/` (actor_saga_coordinator.rs / actor_saga_crash_recovery.rs). NOT in scp-ffi/ or bindings/. `scp-runtime/testing` NOT in production cdylib feature graph (cargo tree -p scp-ffi-napi/-p scp-ffi --features server: testing absent). release.yml publish steps (cargo publish -p scp-runtime, npm/gradlew/xcframework) carry NO testing feature; only line 94 `cargo test` uses it. NOTE: stale incremental-build cache once showed a bogus `for_test` at line 8024 — CARGO_INCREMENTAL=0 clean check confirmed source is correct. Lesson: distrust rustc spans on incremental builds when they contradict the on-disk source.

**Item 4 — no authz/gating regression (VERIFIED).** Recovery is purely compensating (LOCAL-economy refund from durable CallerReservationRecord), never grants authority. Lexer rewrite (`extract_fn_body` in scp-testing pipeline_wiring.rs:190) = sound positive recognizer for Rust comment/string/char grammar (nested block comments, hash-counted raw strings, char-vs-lifetime). Additive defense-in-depth over the type-system primary guarantee; 11 parser unit tests + 2 gate tests PASS. Bridge-routing gate now asserts all 3 FFI exports route through restore_on_startup() (not bare restore_all_contexts) — matches integration checklist. Broadcast signing logic untouched (hosting_handshake change is a doc-comment band fix only).

**Item 5 — error codes (VERIFIED).** hosting_handshake band comment `13100-13999`→`13100-13199` aligns source with sdk-common.md registry (line 62: 13100-13199 broadcast-hosting; codes used 13100/13101/13102 in range). No dangling 13003/4/5 (the grep hits are SHA-256 hex substrings, not error codes). `check-error-codes.sh` PASSES (2300 occurrences).

**Tests run (all PASS):** 4 behavioral (reaper predicate + 2 ordering E2E + deleted-caller reap), 13 lexer/gate, compile_fail doctest, clean no-default-features production build.
