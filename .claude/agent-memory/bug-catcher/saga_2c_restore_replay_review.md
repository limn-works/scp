---
name: saga-2c-restore-replay-review
description: feat/2c-saga-dispatch §17.16.4 restore-then-replay + §5.14.13 broadcast handshake — final defect hunt, clean
metadata:
  type: project
---

# feat/2c-saga-dispatch (15c1aef9c) — final pre-merge review: CLEAN

§17.16.4 saga restore-then-replay startup ordering + bundled §5.14.13 broadcast hosting handshake.

**Why:** Final confirmation before merge. **How to apply:** branch reached clean; pattern is reusable for future ordering-by-witness reviews.

## Verdict: no merge-blocking defect. All 8 gates green.
- scp-runtime build (testing), scp-ffi build: ok
- supervisor lib tests: 185 passed
- pipeline_wiring (74) + saga_bridge_bootstrap (1): ok
- actor_saga_coordinator (10) + crash_recovery (4): ok
- doctests incl. 3 compile_fail forge-closure proofs: 4 passed
- protocol hosting_handshake: 26 passed
- check-error-codes.sh: 2300 occurrences PASSED

## Design pattern worth remembering: ordering-by-type-witness
- `RestoredContexts` witness type encodes "restore BEFORE replay" at compile time. `replay_unresolved_sagas(&RestoredContexts)` can only get the token from `restore_all_contexts()`. Sealed: private `ids` field, module-private `new`, NO Default, NO Clone. 3 compile_fail doctests prove forge-closure (default/struct-literal/no-witness).
- Dual seal: `restore_all_contexts` narrowed `pub`→`pub(crate)` so cross-crate bridges can't call the bare restore leg and skip replay (E0624). Forces all bridges through `restore_on_startup`.
- Source-text gate `restore_on_startup_runs_restore_before_replay` is documented as defense-in-depth ONLY; type system is primary. Hardened comment/string/raw-string/char-literal-stripping parser (handles lifetime-vs-char) so a `/* decoy */` can't evade.

## Test-mint feature isolation (verified end-to-end, security-relevant)
- `saga-witness-test-mint` gates `RestoredContexts::for_test`. Empty feature, NOT implied by `testing`, enabled ONLY by the 2 actor_saga_* test targets' required-features. No crate dep enables it transitively (grep-confirmed).
- CI enables it in test/doc SWEEP steps only (ci/release/build-matrix/docs .yml `cargo test`/`cargo doc`). Artifact builds (`cargo build --release` in build-matrix line 81) and `cargo publish` (crates.io) do NOT enable it. Minter cannot reach any shipped artifact. Claim holds.

## Broadcast hosting_handshake.rs (§5.14.13) — clean
- Domain-separated (SCP-BCAST-HOST-REQ-V1: / -GRANT-V1:), field-enumerated, length-prefixed §9.5.1 canonical_hash preimages. NOT SHA256(prefix‖JCS). OptVarBytes(ucan) uses Absent sentinel SHA256(0x00) ≠ present-zero-length. verify_strict (rejects malleable). Byte-exact preimage tests + per-field tamper tests + gated-vs-ungated non-collision test. Error codes 13100-13102 in 13100-13199 band, registered in sdk-common.md.

## Behavioral enforcement (not just string-search)
- saga_bridge_bootstrap.rs drives the REAL shared bridge entry `restore_all_persisted_contexts` over real persistence + durable journal, asserts BOTH legs ran (context restored AND crash-orphaned saga reconciled to terminal). Genuine, not gamed.
- restore_on_startup_fails_closed_when_restore_leg_errors: restore failure short-circuits replay via `?`, surfaces PersistenceFailed (not swallowed), orphan stays unresolved.
