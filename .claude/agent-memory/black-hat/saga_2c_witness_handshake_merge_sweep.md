# Saga 2C restore-then-replay + §5.14.13 broadcast handshake (branch feat/2c-saga-dispatch @54f937e0f) — CLEAN/SHIP

Final adversarial merge-readiness sweep. No merge-blocking concerns.

## RestoredContexts witness seal — AIRTIGHT (compile-probed cross-crate)
- File: crates/scp-runtime/src/context/supervisor/supervisor.rs:130-179
- Built an external /tmp probe crate depending on scp-runtime by path; all forge vectors sealed:
  - `::default()` → E0599 (no Default derived)
  - `RestoredContexts { ids: .. }` literal → E0451 (private field)
  - `::new(..)` → E0624 (module-private assoc fn)
  - `::for_test(..)` WITHOUT feature → E0599 (gated out — back-door physically absent from normal dependent build)
  - `replay_unresolved_sagas()` w/o witness → E0061 (witness required; no replay-before-restore)
  - `restore_all_contexts()` cross-crate → E0624 (pub(crate); no restore-without-replay; all callers route restore_on_startup)
- 3 compile_fail doctests pass. No Clone. Type is `pub` only so external doctests can name it.
- Cargo feature `saga-witness-test-mint` (Cargo.toml:32) is standalone, NOT in `testing`, only in required-features of actor_saga_coordinator/actor_saga_crash_recovery. CI enables it ONLY in cargo test/clippy/doc lines — never in artifact-producing build steps (maturin/wasm-pack/XCFramework/.aar), so it cannot ship. Verified via grep of all .toml/.yml/.rs.

## Broadcast hosting handshake §5.14.13 — sound signed types, NO live consumer
- File: crates/scp-protocol/src/context/broadcast/hosting_handshake.rs (1201 lines, leaf types only)
- Domain-separated preimages (SCP-BCAST-HOST-REQ-V1 / -GRANT-V1, distinct from envelope/key labels), §9.5.1 field-enumerated canonical_hash, ed25519 verify_strict.
- Named-field *Fields structs prevent positional [u8;32] id swap (compile-visible).
- verify() requires caller to pass the RESOLVED Active Signing Key for the claimed DID — does not trust msg to name its own key.
- Key-redirection closed: wrapping_pubkey bound into both signatures + echoed grant→request + persisted in AcceptedHostSnapshotEntry (pull checked against durable record).
- Gated-vs-ungated UCAN non-collision via CanonicalField::Absent sentinel (SHA-256(0x00)) ≠ present-zero-length VarBytes. Test-proven.
- Replay anchored by nonce (echoed, never independently drawn) + saga_id (Commit replay anchor, supersedes per (host,subscriber)).
- CRITICAL CONTEXT: freshness/nonce-dedup/lifetime-ceiling are Prepare-B runtime steps NOT in this slice. SagaInput::BroadcastHostingHandshake returns NotImplemented at dispatch (supervisor.rs:6562). ONLY reference to the handshake types outside their module is `pub mod hosting_handshake;`. So zero live forgery/replay exposure — dormant leaf types. Wired in 2C commit 11.5.
- 26 unit tests pass.

## Bridge resume wiring — restore_on_startup end-to-end
- crates/scp-ffi/common/src/bridge_instance.rs restore_all_persisted_contexts now calls supervisor.restore_on_startup() (restore THEN replay) not bare restore_all_contexts.
- Error split: NotInitialized/PersistenceFailed → debug (expected ephemeral), genuine saga-journal fault → warn.
- All 3 SDK scp.rs resume wrappers (uniffi/pyo3/napi) delegate to trait BridgeInstanceCore::resume default body — no re-impl. Override ban gated by scripts/check-bridge-instance-lifecycle.py (PASSED).
- saga_bridge_bootstrap.rs: real 2-process crash-recovery test — persist ctx + orphan Initiated saga in proc1, drop supervisor (crash), drive bridge restore entry in proc2, assert BOTH context rehydrated AND orphaned saga reconciled to terminal. Not a string-match.

## Recovery arms (supervisor.rs:5635+) — wave-15 posture preserved
- Never mark terminal-Aborted while caller reservation reversal outstanding; deleted-context reap (caller_context_deleted_from_persistence) is the one bounded residual escape from infinite non-termination. Matches prior xctx_preparingb_sweep_wave15 memory.
- Known limitation documented: external escrow hold on a context deleted mid-PreparingB is irrecoverable from journal evidence (pre-existing journal-evidence boundary).

## Gates/tests run green: clippy (protocol+runtime, witness feat) clean; 26 handshake + 3 compile_fail doctests + 10 coordinator + 4 crash_recovery + 74 pipeline_wiring + 1 saga_bridge_bootstrap. No new unwrap/expect/panic/unsafe on production paths (all .expect in #[cfg(test)]). Small file diffs = doc renames ContextManager::→Supervisor:: + RestoredContexts re-export.
