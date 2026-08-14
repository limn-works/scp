---
name: scp-out-047-final-signoff
description: SCP-OUT-047 whole-feature (all 4 passes) FINAL completeness sign-off — streaming-saga FFI surface end-to-end; COMPLETE @b1d28ef08
metadata:
  type: project
---

# SCP-OUT-047 final all-pass sign-off — COMPLETE zero-gap @b1d28ef08

Branch feat/outlet-xctx-047-streaming-saga-ffi (10 ahead origin/main, 0 behind). Whole cross-context streaming-saga surface: runtime saga (046) → 3 native bridges (PyO3/NAPI/UniFFI) → 4 SDKs → matrix → WASM fence. Story status `done` = LEGITIMATE.

**Verb × layer matrix — every cell filled or sanctioned-fenced:**
Two verbs: `open`(+poll_next companion) and `recover`(_streaming_saga_truncated_close). Both present at: runtime (supervisor.rs:6413 start_cross_context_streaming_outlet_invocation_saga; :6905 recover_...), PyO3 (#[pymethods] outlet_stream.rs:1838/1882/1906), NAPI (scp.rs js_name outletStreamingSagaOpen/PollNext/RecoverTruncatedClose), UniFFI (#[uniffi::export] outlet_stream.rs:1834/1894/1919), Python/TS/Swift/Kotlin SDK (open→StreamingSagaHandle lazy + recover verb, all 4), pipeline_wiring (3 assertions), capability-matrix (2 rows). WASM = sanctioned node-delegated fence (grep scp-client-wasm/src EMPTY, ADR-057).

**All 12 ACs MET (re-verified against code, RAN the tests):**
AC1 equivalently-named method ✓. AC2 PyO3 export + Python __aiter__/__anext__/_ensure_open lazy iterator over poll_next ✓. AC3 NAPI+UniFFI mirror ✓. AC4 WASM none ✓. AC5 enforce_caller_principal_binding(caller_did) in ALL 3 open impls ✓. AC6 xctx_streaming_saga_open_returns_before_committed_non_blocking RAN ok. AC7 ADR-049 §3a streaming amendment present at HEAD (receiver-prompt-return+async-commit-at-seal+caller_did forward obligation). AC8 FFI invoker gate SCP-PERM-3001 BEFORE key-resolve + 3 rejection tests ok + runtime xctx_streaming_saga_truncated_close_ac7 RAN ok (billed_count/exec-once). AC9 3 pipeline_wiring assertions RAN ok. AC10 check-sdk-coverage PASS 0 errors. AC11 cargo build --workspace --release exit 0. AC12 cargo test -p scp-ffi exit 0 (71 base; 73 w/ capability-grant).

**Enforcement all coverage-EXPANDING:** bridge-aliases +3 real entries (all 3 bridges filled, pass-1 exemptions removed); MIN_PARITY_OPERATIONS 106→109 (raised); matrix +2 rows; check-sdk-coverage +2 aliases; check-bridge-symmetry 0 findings. The credential_backend_durable matrix-row + alias REMOVAL = paired ADR-062 §Decision 6 feature removal (removing a now-nonexistent capability, NOT weakening).

**Cross-pass consistency:** 4 SDKs uniform (StreamingSagaHandle + recover); 3 bridges identical security ordering (open: enforce_caller_principal_binding; recover: invoker SCP-PERM-3001 gate BEFORE key-from-custody, evict-on-success) + shared drive_recover_truncated_close driver (common/src/streaming_saga.rs — thin final hop; gate+key live per-bridge in _impl). No stubs/todos against ACs ("placeholders the runtime discards" = documented no-op ContextParams matching same-context open; "not yet implemented" hits = pre-existing governed-invite area, on origin/main). Only 1 ignored test = a doctest, not an AC.

**2 follow-ups genuinely out-of-047-scope:** (a) runtime-reserve active-state gate, (b) lazy-open cancellation-orphan/double-escrow — neither in the 12 ACs, neither touched/introduced by the diff, both systemic/pre-existing (shared w/ same-context 037 + unary + Python). Story's last actionItem (live-cancel control-plane) is conditional "if/when specced" = legit named-owner ref, not a hidden gap.

**2 non-blocking observations (NOT gaps):** (1) AC3 text cites "UniFFI/scp.udl" but UniFFI is proc-macro (#[uniffi::export]); scp.udl has 0 outlet content — substance met, AC phrasing stale. (2) ADR-062 credential-feature removal (~1400 LOC deletion) bundled into 047 branch via allow_in_memory_custody→testing migration that 047 tests needed — coupled-but-orthogonal cleanup riding the feature PR.

**LESSON: AC6 (non-blocking-open) + the whole e2e streaming-saga suite are feature-gated behind `outlet-capability-test-grant` — a PLAIN `cargo test -p scp-ffi` compiles but SILENTLY FILTERS them out (only 71/73 tests, AC6 name absent). Must run `--features "scp-ffi/testing,scp-ffi/outlet-capability-test-grant"` to exercise AC6. Same for the runtime AC8 test: it's plain #[cfg(test)] in the lib but easy to mis-scope — target `-p scp-runtime --lib`. A reviewer who trusts a bare `cargo test -p scp-ffi` green would never actually run the AC6/AC8 substance.**
