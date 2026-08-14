---
name: pr6b-116-ffi-saga-export-review
description: Completeness verdict on branch feat/116-ffi-saga-export (PR-6b #116) — native FFI exports of §6.2.4 cross-context tool-invocation saga; verdict COMPLETE
metadata:
  type: project
---

Branch `feat/116-ffi-saga-export` — PR-6b #116: native FFI exports of the §6.2.4 cross-context tool-invocation saga `tool_invoke_cross_context_saga`. Verdict: **COMPLETE**. Re-verified at **HEAD 30d5d1504 (rebased on main 29b87c8a5)** 2026-06-29, read-only — tip adds NAPI `decode_asserted_nonce` non-hex + wrong-length fail-closed test arms on top of 49402beae; matrix unchanged, still COMPLETE. (Prior passes: 49402beae, 506da562b.)

NOTE on issue numbering: GitHub #116 is a CLOSED *unrelated* issue (py_mcp_load_contexts relay discovery); "116" here is an internal planning slug. PR-6c SDK-wrapper tracker = #1939 (OPEN, confirmed).

**Post-relocation (tip 49402beae) verified:** all saga tests now live in ONE outer `#[cfg(feature="allow_in_memory_custody")] mod xctx_saga_tests` per bridge (covers helpers + future tests by construction → closes the no-feature `never used` regression class). Counts: `cargo test -p scp-ffi-uniffi --features allow_in_memory_custody --lib xctx_saga --list`=**5**; `-p scp-ffi-napi ... xctx_saga`=**4**; no-feature `--lib --no-run` for both = **compiles clean** (no-feature saga count=0). uniffi Cargo.toml `allow_in_memory_custody += scp-core/testing` (the feature-gate fix exposing `Supervisor::test_insert_member` for member-but-unhosted axis-a; napi gets it via `dep:scp-testing`). e2e_bridge gated by `required-features` (no-feature → skip, not error). Only "WASM" in added files = ADR-034 doc-comment (correct, not stale wiring). RAN: 3 pipeline_wiring saga_export assertions pass; parity_count/aliases_sync/cross_bridge_parity_matrix/min_parity_comment pass.

Scope = bridge exports across PyO3/NAPI/UniFFI only. SDK wrappers (Python/TS/Swift/Kotlin) correctly deferred to issue **#1939** (real, OPEN — "PR-6c: SDK wrappers for tool_invoke_cross_context_saga"). WASM N/A (no Supervisor, ADR-034).

**Why:** verifying the per-op × per-layer matrix is fully filled before merge.

**How to apply:** Coverage matrix all-✓:
- Core producer pre-exists (untouched): `Supervisor::start_cross_context_tool_invocation_saga` @ scp-runtime supervisor.rs:5478. All 3 bridges dispatch to it, NO reimplementation.
- Shared classification: `crates/scp-ffi/common/src/saga_errors.rs::decompose_saga_error` (behind `resolvers` feat), 5 unit tests pass. All 3 bridges' `map_saga_error` route through it (no per-bridge drift).
- Typed error variants per bridge: PyO3 3 exception classes (SagaAbortedError/NeedsRepair/Busy, registered in register_exceptions, structured datum on e.args[2], None never 0); NAPI 3 thiserror variants w/ machine-parseable `(retry_after_ms=null)` suffix; UniFFI 3 ScpError variants + SagaResult record.
- SCP-SAGA codes: SAGA_13050 (caller-axis auth), 13065 (NeedsRepair), 13066 (Busy) in error_codes.rs; Aborted sub-codes formatted inline from producer discriminant; band 13000-13999 in check-error-codes.sh.
- pipeline_wiring: 3 REAL brace-matched body assertions (fn_body_contains via genuine brace-matching parser) pinning each export→ enforce_caller_principal_binding + context_id_to_bytes (ADR-056) + start_cross_context_tool_invocation_saga, PLUS helper→registry+is_member edge. Floor 41→44. NOT let_=theater. Tests pass.
- ffi_conformance: floor 105→106; op in bridge-aliases.json drives parity_operations(); per-bridge symbol presence asserted; aliases-in-sync test passes.
- bridge-aliases.json: tool_invoke_cross_context_saga, all 3 bridges populated, no exemption (Rust-core present on all).
- capability-matrix: invoke_cross_context_saga all 4 SDKs false WITH per-SDK exemptions citing #1939.
- e2e: PyO3 e2e_bridge.rs full committed-path test (receipt+output, sum=42) + reject paths; TS real-napi.test.ts real-addon committed round-trip + SCP-SAGA-13050/13062 + retry_after_ms=null suffix.

No issue-number leaks in PR-added source (only 2 pre-existing #1543 refs from earlier commits). No #[ignore] on saga tests. Supporting changes minimal: resolve_signing_key→pub(crate), new identity_registry_contains helper, e2e required-features comment.

Related: [[pr6b_116_ffi_saga_export_review]] (alignment-reviewer's note), [[saga-count-one]].
