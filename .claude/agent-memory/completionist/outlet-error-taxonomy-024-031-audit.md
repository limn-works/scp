---
name: outlet-error-taxonomy-024-031-audit
description: Whole-outlet audit Group 3 (OutletError + wire format, SCP-OUT-024..031) @origin/main d5de8b153 — the typed §5.4.4 envelope is a never-wired island; 027/029/030/031 substantially incomplete despite "done"
metadata:
  type: project
---

Audit of SCP-OUT-024..031 (OutletError taxonomy + wire + SDK) against origin/main d5de8b153 (worktree /Users/alec/Developer/limn/scp-wt-audit). All 8 marked "done".

**Why:** whole-outlet completeness audit; error taxonomy is money/UX-relevant (retryability, oracle-collapse).
**How to apply:** the typed §5.4.4 `errors::OutletError` envelope (024/025/026) is a fully-built ISLAND — never emitted on any production wire. Two OutletError types coexist: legacy thiserror ENUM at `outlets/mod.rs:185` (canonical `scp_protocol::...::OutletError`, used by runtime) vs typed STRUCT envelope at `outlets/errors.rs:635` (aliased `OutletErrorEnvelope`, unused).

Verdicts:
- 024 COMPLETE (types defined+tested; island).
- 025 COMPLETE (14 codes in [12,18]); OVERLOADS: 6131 credit-exhausted[Immediate]+stream-gap+stream-cap-exhausted (tracked #2209, wrong retry for gap/cap); candidate 6150 economic.adapter-failure[Never] (transient infra marked non-retryable).
- 026 COMPLETE at type level (flatten unknown_fields), never exercised live.
- 027 INCOMPLETE: lossy collapse it claims to remove STILL LIVES as `invocation_error_to_context` (outlets_helpers.rs:2815, 14+ callers) → every variant to `ContextError::PermissionDenied(String)` with PHANTOM codes SCP-OUTLET-6080..6089 (NOT in §5.4.4 registry, outside sub-block). No `From<InvocationError> for OutletError`. `from_invocation_error_template` (errors.rs:982) DEAD (0 callers). `invocation_error_to_terminal_payload` (invoke.rs:3115, correct registry codes) also DEAD. AC[9] grep passes ONLY because manager/outlets.rs was renamed to outlets_helpers.rs (file-nonexistence enforcement theater).
- 028 COMPLETE: `run_executor_with_panic_guard` (invoke.rs:2728, wired at :617) real catch_unwind→HandlerPanic→6130+OutletVerified event+1KiB truncation. AC[1] slug 'handler-panic' stale vs spec 'execution.handler-panic' (code correct).
- 029 INCOMPLETE (severe): `wrap_cross_context_error` DOES NOT EXIST. No source_chain prepending / ContextHop pseudonymization / trail-padding / pad_nonce keying anywhere live. ACs[0-21] unimplemented; only the type + unit tests manipulating it manually.
- 030 INCOMPLETE (severe): check-error-codes.sh has ZERO 6100-6199 sub-block logic; only checks broad 6000-6999. AC[0][1][2][3] unmet. Phantom 6080-6089 slip through. Never reads outlets/error_codes.rs, never lists 8 classes.
- 031 INCOMPLETE (severe): Python has `class ProtocolError(OutletError)` (AC[11] requires 0) and NO `OutletProtocolError` (requires ≥1) — direct violation; missing Authorization/Input/Execution/Output/Economic/Transport/Governance subclasses under OutletError (Transport/Governance/Economy extend ScpError). TS OutletError not abstract root. Swift Errors.swift 8-line stub (flat UniFFI ScpError enum, no hierarchy). Kotlin Errors.kt MISSING. `outlet_error_conformance.rs` + `tests/conformance/vectors/outlet_error_fixtures.json` DO NOT EXIST. No PII redaction (AC[9]) in errors.py/errors.ts.

Also: `reserve_error_to_open_rejection` (outlets_helpers.rs:2924) catch-all `_ =>` maps not-a-member/persist/transport/signature (permanent) → AdmissionRateLimited (6160, WithBackoff retryable) = masks permanent failures as retryable rate-limit.

FFI: non-streaming outlet errors surface via ContextError::PermissionDenied → extract_scp_code (scp-ffi/src/error.rs:550) → SDK sees SCP-OUTLET-608x (phantom, unmappable by any registry-based SDK layer).

LESSON: when a story's AC greps a specific file path (e.g. manager/outlets.rs), verify the file still EXISTS — a rename/relocation makes the negative grep pass vacuously while the offending code lives on elsewhere.
