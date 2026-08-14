---
name: c3c1-participation-record-supervisor-unavailable-divergence
description: C3C-1 participation_record R3 (c3c-ts-work, uncommitted) — compute-fail path NOW converged CTX_2000 ×3 (R2 fix landed), but a SECOND supervisor-related fail mode (supervisor UNAVAILABLE/suspended) diverges: PyO3 supervisor(bi)? → CTX_2001
metadata:
  type: project
---

C3C-1 typed `participation_record` op, branch `c3c-ts-work`, UNCOMMITTED working tree. R3 review (this round) of cross-bridge error-code consistency.

**R2 fix CONFIRMED LANDED:** the supervisor *compute* path (`.participation_record(...).map_err(...)`) now emits CTX_2000 on all three bridges — PyO3 uses explicit `ScpPyError::ContextError{code: CTX_2000}` (NOT `context()` which would be CTX_2001), with an inline comment saying exactly that. NAPI `ScpNapiError::Context{CTX_2000}`, UniFFI `ScpError::Context{CTX_2000}`. JSON-parse → VALID_7059 ×3. Attestation-sourcing → VALID_7059 ×3. All correct.

**NEW divergence found (WARNING, not blocker):** there are TWO supervisor-related fail modes, and only the *compute* one was converged. The *supervisor-unavailable/suspended* (not-yet-attached) mode diverges:
- PyO3 trust.rs:642 `crate::runtime::supervisor(bi)?` → the helper (runtime.rs:166) routes through `ScpPyError::context()` which emits **CTX_2001** (error.rs:199-204).
- NAPI runtime.rs:806 `supervisor(bi)?` helper emits **CTX_2000** for both suspended + not-attached.
- UniFFI inlines `self.inner.core.supervisor().ok_or_else(|| ScpError::Context{CTX_2000})` → **CTX_2000**.

So: PyO3 carefully fixed the explicit compute-path map_err to CTX_2000, but the implicit `?`-propagated supervisor-acquisition path still yields CTX_2001 → diverges from NAPI/UniFFI for the SAME "supervisor not ready" condition. Fix: in PyO3 `participation_record_impl`, don't rely on `supervisor(bi)?`; acquire and re-map to CTX_2000 (e.g. match/ok_or_else with explicit ContextError{CTX_2000}), OR accept the shared helper's CTX_2001 and have NAPI/UniFFI match it — but the chosen convention for this op is CTX_2000, so PyO3 should conform.

LESSON (reinforces R2 lesson): when checking cross-bridge error-code parity, enumerate EVERY fail mode including the ones reached via `?`-propagation through shared helpers, not just the explicitly-written `.map_err` in the method body. The convenience helper `supervisor(bi)?` hides a per-bridge code choice (PyO3 CTX_2001 vs NAPI CTX_2000). Same trap as the R1/R2 `context()`-vs-explicit issue, one layer up.

Everything else SOUND: 11-field parity ×3 (identical order/names), NAPI i64 vs PyO3/UniFFI u64 (documented, idiomatic), event_log_root hex String ×3, format validation (shared scp_ffi_common::validate) ×3, anchored flag a named bool field, surface fully wired (matrix + bridge-aliases wasm-exempt + ffi-export-allowlist __repr__ + pipeline). SDK wrappers = #1943 Phase 2C-2 (out of scope). WASM removed (ADR-034, honestly exempted).
