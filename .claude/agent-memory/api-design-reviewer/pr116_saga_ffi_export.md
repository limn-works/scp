---
name: pr116-saga-ffi-export
description: PR #116 tool_invoke_cross_context_saga FFI export across PyO3/NAPI/UniFFI — API design APPROVED, no findings
metadata:
  type: project
---

# PR #116 — `tool_invoke_cross_context_saga` FFI export (3 bridges)

APPROVED, zero findings. Reviewed at HEAD `3afc30c6c` (read-only worktree ffi-saga-116).

**Why:** §6.2.4 cross-context tool-invocation saga, exported as a distinct op (synchronous `tool_invoke_cross_context` coexists). Slice 6b of #105 PR-6. SDK wrappers deferred to 6c #117 (correctly out of this PR's scope).

**How to apply (design facts confirmed, reuse for #117 SDK-wrapper review):**
- Flat named-field shape IDENTICAL across all 3 bridges (9-10 args, `#[allow(clippy::too_many_arguments)]` with "agent-first named params, no builder" justification on every site). PyO3 takes string ids; NAPI/UniFFI take `ContextHandle` (instance-affine, gives extra PERM-3030 pre-check). That variance is the established string-id-vs-handle bridge idiom, not divergence.
- `saga_id` is OUTPUT-ONLY on `*SagaResult` (PyO3 `PySagaResult` / NAPI `NapiSagaResult` / UniFFI `SagaResult`), doc'd "supervisor-minted, never a caller input" on every bridge. Cannot be passed in — correct misuse resistance.
- Nonce = one canonical form: 32-char hex → `[u8;16]`, fail-closed, `decode_asserted_nonce` in all 3 with identical messages + `VALID_7001`. No pad/truncate.
- Caller principal-bound: `enforce_caller_principal_binding` runs BEFORE saga (registry-hosted + is_member), mismatch ⇒ `Rejected`-flavored SagaAborted `SCP-SAGA-13050`. Rustdoc has explicit "Trust boundary (co-resident single-tenant only)" + multi-tenant warning + cross-node forward obligation — strong threat-model doc.
- Typed terminal error surface: dedicated SagaAborted/SagaNeedsRepair/SagaBusy variants on each bridge enum. Structured data carried STRUCTURALLY: `retry_after_ms: Option<u64>` (None NEVER coerced to 0), `saga_id`, `contended_context`. Codes 13050/13065/13066 + inline `SCP-SAGA-{numeric}` for Aborted.
- Per-bridge surfacing differs by language constraint, all best-available: PyO3 = exception `args[2]` (structured); UniFFI = enum fields (`msg:` label per UniFFI convention); NAPI = message suffix `(retry_after_ms=null)` / `(saga_id=…)` / `(contended_context=…)` because napi-rs collapses every error to a single string `napi::Error` — field stays Option<u64> in the Rust variant, rendered by thiserror Display only at the boundary, never re-parsed. TS test pins the `null` rendering.
- `decompose_saga_error` (common/saga_errors.rs) is the SINGLE classification home; each `map_saga_error` is a thin 3-arm match. Public error surface unchanged by the decompose refactor (only map_saga_error bodies route through it). Mirrors the ucan_errors drift-prevention pattern. WASM excluded (no Supervisor, ADR-034).
- bridge-aliases.json entry added (all 3 = canonical name, no alias). New SAGA_13050/13065/13066 constants in common/error_codes.rs, band 13000-13999.
