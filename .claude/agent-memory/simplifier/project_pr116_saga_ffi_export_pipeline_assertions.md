---
name: pr116-saga-ffi-export-pipeline-assertions
description: #116 saga FFI export (feat/116-ffi-saga-export) — saga_errors.rs consolidation + 3 pipeline_wiring assertions are convergent/bounded, NOT BLOCKER
metadata:
  type: project
---

Branch `feat/116-ffi-saga-export` (#116 PR-6b) exports `tool_invoke_cross_context_saga` across PyO3/napi/UniFFI. Reviewed for over-engineering — **clean, no BLOCKER**.

**Why this matters:** Future saga/FFI-export reviews will see the same shapes; pre-judging them as non-convergent would be wrong.

**How to apply:**
- `crates/scp-ffi/common/src/saga_errors.rs` = single home of `SagaError` decomposition (`decompose_saga_error` → `SagaErrorParts`/`SagaErrorKind`). The 3 `map_saga_error` tails (PyO3 tools.rs:964, napi tools.rs:684, uniffi bridge.rs:5425) are IRREDUCIBLE: distinct typed enums (ScpPyError/ScpNapiError/ScpError), only diff = `message:` vs `msg:` field label. Same pattern as [[project_pr116_saga_export_consolidation]] map_saga_error rule — do NOT flag as dup.
- The 3 new pipeline_wiring assertions (pipeline_wiring.rs:2315/2361/2405) are POSITIVE BOUNDED wiring checks ("export body calls enforce_caller_principal_binding + context_id_to_bytes + start_cross_context_tool_invocation_saga"), following established `c4_*_routes_through_*` / `*_routes_to_core_*` pattern. NOT type-redundant: nothing forces the export to route ids through `context_id_to_bytes` (raw Sha256 also typechecks to [u8;32] and double-hashes) or to call the saga producer at all. Net-new assertions for a net-new op, single revision = convergent by construction.
- `enforce_caller_principal_binding` helper duplicated across bridges (sync-vs-async, distinct enum/BridgeInstance) — same per-SDK-idiom constraint (ADR-048 §7) as map_saga_error; only the long error-message LITERALS are byte-identical (PyO3/napi). Extracting them to common = marginal (~12 lines), leaned-against not pushed.
