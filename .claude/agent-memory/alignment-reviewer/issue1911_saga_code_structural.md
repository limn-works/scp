---
name: issue1911-saga-code-structural
description: Issue #1911 — §6.2.4 saga FSM carries SCP-SAGA-* codes structurally via saga_reject! macro, deletes saga_code_from_message. ALIGNED at 875ee615e.
metadata:
  type: project
---

Issue #1911 (follow-up to PR-6b-0 typed SagaError) review @ worktree saga-code-1911 HEAD 875ee615e — **ALIGNED, 0 findings**. Three-dot diff origin/main...HEAD = 4 files in scp-runtime only (commands.rs, actor/handlers/saga.rs, actor/mod.rs, supervisor/supervisor.rs).

**What changed:** new `SagaReject { code: Option<u16>, error: ContextError }` carrier + `saga_reject!(CODE, Variant, fmt, args)` macro (commands.rs) that synthesizes BOTH `code: Some(CODE)` AND the message prefix from ONE literal via `concat!("SCP-SAGA-{}: ", $fmt)` — typed field and string cannot drift. New `PrepareAOutcome`/`PrepareBOutcome` enums let a POLICY reject ride the mailbox SUCCESS channel as `Ok(Rejected(SagaReject))` (the `send` reply is hardcoded `Result<T, ContextError>`, can't carry a code on `Err`). `From<ContextError> for SagaReject` → `code: None` for codeless infra `?` paths. `RunSagaError` gained `saga_code: Option<u16>`; `lift_run_saga_error` now `saga_code.unwrap_or(13067)` — **deleted `saga_code_from_message` string-parse**.

**Verified all 20 Prepare-axis codes preserved (each macro literal === origin/main embedded code):** actor 13010,13011,13012,13013,13014,13015,13016,13017,13018,13019,13020,13021,13023,13024,13025,13026,13027 (17; 13022 never existed); supervisor 13051,13052,13053 (3). RateLimited arm preserves `resource` + `retry_after_ms`. Macro byte-format identical to old `format!`.

**Untouched-scope confirmed:** commit-phase NeedsRepair codes 13030-13064 still embedded in message strings (NeedsRepair lifts to 13065 structurally via decompose; needs_repair branch returns BEFORE consulting saga_code). Gate rejects 13050/13062 (`is_member`/`has_established_tool_interface` authorize-before-reserve at supervisor.rs:5515,5542) were ALREADY structural `SagaError::Aborted{code}` and are untouched (13050/13062 only appear in diff as the new test's DECOY tokens). decompose_saga_error (scp-ffi/common) NOT in diff; no scp-ffi/bindings files in diff → bridge output byte-identical. No #NNNN in source/comments/test-names. All remaining raw `SCP-SAGA-130xx` literals are `#[cfg(test)]` `m.contains(...)` assertions (correct — prefix still emitted).

**Strong test:** `lift_reads_saga_code_structurally_not_from_message` uses a VALID-u16 decoy token (13050≠13013) in the message — a reintroduced parse would recover 13050 and fail the assert. Decoy chosen as valid-u16 deliberately (99999 would overflow→None→pass for wrong reason).
