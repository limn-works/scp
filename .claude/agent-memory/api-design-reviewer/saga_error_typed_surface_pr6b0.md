---
name: saga-error-typed-surface-pr6b0
description: API review of public SagaError/SagaAbortReason typed error returned by Supervisor::start_cross_context_tool_invocation_saga (PR-6b0, commit 7955003da) — APPROVED
metadata:
  type: project
---

PR-6b0 (commit 7955003da) introduces public typed error `SagaError` + `SagaAbortReason` in `crates/scp-runtime/src/context/supervisor/supervisor.rs`, replacing `ContextError` as the return of `start_cross_context_tool_invocation_saga`. Surface the FFI bridges (PR-6b) map to ADR-049 §3a `SCP-SAGA-*` taxonomy.

**Verdict: APPROVED — agent-first sound.** A bridge author can write an exhaustive 3-arm match (Aborted/NeedsRepair/Busy) + 2-arm nested match (RateLimited/Rejected) from the signature + doc, no compile-retry loop. Every non-Ok terminal forced by exhaustive match.

Key design points validated:
- `retry_after_ms` reaches the bridge STRUCTURALLY: `ContextError::RateLimited.retry_after_ms: Option<u64>` (scp-protocol/src/context/mod.rs:385) → `SagaAbortReason::RateLimited { retry_after_ms: u64 }`, no string parse. This is the whole point and it holds.
- `code: u16` on `SagaError::Aborted` is populated by core-side `saga_code_from_message` parse-ONCE-in-core (supervisor.rs ~10954). Bridge reads typed code, never re-parses. Defensible: parsing happens in core not bridge; matches the "parse once" goal.
- Reachability: `scp-core/src/lib.rs:96` re-exports whole `supervisor` module; `SagaError`+`SagaAbortReason` on supervisor/mod.rs:145, `SagaId` on :130. All nameable via `scp_core::context::supervisor::*`.
- Sibling `start_saga` (supervisor.rs:5308) still returns `ContextError` — it's documented test-only/misuse-only for cross-context input. Dedicated `SagaError` only on the real public entry point. Consistent, not a regression.

Minor observations (non-blocking):
- `contended_context: String` is a hex context id — same untyped representation contexts use everywhere in supervisor (caller_hex/target_hex). Consistent with codebase; typed ContextId newtype doesn't exist at this layer.
- `code: u16` exposes a raw numeric discriminant on the public surface. Acceptable here because the §3a taxonomy IS numeric SCP-SAGA-13xxx codes — the bridge's job is to map to those exact numbers. Not an anti-pattern in this specific mapping-layer context.
- `message: String` redundant with `Display` (which re-embeds code+message) but standard for thiserror structured errors; gives bridges the human detail without Display parsing.

Re-confirmed at HEAD 4e5d5cfc8 (rebased). Two additional observations:
- **code-field asymmetry**: only `Aborted` carries an explicit `code: u16` field; `NeedsRepair`(13065)/`Busy`(13066) embed their fixed codes ONLY in Display, not as fields — a bridge must hardcode those two while reading Aborted's `code` structurally. Defensible (variant==discriminant for those two; Aborted multiplexes ~10 sub-codes) but worth #120's structural-code follow-up.
- `SagaId` is `pub struct SagaId(pub String)` (saga_journal.rs:79) — bridges rendering `NeedsRepair.saga_id` reach `.0`; tuple-struct access is a minor LLM-authorability papercut vs a named field. Same .0 already applies to `SagaOutput.saga_id`, so consistent.
