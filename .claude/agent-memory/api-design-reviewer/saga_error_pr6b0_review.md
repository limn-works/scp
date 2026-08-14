---
name: saga-error-pr6b0-review
description: SagaError/SagaAbortReason typed terminal surface (PR-6b0, HEAD 3630e578d) — APPROVED; code:u16 vs typed reason divergence deferred to #1911
metadata:
  type: project
---

# SagaError / SagaAbortReason typed terminal surface (PR-6b0, HEAD 3630e578d)

Reviewed the public `SagaError`/`SagaAbortReason` enums in `crates/scp-runtime/src/context/supervisor/supervisor.rs`, re-exported from `supervisor/mod.rs:141`. Verdict: APPROVED.

**Why:** This is the typed §6.2.4 saga terminal space the native FFI bridges will `match` (later PR) — replacing message-string parsing with structural fields per the agent-first API tenet + ADR-049 §3a.

**How to apply:** When the bridge-mapper PR lands, verify the `code: u16` concern below got resolved as a *type* change (#1911), not left as a raw integer.

## Surface
- `SagaError` (supervisor.rs:353): `Aborted{reason: SagaAbortReason, code: u16, message}` / `NeedsRepair{saga_id: SagaId, message}` / `Busy{contended_context: String, message}`. Derives Debug, Clone, PartialEq, Eq, thiserror::Error.
- `SagaAbortReason` (supervisor.rs:393): `RateLimited{retry_after_ms: Option<u64>}` / `Rejected`. Derives Debug, Clone, PartialEq, Eq.
- `SagaOutput` (supervisor.rs:309) gains Clone, PartialEq, Eq.

## Strengths confirmed
- Neither enum is `#[non_exhaustive]` — bridge `match` is compiler-forced total (agent-first win).
- `RateLimited.retry_after_ms` Option: `None`=token-bucket hard limit (no refill instant), `Some(ms)`=sliding-window cooldown. Explicitly NEVER coerced to 0 (0 reads as "retry now" and re-trips limit). Trap actively avoided.
- Re-export sits with SagaInput/SagaOutput/SagaSigningKeys/SagaId/SagaDivergenceRepairRecord — one `Saga`-prefix autocomplete family.
- Private `RunSagaError` (FSM-internal ContextError+flag) correctly NOT exported.
- `SagaError` returned ONLY by `start_cross_context_tool_invocation_saga`; Committed⇒Ok(SagaOutput)/non-committed⇒Err split is type-enforced.

## The one real concern (deferred to #1911)
`Aborted.code: u16` is primitive-obsession on a public field. Derived 3 ways: inline literals (`code: 13050` @5460, `code: 13062` @5487) + `saga_code_from_message(&message).unwrap_or(13067)` (@5622). `saga_code_from_message` (@11046) re-parses the `SCP-SAGA-` prefix out of a string — the exact anti-pattern the typed surface exists to kill (now done once in core, but result is still stringly-sourced u16). Two fields (`reason` + `code`) both encode "what kind of abort" and the type permits any (reason,code) pairing → mapper can key inconsistently. #1911 tracks structural code; when it lands it'll be a BREAKING type change to every bridge that matched the integer — so bridges should NOT be written against the raw u16 in the interim. Also: NeedsRepair/Busy have NO code field (hardcode SCP-SAGA-13065/13066 in Display only) — consider uniform typed code across all 3 terminals under #1911 so bridges never Display-parse.
