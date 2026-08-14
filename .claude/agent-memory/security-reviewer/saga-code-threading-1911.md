---
name: saga-code-threading-1911
description: Security review of #1911 — §6.2.4 saga reject SCP-SAGA codes carried structurally (saga_reject! macro) instead of parsed from strings; PASS
metadata:
  type: project
---

# #1911 saga code structural threading (worktree saga-code-1911, HEAD 35be7185f) -- 2026-06-30 -- PASS / ZERO FINDINGS

Three-dot diff origin/main...HEAD: 4 files (commands.rs, handlers/saga.rs, actor/mod.rs, supervisor.rs).
Replaces message-string parsing (`saga_code_from_message`, now DELETED with zero residual refs) with a
structural `code: Option<u16>` carried on a new `SagaReject { code, error }` carrier.

**Crux (proceed-as-prepared) — SOUND.** `dispatch_xctx_prepare_a/_b` match `PrepareXOutcome`:
`Prepared(..)` sets `ctx.prepared_X` and returns `Ok(())`; `Rejected(SagaReject)` returns `Err(reject)`.
`ctx.prepared_X` is set ONLY on the Prepared arm, so a Rejected outcome HARD-aborts the FSM (Err →
run_saga_fsm Err arm) and Commit never runs. The move of policy rejects to `Ok(Rejected(..))` on the
mailbox SUCCESS channel is purely transport; the variant (not the code) gates success. `#[must_use]`
on PrepareAOutcome + the reservation carrier enforce the success path carries a real reservation.

**Code integrity — every authz code survives.** Authz rejects (13010/11/12/13/14/15/16/17/18/19/20/21/
25/26/27 in handlers; 13051/52/53 supervisor-axis) are built via `saga_reject!` with `code: Some(literal)`,
ride `Ok(Rejected)` (handlers) or propagate as `Err(SagaReject)` via `?` (supervisor lookups), reach
run_saga_fsm's `Err(rej)` arm → `RunSagaError{ saga_code: rej.code }` → `lift_run_saga_error` does
`code = saga_code.unwrap_or(13067)`. Specific code reaches SagaError::Aborted.code → bridge. NONE pass
through `From<ContextError> for SagaReject` (code:None over-capture) — that conversion is reachable ONLY
on bare-ContextError `?` infra paths (journal append/commit/mailbox-drop/30s phase timeout), which are
genuinely codeless and correctly lift to generic 13067.

**No regression vs old parser.** `reserve_tool_economy` (line 506) + persist failures (573/1021) ride
`Err(ContextError)` → 13067. tools_helpers.rs carries NO SCP-SAGA prefix, so old `saga_code_from_message`
also returned None→13067 for these. Same result. (Token-bucket ECON hard limit intentionally codeless;
§6.2.0.2 sliding-window saga rejects carry Some(130xx) — design-correct split.)

**needs_repair — unchanged.** `if needs_repair { return NeedsRepair }` short-circuits BEFORE `code` use;
commit-exhaustion `Err(err.into())` + `resolve_committed_or_needs_repair(..).map_err(SagaReject::from)`
both code:None, but needs_repair=true → lifts to 13065 regardless. Confirmed.

**No phantom-authz.** `saga_reject!` has 4 forms (PermissionDenied/InvalidState/ContextNotRegistered/
RateLimited), each requires a `$code:literal`; no SUCCESS variant exists. Macro derives BOTH the structural
`code` AND the `SCP-SAGA-{code}:` message prefix from ONE literal → can't drift (stronger than before).
New test `lift_reads_saga_code_structurally_not_from_message` pins: structural code wins over a bogus
message token; None+code-bearing-message still →13067 (proves no parse reintroduced).

**Leakage:** messages format same content as before (DIDs, tool ids, retry secs — not secrets).
**Bridge `decompose_saga_error`:** unchanged, reads `code` structurally — no new trust assumption.

OBSERVATION (non-blocking, not an authz code): `misrouted()` builds InvalidState "SCP-SAGA-13038"
(router-partition-invariant, statically UNREACHABLE) and rides Err→13067 structurally while message
keeps the 13038 token. Old parser would have surfaced 13038 in `code`. Immaterial: unreachable
internal-bug branch, not in the authz inventory; human-readable message still carries the token.
