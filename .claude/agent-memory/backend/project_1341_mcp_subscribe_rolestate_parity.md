---
name: project-1341-mcp-subscribe-rolestate-parity
description: #1341 MCP subscribe fix — the FFI role_state mirror vs Supervisor split is the real AC4 parity defect; PyO3/napi MCP test fixtures never create Supervisor contexts (register_context populates the mirror only)
metadata:
  type: project
---

Branch `fix/1341-f4-mcp-subscribe-honest` made `resources.subscribe` honest by deriving
every MCP capability flag from `event_source_wired`, set only by
`McpServer::with_event_source` which also yields the `#[must_use] ContextEventPump`.
Advertisement and delivery are one value from one call — no setter can desynchronize them.
The unwired rejection is ONE shared fn (`reject_if_subscriptions_unwired`,
`crates/scp-mcp/src/server.rs`) returning `METHOD_NOT_FOUND`, so bridge parity for the
*subscribe* surface is structural, not conventional.

**The residual AC4 defect is one layer down.** The fix introduced
`ContextProvider::validate_resource_access`, implemented three times over TWO sources of truth:
- UniFFI queries the authoritative Supervisor (`role_state_of` → `block_in_place` +
  `Handle::current().block_on` + `QueriesCommand::GetRoleState`).
- PyO3 + napi read the bridge-local `FfiBridgeState::role_state` MIRROR.

**Why it matters:** `notifications_for_event` re-runs this predicate on every emission
precisely so a revoked member stops getting `notifications/resources/updated`. On the
mirror-reading bridges delivery continues until someone calls
`runtime::sync_role_state_from_manager` (19 callers; `crates/scp-ffi/CLAUDE.md` documents
the staleness explicitly). Same split affects `active_context_ids` and `agent_role`.

**How to apply — traps found while fixing this:**
- `crates/scp-ffi/**` is WHOLLY EXCLUDED from `scripts/check-block-in-place.py`
  ("sync bindings require a sync-async bridge at the FFI boundary"). Adding
  `block_in_place`/`block_on` in the bridges does NOT trip that gate — don't assume it does.
- PyO3's `setup_test_context` / napi's equivalents call `crate::runtime::register_context`,
  which populates the FFI mirror ONLY — it does NOT create a Supervisor context. So
  `GetRoleState` legitimately returns `None` and any test moved onto the authoritative path
  fails with empty/None until the fixture calls
  `supervisor.create_context(id, params, DID(creator), None).await`. UniFFI's tests already
  do this — copy their shape.
- `ContextParams::default()` has an EMPTY `ceiling`. The creator is auto-assigned `admin`
  and `builtin_admin`'s capabilities ARE the ceiling, so an empty ceiling grants the creator
  NOTHING and every resource check correctly denies. Fixtures needing `messages:read` must
  name an explicit ceiling. (Recorded in commit 25b6f91f5.)
- Provider trait methods are sync; `block_in_place` needs a multi-thread runtime, so tests
  must be `#[tokio::test(flavor = "multi_thread")]`.
- Error-shape parity was also broken three ways: PyO3 emitted
  `[SCP-CTX-2001] context error: …`, napi `[SCP-TRANS-5012] context error: …` (a transport
  code wearing a context label), UniFFI a bare message. The bare form is correct for a
  JSON-RPC wire message — the JSON-RPC `code` already carries the classification.

Related: [[feedback-check-scripts-need-cargo-target-dir]]
