---
name: mcp-1341-subscribe-adr015
description: Review of #1341 (MCP resources/subscribe backed by Supervisor events) — what was complete, and the ADR-015 cells still empty (tools.listChanged still hard-coded, resources/read denied everywhere, AC7/AC8 unmet)
metadata:
  type: project
---

Branch `fix/1341-f4-mcp-subscribe-honest` (dc64f3432, 0ae8889c9) made
`resources.subscribe` a *derived* advertisement (`subscribe: self.subscriptions_enabled`)
sourced from `Supervisor::subscribe_events()` through `run_stdio`/`run_sse` on all three
bridges, and deleted `ContextProvider::subscribe_resource`.

**Why:** the old seam let PyO3/UniFFI return `Ok(())` and do nothing while `initialize`
advertised `subscribe: true` — a false guarantee; NAPI returned `Err` (three-way divergence).

**How to apply (durable findings — re-verify before citing):**
- The same false-guarantee shape survives one field over: `crates/scp-mcp/src/server.rs`
  hard-codes `tools: Some(ToolServerCapability { list_changed: true })` while the ONLY
  emitter of `notifications/tools/list_changed` is `notifications_for_event`, driven
  solely by the pump. No pump ⇒ advertised-but-never-sent. Fix is the same one-flag
  derivation used for subscribe.
- `handle_resources_subscribe` authorizes on *membership only*; `handle_resources_read`
  authorizes on `validate_capability("resource:{type}")`. That capability name is never
  registered as an outlet on ANY bridge, so `resources/read` is unconditionally
  CAPABILITY_DENIED — subscribe now pushes updates for resources nobody can read.
  Same reason `tools/list` never lists the ADR-015 AC1 built-ins on PyO3/UniFFI.
- `active_context_ids()` is a static `Vec` snapshot on all three bridges ⇒ ADR-015 AC7
  ("agent joins/leaves a context ⇒ tool list updates dynamically") cannot hold, and no
  `ContextEvent` variant exists for outlet registration.
- ADR-015 AC8's `scp-mcp serve` CLI is a Python console script
  (`bindings/python/pyproject.toml` → `scp_sdk.mcp:cli_main`), not a Rust binary.
- `scp_mcp::sse::sse_router` has zero non-test callers and drops the pump `JoinHandle`,
  detaching a task that pins `Arc<AppState>`.
- stdio tests exercise a duplicated `process_lines` copy, not `read_loop`/`pump_events`.

Related: [[adr057_transport_wasm_surface_parity]] (same class — an embedder surface
present on one layer and absent on its mirror).
