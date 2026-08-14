---
name: mcp-1341-subscribe-adr015
description: SHIPPED state of #1341 (MCP resources/subscribe backed by Supervisor events) on branch fix/mcp-subscribe-honest — four earlier findings are now FIXED; only ADR-015 AC7 (dynamic tool list) and AC8 (Rust serve binary) remain genuinely open.
metadata:
  type: project
---

Branch `fix/mcp-subscribe-honest` (rebased on origin/main) landed #1341 and the
full-roster review fixes on top. This note records the SHIPPED end state — do not
report the fixed items as open.

**Origin:** the old seam let PyO3/UniFFI return `Ok(())` from `subscribe_resource`
and do nothing while `initialize` advertised `subscribe: true` (NAPI returned
`Err` — three-way divergence). That false guarantee is gone.

## FIXED on this branch (re-verify against code before re-citing as open)
- **`resources.subscribe` is honest and structural.** `McpServer::with_event_source`
  is the ONLY constructor that sets `event_source_wired`, and it returns the
  `#[must_use] ContextEventPump` in the same call. `resources.subscribe`,
  `resources.listChanged` AND `tools.listChanged` at `initialize` are all derived
  from `event_source_wired` (`crates/scp-mcp/src/server.rs` ~504-514) — the
  `tools.listChanged` hard-code is gone, not "still hard-coded."
- **`resources/read` and `resources/subscribe` share one real predicate.** The
  phantom `resource:{type}` capability is deleted; `ContextProvider::validate_resource_access`
  takes a typed `ResourceKind` (no string to synthesize `resource:` from) and each
  bridge answers it against `Capability::MessagesRead` (spec §5.3.1). Not
  "denied everywhere."
- **The SSE pump is owned, not leaked.** `sse_router` is deleted; `router_with_pump`
  is crate-private, returns the pump `JoinHandle`, and `run_sse` holds it in
  `stdio::AbortOnDrop` so it is aborted on bind error, graceful shutdown, AND
  cancellation-drop. `run_stdio` does the same via `serve_stdio`'s guard — this
  closed a real stdout-corruption leak (pump kept writing notifications after
  `mcp_server_stop`).
- **stdio tests drive the shipped loop.** `read_loop_from` (the loop `run_stdio`
  runs) is exercised directly through the `ClientChannel` seam — no duplicated
  `process_lines` copy. A cancellation test proves stop-while-stdin-open aborts
  the pump.
- **Transport pairing is unconstructable-by-type, not runtime-checked.**
  `McpServer::with_optional_event_source` returns one `McpServerForTransport`
  bundle (`Wired(server, pump)` / `Unwired(server)`) and `run_stdio`/`run_sse`
  take that bundle as a single atomic argument — a wired server without its pump
  cannot be built, so the former runtime `PumpServerMismatch` check is DELETED,
  not merely unused. Do not cite it.
- **Lagged receiver over-notifies, never silent.** On `broadcast Lagged`, both
  pumps emit `resources/list_changed` + `tools/list_changed` + one
  `resources/updated` per still-authorized subscription
  (`McpServer::lagged_resync_notifications`, re-authorized per URI so it is not
  an activity oracle; the two list-changed signals are content-free and thus
  deliberately not per-event auth-gated).

## Still genuinely OPEN (ADR-015 acceptance criteria, not regressions)
- **AC7 — dynamic tool list on join/leave.** `active_context_ids()` is a static
  `Vec` snapshot on all three bridges, and no `ContextEvent` variant exists for
  outlet registration, so "agent joins/leaves ⇒ tool list updates dynamically"
  cannot yet hold end-to-end. Real work, not a stub.
- **AC8 — `scp-mcp serve` CLI.** Still a Python console script
  (`bindings/python/pyproject.toml` → `scp_sdk.mcp:cli_main`), not a Rust binary.

Related: [[adr057_transport_wasm_surface_parity]] (same class — an embedder surface
present on one layer and absent on its mirror).
