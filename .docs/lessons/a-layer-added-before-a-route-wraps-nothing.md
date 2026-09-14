# A Layer Added Before a Route Wraps Nothing

**Date:** 2026-08-25
**Source:** review of pull request #2373, the bridge-handler authorization scope change,
`crates/scp-node/src/bridge_handlers.rs`

## The bug

`bridge_router` built its router this way:

```rust
Router::new()
    .layer(axum::extract::DefaultBodyLimit::max(MAX_BRIDGE_BODY_BYTES))
    .route("/v1/scp/bridge/shadow", post(create_shadow_handler))
    // four more routes
```

Axum applies `Router::layer` to whichever routes the router already holds, and adds nothing to a
route registered afterwards. Its own documentation states the rule: "Note that the middleware is
only applied to existing routes. So you have to first add your routes (and / or fallback) and then
call `layer` afterwards. Additional routes added after `layer` is called will not have the
middleware added."

`Router::new()` holds no routes, so the limit wrapped zero handlers. All five bridge routes ran
under axum's own 2 MiB default, which is eight times the 270,336-byte bound the constant names.
The doc comment above that constant said "a body far above it is refused before a node buffers it",
which no request ever experienced.

## Why the test missed it

The route's own test posted `MAX_MESSAGE_CONTENT_BYTES + 1` bytes and asserted 400. That body is
262,145 bytes, which sits under axum's 2 MiB default, so the handler received it and answered 400
whether or not the layer applied. A test that lands between the intended bound and the fallback
bound cannot distinguish the two.

## The invariant

A test for a limit must send a body that only the intended limit rejects. Two assertions state it:

1. A body one byte over the intended limit answers 413, and
2. a body exactly at the intended limit reaches the handler.

The first assertion fails when the layer is absent or misplaced. The second fails when the layer
rejects everything. Neither one alone pins the threshold.

## The general shape

A configuration value that silently falls back to a framework default produces a defect nothing
reports: no error, no warning, no failing test — the request succeeds, under the wrong bound. Ask
of every limit, timeout, and middleware in a builder chain: what does the code do when this value
never takes effect, and would any assertion notice? When the answer is "it keeps working under a
default", write the assertion that separates the two.

## Related

- `crates/scp-node/src/dev_api.rs` places its `DefaultBodyLimit` after every `route` call, which is
  the ordering this fix adopted.
