---
name: dashmap-ref-across-await
description: Never hold a DashMap Ref (from context_handle_registry().get()) across an async lock/.await in the UniFFI bridge — clone the Arc out first. clippy await_holding_lock and the type system both miss it.
metadata:
  type: feedback
---

In the UniFFI bridge (`crates/scp-ffi/uniffi/src/bridge.rs`), `context_handle_registry(bi).get(id)` returns a `dashmap::mapref::one::Ref` holding a **parking_lot shard read-lock** for the lifetime of the binding. NEVER hold that `Ref` across an `.await` (e.g. awaiting `handle.tool_handlers.lock()`).

**Why:** The Ref holds a shard read-lock; `deregister_context_handle` (`context_close`/`context_leave`) calls `DashMap::remove`, taking the shard WRITE lock and synchronously parking a runtime worker until readers drop. If a saga/op is suspended at an `.await` while holding the Ref, a concurrent close on a same-shard context stalls a worker; parking_lot writer-priority then also stalls fresh readers. clippy's `await_holding_lock` does NOT recognize a DashMap Ref, and it's `Send` so the type system compiles it — both miss the hazard. Tests pass because they don't contend the shard.

**How to apply:** Clone the owned `Arc<ContextHandle>` out of the Ref, drop the Ref, THEN await:
```rust
let h = context_handle_registry(&bi).get(&ctx_id).map(|e| Arc::clone(e.value()));
let handler = match h { Some(h) => h.tool_handlers.lock().await.get(&tool_id).cloned(), None => None };
```
This matches the safe sibling pattern (`tool_invoke`/`tool_invoke_cross_context` take an owned `Arc<ContextHandle>` and never hold a Ref across the lock). Caught by bug-catcher on FFI task #116 Slice C — the hazard came from translating the PyO3 reference, where `with_context` snapshots synchronously over a plain HashMap (no lock across await). Note: switching the method to take typed handle params (see [[typed-bindings-use-handles]]) makes the handle directly available and dissolves this hazard at the source.
