# UniFFI Handle Reference Counter and Shutdown Ordering

**Context:** SCP-078 — UniFFI async bridging and Rust scaffolding.

## Problem

If the Rust tokio runtime is dropped while Swift or Kotlin objects still hold FFI
handles (`Identity`, `ContextHandle`, etc.), those objects attempt to call into a
dead runtime. This causes panics or undefined behavior on the calling thread.
UniFFI's generated bindings do not provide any built-in shutdown coordination.

## Solution

Add a global `AtomicUsize` reference counter (`HANDLE_COUNT`) in `lib.rs`. Every
opaque FFI handle type increments it on construction and decrements it in `Drop`.
Export a `scp_shutdown(timeout_secs)` function that polls until the counter reaches
zero (or the timeout elapses) before returning. Swift/Kotlin call this before
tearing down the library.

## Implementation Rules

1. **Increment after `Arc::new()` succeeds, not before.** If you increment first
   and then `Arc::new()` fails (OOM), you have an unmatched increment. Place
   `increment_handle_count()` inside the `spawn(async move { ... })` closure,
   after the `Arc::new(...)` call, before returning `Ok(handle)`.

2. **Decrement in the struct's own `Drop`, not `Arc`'s.** UniFFI wraps opaque
   objects in `Arc`. The struct's `Drop` is called when the last `Arc` reference
   is released — exactly when the FFI handle becomes unreachable. Do not try to
   intercept `Arc`'s drop.

3. **Use `Ordering::Relaxed` in production, `Ordering::SeqCst` in tests.** The
   counter only needs to reach zero eventually — it does not synchronize any other
   memory. `Relaxed` is correct and lower overhead. Tests that check the exact
   value across thread boundaries should use `SeqCst` for visibility guarantees.

4. **Zero timeout short-circuits.** `scp_shutdown(0)` returns immediately. This
   lets callers opt out of waiting (e.g., in process exit hooks where the OS
   reclaims memory anyway).

5. **Export via `#[uniffi::export]`.** The shutdown function must be exported so
   Swift and Kotlin can call it. Define it in `lib.rs` alongside the counter; do
   not put it in `bridge.rs` (that module is for domain bridge functions, not
   library lifecycle).

## InMemoryKeyCustody in [dependencies] vs [dev-dependencies]

`identity_create("in_memory")` uses `scp_platform::testing::InMemoryKeyCustody`,
which requires the `testing` feature of `scp-platform`. This feature belongs in
regular `[dependencies]` (not just `[dev-dependencies]`) for the `scp-ffi-uniffi`
crate because the in-memory path is a first-class, documented code path for:

- Unit and integration tests
- CLI tools
- Desktop (non-mobile) builds
- Developer onboarding (zero config identity creation)

The doc comment on `identity_create` warns that `"in_memory"` stores key material
in unprotected heap memory and is not safe for production mobile deployments. The
`"platform"` and `"software"` custody paths return `ScpError::Identity` pointing
callers to the `KeyCustodyProvider` callback interface until that story is wired.

**Do not move `testing` back to dev-dependencies** to "prevent production use" —
that prevents all non-mobile use cases too and breaks the conformance tests that
run in the regular build.

## Thread-Safety Doc Comments on Callback Interfaces

All `#[uniffi::export(callback_interface)]` traits must include a `SAFETY:` doc
comment explaining that UniFFI executes callbacks on Rust tokio threads, not the
Swift/Kotlin main thread. Template:

```rust
/// # SAFETY: Thread execution context
///
/// UniFFI callbacks execute on Rust tokio threads, NOT the Swift/Kotlin main
/// thread. All implementations MUST be thread-safe (`Send + Sync`) and MUST
/// NOT assume main-thread execution. Any UI or main-thread-only operations
/// MUST be dispatched explicitly:
///
/// - **Swift:** `await MainActor.run { /* UI update */ }`
/// - **Kotlin:** `withContext(Dispatchers.Main) { /* UI update */ }`
///
/// See sdk-common.md §"FFI Async Bridging Risks" rule 2.
```

## Reference

- `sdk-common.md` §"FFI Async Bridging Risks" — rules 2 and 4
- ADR-021 acceptance criteria 1 and 14
- `crates/scp-ffi/uniffi/src/lib.rs` — `HANDLE_COUNT`, `scp_shutdown`
- `crates/scp-ffi/uniffi/src/bridge.rs` — `Drop` impls, constructor increments
