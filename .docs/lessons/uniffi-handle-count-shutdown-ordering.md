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

**ADR-062, capability injection and prove-absent dev backends, reversed the
guidance this section originally gave.** The original text argued that
`scp-platform/testing` belongs in the `scp-ffi-uniffi` crate's regular
`[dependencies]`, so that a desktop or CLI build could create an identity with
zero configuration. ADR-062 Slice 6 rejected that argument: `InMemoryKeyCustody`
is a nullifier, so a shipped artifact must not resolve it at all. Read the rest
of this section as the record of a decision that no longer holds, and follow the
paragraph below it.

`identity_create("in_memory")` uses `scp_platform::testing::InMemoryKeyCustody`,
which requires the `testing` feature of `scp-platform`. `crates/scp-ffi/uniffi/Cargo.toml`
now names that edge in two places and neither one reaches a shipped build: the
crate's own `testing` feature adds `scp-platform/testing`, and `[dev-dependencies]`
adds it for the test binaries. The regular `[dependencies]` entry names
`software_platform`, `file`, `encrypting`, and `sqlite`, and no `testing`, so a shipped
build returns `SCP-IDENT-1008` for `"in_memory"` instead of creating an identity.
`scripts/check-shipped-feature-graph.sh` fails the build when a shipped artifact's
resolved feature set contains `scp-platform/testing`.

The `"platform"` and `"software"` custody strings name no custody value, so they
return `ScpError::Validation` carrying `SCP-VALID-7005`, the code every string
outside the vocabulary returns; `SCP-IDENT-1003` is what `"os_keystore"` returns
when the bridge holds no `KeyCustodyProvider`. §3.2.2 of `.docs/specs/03-identity.md`
states the vocabulary. That behaviour is permanent, not a waiting state: `identity_create_with_custody` is exported on all three bridges, and
passing a `KeyCustodyProvider` to it is the only path to Apple Keychain or Android
Keystore. No custody string reaches either key store on any bridge.

**Do not move `scp-platform/testing` into the regular `[dependencies]` table** to
restore zero-configuration identity creation. A shipped build that resolves that
feature reaches a nullifier on a production path, which the builder tenet "No
dev/test-only stand-ins in production" forbids and the shipped-feature-graph gate
rejects.

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
