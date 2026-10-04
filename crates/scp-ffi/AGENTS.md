# scp-ffi — the three FFI bridges

This directory holds the PyO3 bridge (`src/`, the Python `_scp_core` module and the reference bridge), the napi-rs bridge (`napi/`, the `@limn-works/scp-ts-napi` addon), the UniFFI bridge (`uniffi/`, Swift and Kotlin), and the logic they share (`common/`). Every bridge delegates context lifecycle to the shared `Supervisor` from `scp-runtime`; a bridge adds FFI state, never a second copy of supervisor state.

## Rules for every bridge

- **State is per bridge instance.** Every registry, allowlist, storage slot, and resolver lives on the bridge instance (`PyBridgeInstance`, `NapiBridgeInstance`, and the UniFFI equivalent, with shared fields in `common/src/bridge_instance.rs`). A process-global lets one tenant change another's policy (`.docs/lessons/process-global-policy-state-is-realm-local-rce.md`); `check-no-bridge-globals.sh` rejects one.
- **Validators live in `scp-ffi-common`.** A bridge's local validator delegates to `scp_ffi_common::validate::validate_X` and maps the error, as `src/validate.rs` does. Never reimplement a validator in a bridge.
- **Authorization lives in the Supervisor.** `context_close` performs no bridge-layer check; `Supervisor::close_context` checks the `ContextClose` capability. Do not add a second check in a bridge.
- **Storage fails closed.** A storage selection names `in_memory` explicitly or names `sqlite` with exactly one of `key` and `passphrase`; a failed SQLCipher open returns an error and never degrades to in-memory. `DurableProviders::from_handle` derives the saga journal and the MLS storage from one storage handle, so they share one backend by construction. The supervisor build fails when no storage was selected first.
- **Registry closures must not nest `block_on`.** `with_identity` and `with_context` are synchronous closures over a `DashMap` entry. When the work inside is async, call `rt.block_on(async { … })` once inside the closure; a nested `block_on` deadlocks tokio.
- **Never hold a `MutexGuard` across `.await`.** Scope the lock and copy what the async code needs.

## tokio locks by caller

`blocking_lock()` panics with "Cannot block the current thread from within a runtime" on a tokio worker thread, and creating a second runtime or calling `block_on` inside `#[tokio::test]` panics the same way. Code reached from the transport layer or an actor runs on the runtime, so a synchronous lock there panics in production while a unit test that calls the function from a plain thread passes.

| Caller | Use |
|---|---|
| async code on the runtime | `.lock().await` |
| sync code that may run on a runtime thread | `.try_lock()`, and handle contention |
| sync code on a thread the runtime does not own, such as a Python or FFI caller thread | `.blocking_lock()` |
| `#[tokio::test]` | the test's own runtime; never create a second one inside it |

`deliver_message` in `src/runtime.rs` takes `blocking_lock()` on purpose to keep oldest-drop overflow semantics, because `try_lock()` would drop the new message under contention. That choice is sound only while every caller of `deliver_message` runs off the runtime's worker threads.

## PyO3 (`src/`)

- `cargo test -p scp-ffi` links libpython; the root `AGENTS.md` Toolchain gotchas give the library-path setup. `cargo check -p scp-ffi` compiles without it. Never skip these tests.
- `FfiBridgeState.role_state` is a local copy that MCP's `held_role_state` in `src/mcp.rs` reads when no Supervisor is attached. After any governance action that changes roles or membership, call `runtime::sync_role_state_from_manager` so the copy matches the Supervisor.
- A bridge function that returns a dict is read in Python as `h["key"]`, not `h.key`. Return a `#[pyclass]` for a new structured result.
- The MCP stdio client accepts only bare binary names on the instance's allowlist; it rejects every path, even in unrestricted mode, to block basename spoofing.
- An outlet handler that times out keeps its thread running until the handler returns, because Rust cannot cancel a thread; the design rejects cooperative cancellation (see the doc comment on `invoke_outlet` in `src/mcp.rs`).

## napi-rs (`napi/`)

- `identity_execute_recovery` and `identity_execute_custody_migration` are synchronous napi entry points that drive the async orchestrator with `runtime().block_on`, because the napi-rs worker thread has no tokio context. Do not make them `async fn`. Before the orchestrator runs they check, in order, that this instance owns the DID, that the context list is within its cap, and that a recovery permit is free; an exhausted permit returns `SCP-VALID-7140` at once rather than queueing, since a queued wait would pin a libuv worker.
- UCAN validation state (revocation lists, nonce trackers) lives in the bridge's own registry, not in the Supervisor.
- `cargo test -p scp-ffi-napi` needs no Python linkage. `bindings/typescript/AGENTS.md` covers how napi values reach JavaScript.

## UniFFI (`uniffi/`)

- `scp.udl` is a namespace anchor only; proc-macros (`#[uniffi::export]`) define every type and function.
- Opaque objects (`Identity`, `ContextHandle`, `UcanToken`, `TransportManager`) are `Arc`-wrapped with manual handle counting in `lib.rs`; each `Drop` decrements the count.
- `cargo test -p scp-ffi-uniffi` needs no Python linkage. Generate bindings with `cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate …`; `bindings/swift/AGENTS.md` covers the committed Swift output.
