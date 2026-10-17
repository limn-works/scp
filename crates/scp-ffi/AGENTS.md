# scp-ffi — the three FFI bridges

This directory holds the PyO3 bridge (`src/`, the Python `_scp_core` module and the reference bridge), the napi-rs bridge (`napi/`, the `@limn-works/scp-ts-napi` addon), the UniFFI bridge (`uniffi/`, Swift and Kotlin), and the logic they share (`common/`). Every bridge delegates context lifecycle to the shared `Supervisor` from `scp-runtime`; a bridge adds FFI state, never a second copy of supervisor state.

## Rules for every bridge

- **State is per bridge instance.** Every registry, allowlist, storage slot, and resolver lives on the bridge instance (`PyBridgeInstance`, `NapiBridgeInstance`, and the UniFFI equivalent, with shared fields in `common/src/bridge_instance.rs`). A process-global lets one tenant change another's policy (`.docs/lessons/process-global-policy-state-is-realm-local-rce.md`); `check-no-bridge-globals.sh` rejects one.
- **Validators live in `scp-ffi-common`.** A bridge's local validator delegates to `scp_ffi_common::validate::validate_X` and maps the error, as `src/validate.rs` does. Never reimplement a validator in a bridge.
- **Authorization lives in the Supervisor.** `context_close` performs no bridge-layer check; `Supervisor::close_context` checks the `ContextClose` capability. Do not add a second check in a bridge.
- **Storage fails closed.** A storage selection names `in_memory` explicitly or names `sqlite` with exactly one of `key` and `passphrase`; a failed SQLCipher open returns an error and never degrades to in-memory. `DurableProviders::from_handle` derives the saga journal and the MLS storage from one storage handle, so they share one backend by construction. The supervisor build fails when no storage was selected first.
- **Registry closures must not wait.** `with_identity`, `with_context`, `with_ffi_state` and `with_transport_manager` hold a `DashMap` shard lock for the closure's duration. Clone the `Arc`s and handles the async work needs out of the closure, and wait after it returns. In PyO3, a wait inside the closure releases the GIL while the shard lock is held, so a Python thread that holds the GIL and blocks on the same shard deadlocks against it; a write-back after the wait installs only if the entry still matches the snapshot it was built from.
- **PyO3 waits on an actor reply only through `actor_wait::block_on_released`,** which releases the GIL around the wait. Every bridge waits through `scp_ffi_common::bridge_wait::bridge_block_on` or `bridge_block_on_off_thread` (or a bridge's thin wrapper over one), whose private `drive` is the only `block_on` or `block_in_place` caller under `crates/scp-ffi/`, and only the functions in the `CALLERS` list of `scripts/check-bridge-block-on.py` may call it; the gate fails any other site, has no directive escape, and a new sync wait needs the human's approval to extend the list. The same gate fails every other thread-blocking call outside `common/src/bridge_wait.rs` (`std::thread::sleep`, an un-awaited `recv` or `wait`, `recv_timeout`, `recv_deadline`, `Condvar` `wait_*`, and tokio's `blocking_*`), so such a wait becomes async and goes through the bridge wait.
- **Never hold a `MutexGuard` across `.await`.** Scope the lock and copy what the async code needs.
- **NAPI and UniFFI read the ceiling and the creator from the supervisor actor, never from a bridge copy.** Their per-context UCAN state (`UcanContextStateCore` in `common/`, which NAPI extends) holds no capability ceiling and no creator DID, and a UniFFI `ContextHandle` holds no ceiling. `media_initiate_session` breaks this rule on all three bridges: it checks the requested media capabilities against a ceiling list the caller passes, not against the context's live ceiling, so a caller that passes a permissive list passes the check. UniFFI builds per-context UCAN state only through `ensure_ucan_registered_while_active`, `ensure_ucan_registered_while_active_on`, and `require_active_context_with_ucan_before_authz`, which build nothing unless the actor reports `Active` and no release mark stands on the id, or through `join_from_welcome_occupied`, which removes the state it built when the spawn future it awaits fails; both builders behind them and the UCAN registry are private to `uniffi/src/runtime.rs`.
- **`context_close` releases a context the supervisor already took out of service.** The close reads `read_live_context_state`, which calls `Supervisor::read_context_state_checked`: no actor, `Closed`, `Expired`, and `Tombstoned` skip the `CloseContext` dispatch and release the bridge's per-context state; `Closing`, `Creating`, `MigratingOut`, `Poisoned` (the operator's `clear_poison` respawns it as `Active`, and a release before that would leave the `Active` context with no revocation list on this bridge), an actor that did not answer (`ContextError::ActorBusy`), and a context whose actor is mid-respawn or whose last respawn failed (`ContextError::ActorCrashed`) refuse. The skip runs no `ContextClose` check, because that check runs inside the dispatch. The NAPI and UniFFI close marks the id released. `import_context` can return a `Closing`, `Closed`, `Expired`, or `Tombstoned` id, or an id no actor serves, to `Active`; the NAPI and UniFFI context import, the Welcome join, UniFFI `restore_context` and `restore_all_contexts`, and NAPI `context_restore` and `context_restore_all` clear the mark, and the bridge then rebuilds the context's revocation list and nonce tracker from the durable records under `context/{id}/ucan/` (`scp_ffi_common::ucan_durable_state`); a record that cannot be read or decoded refuses the registration with a typed error instead of starting from an empty list.

## tokio locks by caller

`blocking_lock()` panics with "Cannot block the current thread from within a runtime" on a tokio worker thread, and creating a second runtime or calling `block_on` inside `#[tokio::test]` panics the same way. Code reached from the transport layer or an actor runs on the runtime, so a synchronous lock there panics in production while a unit test that calls the function from a plain thread passes.

| Caller | Use |
|---|---|
| async code on the runtime | `.lock().await` |
| sync code that may run on a runtime thread | `.try_lock()`, and handle contention |
| sync code that must wait for the lock | the bridge wait (`actor_wait::block_on_released` in PyO3, `bridge_block_on` elsewhere) over `.lock()`; `scripts/check-bridge-block-on.py` fails `.blocking_lock()` anywhere under `crates/scp-ffi/` outside `bridge_wait.rs` |
| `#[tokio::test]` | the test's own runtime; never create a second one inside it |

`deliver_message` in `src/runtime.rs` waits for the receiver lock on purpose to keep oldest-drop overflow semantics, because `try_lock()` would drop the new message under contention. It waits through `actor_wait::block_on_released`, which picks a regime that cannot panic on a runtime thread and releases the GIL while it waits.

## PyO3 (`src/`)

- `cargo test -p scp-ffi` links libpython; the root `AGENTS.md` Toolchain gotchas give the library-path setup. `cargo check -p scp-ffi` compiles without it. Never skip these tests.
- A bridge function that returns a dict is read in Python as `h["key"]`, not `h.key`. Return a `#[pyclass]` for a new structured result.
- The MCP stdio client accepts only bare binary names on the instance's allowlist; it rejects every path, even in unrestricted mode, to block basename spoofing.
- An outlet handler that times out keeps its thread running until the handler returns, because Rust cannot cancel a thread; the design rejects cooperative cancellation (see the doc comment on `invoke_outlet` in `src/mcp.rs`).

## napi-rs (`napi/`)

- `identity_execute_recovery` and `identity_execute_custody_migration` are synchronous napi entry points that drive the async orchestrator with `runtime().block_on`, because the napi-rs worker thread has no tokio context. Do not make them `async fn`. Before the orchestrator runs they check, in order, that this instance owns the DID, that the context list is within its cap, and that a recovery permit is free; an exhausted permit returns `SCP-VALID-7140` at once rather than queueing, since a queued wait would pin a libuv worker.
- UCAN validation state (revocation lists, nonce trackers) lives in the bridge's own registry, not in the Supervisor. Every registration path loads it from the instance's storage, `ucan_revoke` writes the revocation list back before it returns, and every pipeline run that records a nonce writes the nonce entries back, each write made while holding the context's registry entry so concurrent writers land in order.
- `cargo test -p scp-ffi-napi` needs no Python linkage. `bindings/typescript/AGENTS.md` covers how napi values reach JavaScript.

## UniFFI (`uniffi/`)

- `scp.udl` is a namespace anchor only; proc-macros (`#[uniffi::export]`) define every type and function.
- Opaque objects (`Identity`, `ContextHandle`, `UcanToken`, `TransportManager`) are `Arc`-wrapped with manual handle counting in `lib.rs`; each `Drop` decrements the count.
- `cargo test -p scp-ffi-uniffi` needs no Python linkage. Generate bindings with `cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate …`; `bindings/swift/AGENTS.md` covers the committed Swift output.
