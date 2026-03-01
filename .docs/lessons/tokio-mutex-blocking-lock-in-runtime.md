# tokio::sync::Mutex::blocking_lock panics inside tokio runtime

## Context

When implementing the SCP-216 receive channel overflow handling, `deliver_message` needed sync access to a `tokio::sync::Mutex`-protected receiver to pop the oldest message. The initial implementation used `blocking_lock()`.

## Problem

`tokio::sync::Mutex::blocking_lock()` panics with "Cannot block the current thread from within a runtime" when called from any tokio worker thread. Since `deliver_message` is called by the transport layer (which runs on the tokio runtime), this panics at runtime.

Similarly, `tokio::runtime::Runtime::block_on()` panics with "Cannot drop a runtime in a context where blocking is not allowed" if a second runtime is created inside a `#[tokio::test]` context.

## Solution

Use `try_lock()` instead of `blocking_lock()` for sync access to `tokio::sync::Mutex` from code that may run inside a tokio runtime. `try_lock()` returns immediately with `Err` if the lock is held, which is acceptable for best-effort operations like oldest-drop overflow.

For `__anext__` (called from Python, not from tokio), `py.allow_threads()` + `runtime().block_on(rx.lock().await.recv().await)` is safe because Python threads are not tokio worker threads.

## Rule

- **From tokio context**: use `.lock().await` (async) or `.try_lock()` (sync, may fail)
- **From non-tokio context**: use `.blocking_lock()` (sync, blocks) or `runtime.block_on(.lock().await)` (async-to-sync bridge)
- **Never**: `blocking_lock()` from a tokio worker thread
- **Tests**: `#[tokio::test]` creates its own runtime; never call `init_runtime()` or create a second runtime inside it

## Files

- `crates/scp-ffi/src/runtime.rs` -- `deliver_message` uses `try_lock()`
- `crates/scp-ffi/src/context.rs` -- `__anext__` uses `runtime().block_on()` from Python thread
