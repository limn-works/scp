# `tokio::sync::Mutex::blocking_lock` Panics on a Tokio Worker Thread

`blocking_lock()` panics with "Cannot block the current thread from within a runtime" when it
runs on a tokio worker thread, and creating a second runtime or calling `block_on` inside
`#[tokio::test]` panics the same way. Code reached from the transport layer or from an actor
runs on the runtime, so a synchronous lock there panics in production while a unit test that
calls the function from a plain thread passes.

| Caller | Use |
|---|---|
| async code on the runtime | `.lock().await` |
| sync code that may run on a runtime thread | `.try_lock()`, and handle contention |
| sync code on a thread the runtime does not own, such as a Python or FFI caller thread | `.blocking_lock()` |
| `#[tokio::test]` | the test's own runtime; never create a second one inside it |

`deliver_message` in `crates/scp-ffi/src/runtime.rs` takes `blocking_lock()` on purpose to
keep oldest-drop overflow semantics, because `try_lock()` would drop the new message under
contention. That choice is sound only while every caller of `deliver_message` runs off the
runtime's worker threads.
