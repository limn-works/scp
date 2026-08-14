---
name: outlet-stream-pyo3-gil-deadlock
description: C7 PyO3 outlet-streaming bridge (outlet_stream.rs) poll_next holds the GIL across block_on(recv()) — deadlocks against the spawned pump's Python handler
metadata:
  type: project
---

# C7 outlet-streaming PyO3 bridge — poll_next GIL deadlock (commit eb75ce608, branch feat/outlet-streaming-ffi)

BLOCKER found in `crates/scp-ffi/src/outlet_stream.rs`.

**Bug:** `outlet_stream_poll_next` (impl at :585, pymethod :846) does NOT take `py: Python` and does NOT wrap `rt.block_on(async { receiver.lock().await.recv().await })` (:599) in `py.allow_threads`. So it PARKS in recv() **holding the Python GIL**.

**Why fatal (unlike unary):** the streaming pump is a DETACHED tokio task (Supervisor::open_outlet_stream spawns it, returns promptly). The registered outlet handler (mcp.rs:2316 `py_register_outlet_handler`) is a Rust closure that reacquires the GIL via `Python::with_gil` to call back into Python — and it runs on a tokio WORKER thread. poll_next waits for a chunk → chunk needs the handler → handler needs the GIL → GIL held by poll_next. Permanent deadlock, hangs the whole interpreter, on the very first poll of a live stream with a Python handler.

The unary `outlet_invoke_impl` (outlets.rs:463) also holds the GIL across block_on but is SAFE because block_on drives the executor INLINE on the same thread (with_gil is reentrant on the GIL-holding thread). The streaming asymmetry — producer on another thread, consumer holds GIL — is the root cause.

**Fix:** `pub fn outlet_stream_poll_next(&self, py: Python<'_>, handle_id: &str)` and `py.allow_threads(|| outlet_stream_poll_next_impl(&self.inner, handle_id))`. Matches the documented discipline in lib.rs:22 and everywhere in identity.rs/server.rs/scpid.rs.

**Test gap (vacuous):** e2e_bridge.rs:2097 `outlet_stream_open_path_wired_and_control_plane_not_found` only opens against a NON-MEMBER (rejected at membership gate → no live stream) and polls a BOGUS handle (returns None immediately, never parks). The deadlock path (live stream + Python handler + poll) has ZERO coverage. Test comment even admits "a member-backed live stream is not constructible at the bridge boundary."

**LOW also noted:** open path :557 — if `handle.receiver()` returns None (only when already taken; unreachable on first call) the pump is already spawned + escrow consumed but handle is dropped without registry insert → orphaned billing stream. Unreachable today but fragile.

**Verified CLEAN:** handle_id parsing (registry key lookup, no hex::decode of caller input; pure wrappers use try_from with clean errors — no panic on malformed input); error mapping totality (grant_error_to_code/cancel_error_to_code/error_code are const fn → &'static str, exhaustive); no DashMap ref across await (authorized_control + poll_next both clone Arc out then drop the Ref); no lock-order inversion (control plane locks `handle`, data plane locks `receiver`, independent, no path takes both); concurrent poll_next serialized by receiver Mutex, double-remove idempotent.
