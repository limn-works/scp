---
name: pr2183-indexeddb-sticky-poison
description: PR #2183 crash-consistency fix (sticky-poison the wasm IndexedDbStorage write-behind chain) — the fix updated the TS adapter doc but left the Rust embedder-contract doc's FIFO framing stale
metadata:
  type: project
---

PR #2183 / commit b9c5e0a29, branch feat/scp-ts-wasm-packaging.
`bindings/typescript-wasm/src/adapters/indexeddb-storage.ts`: the async write-behind
chain now sticky-poisons on a durable-write fault (`#chainPoisoned` flag gates
`#runOp`; `#throwIfFaulted` no longer clears `#pendingFault`) so every op after the
first fault is skipped and the durable store stays a strict PREFIX (no gap). Recovery
= re-open (fresh instance is un-poisoned, `#preload` restores the prefix).

**The fix delta was clean** (doc honest, all 4 sync methods + `flushed()` fail closed,
`InMemoryStorage` correctly needs no change — it has no write-behind chain).

**Finding (INCOMPLETE):** the driver-side embedder-contract doc
`crates/scp-client-wasm/src/storage.rs:44-49` is now STALE — it still teaches that the
prefix property holds "*only under FIFO*" and that reorder is the sole failure mode.
The fix's own rationale disproves this: a non-uniform fault (quota-exceeded `put`
aborts, later `delete` frees space and succeeds) creates a GAP with NO reordering.
That doc is the contract for ALL embedders incl. the explicitly-anticipated
wa-sqlite/OPFS (storage.rs:6, :96), so a future embedder implementing only FIFO would
reintroduce the bug. Fix = add the fail-closed-sticky-on-fault obligation to the FIFO
section.

**Why:** Lesson — a crash-consistency fix in one embedder implementation must
propagate the corrected understanding to the shared driver-side port contract, or the
two docs diverge (implementation says "FIFO + sticky poison," contract says "FIFO").
**How to apply:** when reviewing a fix to a wasm SDK adapter (`bindings/typescript-wasm`
or any `scp-client-wasm` embedder), always check whether the Rust port-contract module
doc in `crates/scp-client-wasm/src/storage.rs` (or the `extern` JsStorage method docs)
still matches the corrected behavior.

Secondary: `crates/scp-client/src/error.rs:165-169` ABANDON path says `close_context`
"can always be closed cleanly" — true at the driver's per-context poison guard, but the
new instance-wide sticky adapter makes `close_context`'s `Storage::delete` throw on a
faulted instance until re-open. Worth author confirmation.
