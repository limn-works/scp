---
name: outcome-error-sketch-dup
description: Actor handler modules each hand-roll their own outcome_error_sketch (clone a non-Clone ContextError); copies drift in fidelity. Watch for it in new handlers.
metadata:
  type: project
---

Multiple actor-handler modules under `crates/scp-runtime/src/context/actor/handlers/`
define a private `fn outcome_error_sketch(err: &ContextError) -> ContextError` to
produce a clone-equivalent of the non-`Clone` `ContextError` for the `Outcome` sink
(the real error is moved into the oneshot reply; a "sketch" goes to the actor).

As of the §6.2.4 saga PR (`feat/actor-2c-6.2.4-xctx-saga`):
- `tools.rs` copy maps ~9 variants faithfully.
- `saga.rs` copy maps only 4 (PermissionDenied/PersistenceFailed/RateLimited/NotImplemented)
  and folds the rest into `CryptoFailed(format!("{other}"))` — so the same error gets a
  *different variant* depending on which handler it flows through.

**Why this matters:** the need is a property of `ContextError`, not of any handler.
Every new actor handler tends to spawn another divergent copy.

**How to apply:** when reviewing a new actor handler, if it defines its own
`outcome_error_sketch` (or similar non-Clone-clone helper), flag it as REPETITION and
recommend hoisting ONE canonical conversion to `ContextError`'s own module — either
`impl Clone for ContextError` or a single `ContextError::sketch(&self)` — and deleting
the per-handler copies. Not a blocker; MEDIUM-value cleanup with broad payoff.
Related: [[reprepare-from-receipt-lossy-inverse]].
