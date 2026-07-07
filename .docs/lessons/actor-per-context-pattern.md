# One actor per context: state owned by move, not shared under a lock

## The model

Every live context is a `tokio::spawn`'d task that **owns its state by move**. The
task is `ContextActor` (`crates/scp-runtime/src/context/actor/mod.rs`); the state it
owns is `PerContextState` (`context/actor/state.rs`). Callers never touch the state
directly — they send a `ContextCommand` down an `mpsc` inbox and await a reply on a
`oneshot` embedded in the command. The registry that routes a `context_id` to its
actor's mailbox is `Supervisor` (`context/supervisor/supervisor.rs`), whose
`actors: DashMap<String, ContextActorHandle>` lookup is lock-free (`Supervisor::lookup`).

The dispatch loop is a four-arm `tokio::select!` in `ContextActor::run`, `biased;` so
shutdown wins ties: (1) inbox `recv`, (2) TTL timer, (3) governance-proposal timeout,
(4) persistence-coalesce tick. One task, one `&mut PerContextState`, commands processed
one at a time — so **within a context there is no shared mutable state and no lock to
contend**. Cross-context reads that used to require a lock are now either lock-free
snapshots on `Supervisor` (`standing_contexts: ArcSwap`, `local_dids: Arc<ArcSwap<…>>`)
or another actor's mailbox.

## The "before": `ContextManager`

This replaced a monolithic `ContextManager` that held every context's `PerContextState`
behind a per-context `Mutex` (a shared-lock, shared-state model). ADR-049 §1
(`ContextActor owns state by move`) deleted it: at this commit `ContextManager` survives
only as a doc reference (`context/state.rs`) and in migration-shim comments. The header
of `context/actor/state.rs` narrates the field-for-field move off the legacy struct. The
payoff is the lock-free read invariant — see `lock-free-read-invariant.md` (ADR-049 §12):
a read on a hot path must never take `tokio::sync::RwLock`/`Mutex`; the actor model makes
that structural, because per-context state is reached by mailbox, not by lock.

## Class-S vs Class-C: the fail-closed / coalesced persist split

`ContextActor::new` wraps the owned state in a `ClassSCell` (`context/actor/class_s.rs`)
and hands it to handlers as `&mut ClassSCell` — **never** a bare `&mut PerContextState`.
The cell has no `DerefMut` and no `state_mut()` escape hatch. This encodes ADR-049 §9's
**two persistence classes** in the type system:

- **Class-S (fail-closed).** A spending-nonce consume, an executed-proposal record, a
  downward-authorization transition, a saga reservation slot — a mutation that must not be
  acknowledged to a caller unless it is already durable, because a coalesced ack would let
  a crash roll it back and re-open a replay/re-spend/re-grant window the caller already
  observed as closed. These go through the synchronous `commit_class_s_keep` /
  `commit_class_s_restore` combinators, which persist **before returning**. The three
  privatized Class-S fields (`PerContextState.class_s`, `GovernanceState.class_s`,
  `GovernanceState.revoked_spending_ucan_cids`) are `pub(in crate::context)`, so mutating
  them outside a fail-closed combinator is a **compile error** — the discipline is the
  type system's, not a source-text scanner's (a retired `check-class-s-fail-closed.sh`).
  Deferred Class-S work rides a `#[must_use]` `ClassSCommitToken` whose drop message warns
  that a dropped token leaves a burned nonce unpersisted.
- **Class-C (coalesced, best-effort).** Structural state — the MLS-commit retry queue,
  receive buffers, broadcast bookkeeping — mutates through `commit_class_c_best_effort` /
  `class_c_view()`. The actor's run-loop coalesces these into one snapshot write per
  `COALESCE_INTERVAL` (50 ms, ADR-049 §Decision 9) when `dirty == true`.

## `#[async_trait]` Send-discipline (ADR-049 §153, Decision 7)

`ActorDeps` is moved into the spawned task, so **every field it carries must be `Send`** —
including the `OwnedIdentityDid` capability token (`identity_capability.rs` ships a
`token_is_send_sync` `#[test]` asserting `Send + Sync` for exactly this reason; see
`owned-identity-did-capability.md`). ADR-049 §153 (Decision 7) is the normative rule that
follows: the provider traits an actor reaches through `ActorDeps` become `async` via
plain `#[async_trait]` (dyn-compatible, `Send` futures) rather than RPITIT, and all
`block_in_place` sync→async bridges are deleted. `SqliteStorage` wraps each `rusqlite` op
in `spawn_blocking` instead of pinning a worker thread — see
`spawn-blocking-for-sync-storage.md`, which covers the already-landed KV seam
(`SpawnBlockingStorageAdapter`). This was a multi-PR rollout, now complete: the
runtime-facing `ContextTransportProvider` (`context/builder.rs`) and `RelayPersistence`
(`scp-transport/src/native/relay_persistence.rs`) are both `#[async_trait]` now, and their
`block_in_place` sync→async bridges are deleted (`ratchet/block-in-place-count.json` records
`provider.rs: 0` / `relay_persistence.rs: 0`, and notes this is the LAST
block-in-place-deletion PR of Decision 7). The deletions were gated bridge-by-bridge by
`scripts/check-block-in-place.py` (see `ast-based-ci-enforcement.md`).

The Send boundary is not uniform. A trait whose futures must cross the spawn boundary is
`Send`; a trait consumed on a caller-local, non-`Send` path can stay `?Send`. When a call
must be `Send`-affine, the fix is often an **async/sync split**: keep the durable step
synchronous and push the awaitable external effect to a separate arm.

### Worked example — the split falls out of the persist discipline

The `ClassSCell` combinator family is the split made concrete. The **durable persist** is
synchronous and fail-closed (`commit_class_s_keep`, `commit_class_s_restore`); the
**external side effect** a mutation triggers (voiding an escrow, a compensating network
call) is a *separate* async combinator (`commit_class_s_compensating`,
`commit_class_s_keep_compensating`). The state mutation + its durable record commit
without an await in the critical section; the awaitable effect runs after, so a persist
can never straddle an await point.

The MLS-Commit broadcast is the sharpest instance of the split — and it runs the *other* way
from the escrow case above: here the awaitable step is the async terminal that touches **no**
state, and the *durable* record is the synchronous part the caller places in whichever class
its safety needs. Because `ContextTransportProvider` is now async (Decision 7), the broadcast
can no longer be awaited inside the synchronous `commit_class_s_keep` closure that
fail-closed-persisted the underlying mutation, so PR-3 split the failure bookkeeping OUT into
three pieces (`context/governance_helpers.rs`):

- `try_broadcast_commit` — the **async terminal**. `Send`, `&ActorDeps`,
  `-> Option<BroadcastFailure>`; it performs ONLY the transport send and builds the retry
  payload, mutating **no** `PerContextState` field.
- `apply_broadcast_failure` — the **synchronous applier**. Given a `BroadcastFailure` and the
  three disjoint Class-C `&mut` fields
  (`CommitBroadcastBorrows { pending_commits, commit_fault, receive_buffer }`), it enqueues the
  retry / trips the `commit_fault` gate / emits the local event, and touches nothing else — so
  the **durability class is the caller's choice.**
- `keep_broadcast_failure` — the safety-gated wrapper: a *second* `commit_class_s_keep` that
  runs `apply_broadcast_failure` fail-closed (the second `commit_class_s_keep` in the operation).

The caller picks the class. The safety-gated Class-S sites — `execute_remove_member`,
`execute_rotate_content_keys`, `leave_context`, and `recovery_advance_epoch` (§9.12) — call
`keep_broadcast_failure`, so the `commit_fault` safety-gate marker and the `pending_commits`
retry entry persist FAIL-CLOSED; a crash between the send failure and the ≤50 ms coalesce tick
would otherwise drop the only re-delivery of an epoch-advancing Commit — silent, permanent
group desync. The best-effort sites — `execute_add_member`, `execute_reset_member` — apply the
identical value COALESCED through a `class_c_view()` / `ClassCMut`. The async terminal stays
out of every persist closure; the durable step is a plain synchronous applier the caller runs
in its chosen class (ADR-049 §9 / Decision 7).

## Cross-refs

- ADR-049 §1 (actor owns state by move), §9 (Class-S/Class-C persistence), §153 / Decision 7
  (async provider traits + `block_in_place` deletion), §Decision 9 (coalesce interval).
- `lock-free-read-invariant.md` — why per-context state is reached by mailbox, not lock.
- `owned-identity-did-capability.md` — the `Send` capability token in `ActorDeps`.
- `spawn-blocking-for-sync-storage.md` — the sync-storage seam the Send-discipline needs.
- `saga-prepare-commit-abort.md` — the one cross-actor protocol the mailbox model runs.
