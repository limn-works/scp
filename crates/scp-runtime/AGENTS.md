# scp-runtime

Read `.docs/adrs/ADR-049-actor-per-context.md` before you change this crate; every rule below traces to a numbered decision in it. `src/context/README.md` and `src/crypto/mls/README.md` map the modules.

## Actor-per-context

One tokio task per live context (`ContextActor`) owns that context's `PerContextState` by move, so context state carries no lock. The `Supervisor` is a plain struct, not an actor: it owns the registry of actor mailboxes and every provider, and it coordinates the one cross-context saga.

```
caller → Supervisor::method (lock-free lookup) → ContextActorHandle mailbox
       → ContextActor::run() select! → handlers/<domain>::dispatch
       → &mut ClassSCell (owns PerContextState) → coalesced or fail-closed persist
```

Read paths take no lock: `DashMap::get` and `ArcSwap::load` only (ADR-049 Decision 12, the lock-free read invariant, which lists the few allowed `Mutex` sites).

## Invariants

**Class-S persistence fails closed (ADR-049 Decision 9).** A Class-S field — spending-nonce consumption, executed proposals, downward-authorization transitions, saga reservation slots — is durable before the caller sees the mutation acknowledged; a coalesced acknowledgement would let a crash re-open a replay, re-spend, or re-grant window. `ClassSCell` (`actor/class_s.rs`) exposes `Deref` and no `DerefMut`, so the only way to mutate a Class-S field is one of its `commit_class_s_*` combinators, and Class-C state goes through `commit_class_c_best_effort` and its field-granular `ClassCMut` view. Add any new Class-S field or persist shape through a combinator. Never add a `state_mut` escape hatch or a source-text scanner; `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` records why the scanner was retired.

**Everything the actor awaits is `Send` (ADR-049 Decision 7).** Actor futures are `tokio::spawn`ed. Provider traits resident in `ActorDeps` are plain `#[async_trait]` with a `Send + Sync` supertrait, erased as `Arc<dyn …>`. `scp_platform::Storage` uses return-position `impl Trait` and is not dyn-compatible, which is why `OpenMlsStorageAdapter` wraps a concrete `S: Storage`; never add `dyn Storage` to `ActorDeps`. `RecoveryBackend` is the one `#[async_trait(?Send)]` trait, because the FFI boundary drives it on one task and never spawns it. Never resolve a `!Send` borrow by wrapping the event sink in a `Mutex`.

**Capability reduction (ADR-049 Decisions 3 and 5).** An actor holds a `SupervisorHandle`, never `Arc<Supervisor>`, and the handle returns no `ContextActorHandle`, so an actor cannot reach a sibling; cross-context work goes through `SupervisorHandle::start_saga`. A per-identity operation takes `&OwnedIdentityDid`, which only supervisor-module code can mint (`supervisor/identity_capability.rs`, guarded by `#![deny(unsafe_code)]`, `#![deny(non_local_definitions)]`, and a `compile_fail` doctest). Add no second minter and no handle method that returns an actor handle or the raw supervisor.

**The actor holds no signing key and retrieves nothing.** Its transport is send-only, `ActorDeps.key_resolver` resolves public keys only, and `send_message` takes the signing key as a per-call argument. A feature that must sign on its own schedule or pull messages from the relay runs at the FFI or SDK boundary (as `context_subscribe` does) and reaches the actor through mailbox commands that carry the key. Receive-side classification after MLS decryption belongs in the actor. When a plan puts a timer that signs, or a relay reader, inside the actor, the plan is wrong.

**Supervisor concurrency.** Every change to `src/context/supervisor/` or to work that leaves an actor mailbox keeps these properties:
- **Lock order.** The `Supervisor` holds two `tokio::sync::Mutex`es. `write_lock` serializes every mutation of `actors`, `standing_contexts`, `local_dids`, and `wrapping_keys`. `bootstrap_spawn_lock` serializes the crypto-write → spawn tail of `create_context`, `import_context`, and `restore_context`. Acquire `bootstrap_spawn_lock` before `write_lock`, never the reverse. A tokio `Mutex` is not reentrant, and `spawn_actor_with_state` and `despawn_actor` take `write_lock`, so no caller may hold `write_lock` while it calls either; that re-entrancy is why `bootstrap_spawn_lock` is a separate lock.
- **No shard guard across an await.** A `Ref` or `RefMut` from any Supervisor `DashMap` (`actors`, `wrapping_keys`, `key_package_stores`, `crash_windows`, `floors`, `saga_repair_records`) holds a shard lock while it lives. Drop it before any `.await` and before any `write_lock` acquire: clone the `Arc`, drop the entry, then await. `for entry in map.iter() { entry.value().lock().await }` deadlocks.
- **`reserved_saga_contexts` is a `std::sync::Mutex`.** Never hold its guard across an `.await`.
- **ArcSwap cells are not locks.** `standing_contexts`, `local_dids`, and `ContextHandle`'s lifecycle state (`Arc<ArcSwap<ContextState>>`, ADR-049 Decision 12) load without a lock, so they never enter the lock order. Their hazard is a lost read-modify-write: mutate `standing_contexts` and `local_dids` only under `write_lock`, and change a lifecycle state only through `ContextHandle::transition_to`, whose compare-and-swap loop makes the read-validate-store atomic. A bare `state()` load followed by a store races the other writers of the shared cell (the actor loop and the off-actor FFI finalize both hold clones).
- **A capability check and its action share one mailbox turn.** The mailbox serializes per-context work, so a check and its gated action are atomic only inside one turn. A check made supervisor-side before dispatch, or in one turn with the action in a later turn, can pass on a capability revoked in the gap; the governance and close paths (`GovernancePropose`, `GovernanceVote`, `ContextClose`) are where this split has occurred.
- **Off-mailbox work re-checks the spawn generation.** Each spawn stamps `Supervisor::spawn_generation.fetch_add(1) + 1` onto the actor's `PerContextState::generation`. Work that leaves the mailbox and returns later, such as the outlet-economy reserve → execute → settle split, captures the generation at reserve and rejects the settle when the live actor's generation differs, because an actor despawned and respawned for the same context id in the gap is a different instance; standing contexts reuse deterministic ids, so this respawn happens in practice. The crash-recovery refund (`reverse_caller_reservation_record`) is the one path that does not compare generations, because every restart stamps a new generation onto state restored from the same snapshot; its doc comment gives the argument.
- **Background tasks re-resolve.** A TTL timer or governance timeout task that holds an `Arc` to per-context state acts on a dead instance after a respawn unless it re-resolves the handle through `actors` or compares the spawn generation.

**No `block_in_place` or `block_on` in the actor scope.** `scripts/check-block-in-place.py` is a ratchet: each file's count may only fall, and a new site fails CI. At a genuine sync→async seam use `spawn_blocking` (see `SpawnBlockingStorageAdapter`). `crates/scp-ffi/AGENTS.md` lists which tokio lock call each caller may use.

**No panics on the actor task (ADR-049 Decision 10).** `scripts/check-handler-no-panic.sh` bans `panic!`, `unreachable!`, `unimplemented!`, and `todo!` in every `.rs` file under `src/context/`, and the `assert*!` family too in `actor/handlers/` and `actor/mod.rs`. It scans a separate `*_tests.rs` file as production code, because that file carries no `#[cfg(test)]` marker of its own; write `assert!` or `matches!` there, and note that `assert!(false)` trips clippy's `assertions_on_constants`.

`#![warn(missing_docs)]` is crate-wide; document every new public item.
