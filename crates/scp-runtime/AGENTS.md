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

**No `block_in_place` or `block_on` in the actor scope.** `scripts/check-block-in-place.py` is a ratchet: each file's count may only fall, and a new site fails CI. At a genuine sync→async seam use `spawn_blocking` (see `SpawnBlockingStorageAdapter`). `crates/scp-ffi/AGENTS.md` lists which tokio lock call each caller may use.

**No panics on the actor task (ADR-049 Decision 10).** `scripts/check-handler-no-panic.sh` bans `panic!`, `unreachable!`, `unimplemented!`, and `todo!` in every `.rs` file under `src/context/`, and the `assert*!` family too in `actor/handlers/` and `actor/mod.rs`. It scans a separate `*_tests.rs` file as production code, because that file carries no `#[cfg(test)]` marker of its own; write `assert!` or `matches!` there, and note that `assert!(false)` trips clippy's `assertions_on_constants`.

`#![warn(missing_docs)]` is crate-wide; document every new public item.
