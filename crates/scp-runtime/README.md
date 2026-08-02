# scp-runtime

Async runtime orchestration for [SCP](https://github.com/limn-works/scp) (Shared Context Protocol).

`scp-runtime` is where SCP's stateful, `tokio`-driven logic lives: context
lifecycle, MLS group encryption, UCAN minting, governance, the cross-context
saga coordinator, and the persistence bridges. It depends on `scp-protocol`
for pure sync types and `scp-platform` for platform abstraction traits
(key custody, storage). Transport is injected, never hard-wired.

## The concurrency model — actor-per-context (ADR-049)

The runtime runs **one `tokio` task per live context**. That task (a
`ContextActor`) owns its `PerContextState` by move and mutates it inside a
command-dispatch loop — there are no interior locks on context state, and no
two tasks ever touch the same context. This replaced an older lock-based
manager whose lock types and scattered relock sites were "correct by
discipline"; the actor model makes single-writer ownership a structural
property instead. Read `.docs/adrs/ADR-049-actor-per-context.md` for the full
rationale and the decisions referenced throughout these docs.

Three types anchor the model:

- **`Supervisor`** — a plain struct (not an actor) that owns the actor
  registry and every injected provider. Lookups are lock-free
  (`DashMap::get` + `ArcSwap::load`) because they sit on the hot path of
  every public call; a mailbox hop per lookup would be too expensive
  (Decision 2, Decision 12). It is also the cross-context **saga
  coordinator**.
- **`ContextActor`** — the per-context task. Its `run()` loop is a
  `tokio::select!` over four arms: inbox command, TTL timer, governance
  timeout, and the coalesced-persistence tick (Decision 1).
- **`SupervisorHandle`** — a capability-reduced view of the `Supervisor`
  handed to each actor. It exposes no way to reach a sibling actor's handle;
  cross-context work must go through `SupervisorHandle::start_saga`
  (Decision 5). This is what makes "actor A cannot send to actor B directly"
  a compile-time guarantee, not a convention.

## Quick Start

The `Supervisor` is the single entry point. In production, FFI bridges build
one via `Supervisor::with_providers_and_journal` (durable saga journal). Tests
and local setups use the `test_supervisor` convenience constructor, which
wires an in-memory MLS storage backend and no-op persistence:

```rust,ignore
use std::sync::Arc;
use scp_runtime::context::test_supervisor;
use scp_runtime::crypto::mls::provider::NodeMlsFactory;
use scp_protocol::context::{ContextParams, ContextState};

// `test_supervisor` returns an `Arc<Supervisor>` with the given providers and
// an in-memory MLS store (a dev/test opt-in — production supplies a real
// `Storage`). `crypto` is a shared `Arc<NodeMlsFactory>`; `transport` and
// `event_log` are boxed provider trait objects; `key_resolver` maps a DID +
// verification method to its Ed25519 verifying key (ADR-039).
let supervisor = test_supervisor(
    Arc::new(NodeMlsFactory::new(
        "did:dht:z6Mk...creator".to_owned(),
        Arc::new(scp_clock::SystemClock),
    )),
    Box::new(my_transport_provider),
    Box::new(my_event_log_provider),
    my_key_resolver,
);

// Create a context. Returns a `ContextHandle` in `Active` state.
let handle = supervisor
    .create_context(
        "my-context-1".into(),
        ContextParams::default(),      // encrypted mode, default TTL
        "did:dht:z6Mk...creator".into(),
        None,                          // local pseudonym (§9.10.4)
    )
    .await?;

assert_eq!(handle.state(), ContextState::Active);
```

## Send a message

`send_message` takes a `MessageSigner` that binds the signing key to the
persona stamped on the wire — `Active` for human-originated sends, `Agent`
for agent-autonomous sends (ADR-039). The single enum prevents the key and
the persona from ever diverging:

```rust,ignore
use scp_runtime::context::supervisor::MessageSigner;

supervisor
    .send_message(
        &handle,
        &"did:dht:z6Mk...sender".into(),
        b"hello world",
        MessageSigner::Active(&signing_key),  // or MessageSigner::Agent(&key)
        None,   // source provenance (cross-context attribution)
        None,   // spending UCAN (paid contexts)
    )
    .await?;
```

## Production assembly and crash recovery

Production bridges call `Supervisor::with_providers_and_journal`, passing a
`DurableProviders` value. Its only non-test constructor derives **both** the
durable saga journal and the MLS storage adapter from **one** `Storage`
handle, so the "same backend for journal and state" invariant is enforced by
the type system rather than by convention. After construction, restore
persisted contexts and replay any crash-orphaned saga journal entries in one
call:

```rust,ignore
// Restore every persisted context, THEN replay unresolved sagas. The ordering
// is enforced by construction: `replay_unresolved_sagas` requires a
// `RestoredContexts` witness that only `restore_all_contexts` can mint, so
// replay-before-restore does not compile. `restore_on_startup` runs both
// steps in the correct order and returns the restored context IDs.
let restored = supervisor.restore_on_startup().await?;
```

## Type hierarchy

```text
Platform layer (scp-platform)
  Storage trait              async key-value store (RPITIT — NOT dyn-compatible)
  EncryptedStorage trait     sealed — wrap any Storage via EncryptingAdapter<S>

Runtime — the actor model (scp-runtime::context)
  Supervisor                 plain-struct actor registry + saga coordinator;
                             owns every provider; lock-free reads
  SupervisorHandle           capability-reduced Supervisor view held by actors
                             (no sibling-actor access; start_saga only)
  ContextActor               one tokio task per context; run() select! loop
  ClassSCell                 fail-closed-persist wrapper around PerContextState
                             (no DerefMut — Class-S mutation only via combinators)
  PerContextState            the owned per-context state payload
  ActorDeps                  non-state deps moved into the actor task
                             (crypto, transport, event log, mls/hpke backends,
                              SupervisorHandle, clock, key_resolver, …)

Provider traits (injected, dyn-erased)
  ContextTransportProvider   relay connectivity + message sending
  ContextEventLogProvider    event log init/append/read/export/import
  ContextPersistence         context snapshot persist/load/delete
  MlsBackend / HpkeBackend   async #[async_trait] MLS + HPKE primitive surfaces
  OpenMlsStorageAdapter      dyn-compatible async KV under the OpenMLS bridge

Convenience
  NodeMlsFactory          concrete MLS crypto provider (OpenMLS + HPKE);
                             held as Arc<NodeMlsFactory> in ActorDeps
  MerkleEventLogProvider     Merkle event log with optional persistence
  test_supervisor            in-memory Supervisor for tests/local setups
```

## Crate-internal maps

- `CLAUDE.md` (this crate) — agent-facing map for modifying the runtime.
- `src/context/README.md` — the `context/` module tree and command flow.
- `src/crypto/mls/README.md` — the MLS subsystem.

## License

Apache-2.0
