# scp-core

Core protocol implementation for [SCP](https://github.com/limn-works/scp) (Shared Context Protocol).

Implements context lifecycle, MLS group encryption, UCAN capability authorization, governance engines, membership management, broadcast channels, tool registration, and trust scoring.

## Quick Start

```rust,ignore
use scp_core::context::{
    ContextManager, ContextParams, LocalTransportProvider,
};
use scp_core::context::providers::MerkleEventLogProvider;

// Build a ContextManager with defaults.
//   - LocalTransportProvider: all operations succeed locally (no relay).
//   - MerkleEventLogProvider: in-memory Merkle-chained event log.
//   - No persistence: state lives in memory only.
let manager = ContextManager::builder()
    .crypto(Box::new(my_crypto_provider))
    .build()
    .expect("crypto is the only required provider");
```

## With Persistence (crash recovery)

Pass an `EncryptedStorage` implementation to `.storage()` and the builder auto-wires
`ProtocolStore`, context persistence, and event log persistence:

```rust,ignore
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::testing::InMemoryStorage;
use zeroize::Zeroizing;

let key = Zeroizing::new([0x42u8; 32]); // your encryption key
let storage = EncryptingAdapter::new(InMemoryStorage::new(), key);

let manager = ContextManager::builder()
    .crypto(Box::new(my_crypto_provider))
    .storage(storage)   // auto-wires persistence + event log
    .build()
    .expect("crypto is the only required provider");
```

For production, replace `InMemoryStorage` with `SqliteStorage` or
`AppleStorage`. The builder handles the rest.

## Create a Context

```rust,ignore
let params = ContextParams::default(); // encrypted mode, 7-day TTL

let handle = manager
    .create_context("my-context-1".into(), params, "did:dht:z6Mk...creator".into())
    .await?;

assert_eq!(handle.state().await, ContextState::Active);
```

## Send a Message

```rust,ignore
manager
    .send_message(&handle, &"did:dht:z6Mk...sender".into(), b"hello world", None)
    .await?;
```

## Read Event Log Entries

The `ContextEventLogProvider` trait includes `event_log_entries()` for
reading entries through a trait object — no need to downcast:

```rust,ignore
use scp_core::context::ContextEventLogProvider;

// Works through Box<dyn ContextEventLogProvider>:
let entries = event_log_provider
    .event_log_entries(&context_id_bytes)?
    .unwrap_or_default();

for entry in &entries {
    println!("{}: {}", entry.timestamp, entry.event);
}
```

## Persist and Restore

When `.storage()` or `.persistence()` is set, the manager persists context
state after every mutation (best-effort). To restore after a process
restart:

```rust,ignore
// Same storage backend as before (same database file / same in-memory state).
let manager = ContextManager::builder()
    .crypto(Box::new(my_crypto_provider))
    .storage(storage)
    .build()?;

// Restore all previously persisted contexts.
manager.restore_all_contexts().await?;
```

## Manual Provider Assembly

If you need full control (custom transport, custom event log), use the
raw constructors instead of the builder:

```rust,ignore
use scp_core::context::ContextManager;
use scp_core::context::governance::KeyResolver;

let key_resolver: KeyResolver = Arc::new(|did| {
    // Map DID to Ed25519 verifying key for governance vote verification.
    None
});

// Without persistence:
let manager = ContextManager::new(
    Box::new(my_crypto),
    Box::new(my_transport),
    Box::new(my_event_log),
    key_resolver,
);

// With persistence:
let manager = ContextManager::with_persistence(
    Box::new(my_crypto),
    Box::new(my_transport),
    Box::new(my_event_log),
    Box::new(my_persistence),
    key_resolver,
);
```

## Type Hierarchy

```text
Platform layer (scp-platform)
  Storage trait              async key-value store
  EncryptedStorage trait     sealed — use EncryptingAdapter<S> to wrap any Storage

Core layer (scp-core)
  ProtocolStore<S>           typed domain wrapper over Storage (100+ async methods)
  ProtocolStoreContextBridge<S>    sync bridge: ProtocolStore → ContextPersistence trait
  ProtocolStoreEventLogBridge<S>   sync bridge: ProtocolStore → EventLogPersistence trait

Provider layer (scp-core::context)
  ContextCryptoProvider      MLS group + sender key operations
  ContextTransportProvider   relay connectivity + message sending
  ContextEventLogProvider    event log init/append/read/export/import
  ContextPersistence         context snapshot persist/load/delete

Convenience types
  LocalTransportProvider     no-op transport (single-user / local-only apps)
  MerkleEventLogProvider     production event log with optional persistence
  ContextManagerBuilder      progressive assembly with sensible defaults
```

## License

Apache-2.0
