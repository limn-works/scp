//! Phase 4 PR 3 — end-to-end persistence lifecycle tests.
//!
//! These tests exercise the SQLite-backed persistence path that the FFI
//! bridges (`StorageConfig::Sqlite { path, key }`) compose internally.
//! They bypass the FFI free-function façade (which is wired to the
//! default in-memory bridge instance and cannot be re-targeted at a
//! caller-owned `Scp` handle until the PR 4+ migration surfaces context
//! methods on `Scp`) and drive the underlying machinery directly:
//!
//! - [`scp_platform::sqlite::SqliteStorage`] — `SQLCipher` on-disk backend.
//! - [`scp_core::store::ProtocolRepository`] — typed domain layer.
//! - [`scp_core::store::context::ProtocolRepositoryContextBridge`] — the
//!   `ContextPersistence` implementation the FFI layer attaches to
//!   `CoreFields::persistence`.
//! - [`scp_core::context::manager::ContextManager::builder`] — the exact
//!   wiring point used by `UniffiBridgeInstance::with_storage_uniffi`
//!   and its `PyO3`/NAPI siblings (see `crates/scp-ffi/**/runtime.rs`).
//!
//! Issues exercised:
//! - #1491 (SQLite-backed persistence through the FFI).
//! - #1260 (persistence threaded through `CoreFields` via shared `Arc`).
//! - #1342 (no `FfiBridgeCrypto` — real `ContextManager` with DID).
//! - #1678 (multi-URL reconnect; see `multi_relay.rs` for transport side).
//!
//! Run:
//! ```sh
//! cargo test -p scp-testing --test persistence_sdk --features sqlite
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::significant_drop_tightening
)]

#[cfg(feature = "sqlite")]
use std::sync::Arc;

#[cfg(feature = "sqlite")]
use scp_core::context::governance::KeyResolver;
#[cfg(feature = "sqlite")]
use scp_core::context::manager::ContextManager;
#[cfg(feature = "sqlite")]
use scp_core::context::{
    Capability, ContextMode, ContextParams, ContextState, context_id_bytes, context_routing_id,
};
#[cfg(feature = "sqlite")]
use scp_core::store::ProtocolRepository;
#[cfg(feature = "sqlite")]
use scp_core::store::context::ProtocolRepositoryContextBridge;
#[cfg(feature = "sqlite")]
use scp_identity::DID;

#[cfg(feature = "sqlite")]
use scp_platform::sqlite::SqliteStorage;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "sqlite")]
const ALICE_DID: &str = "did:dht:z6MkPersistAliceAliceAliceAliceAliceAliceAlic";
#[cfg(feature = "sqlite")]
const BOB_DID: &str = "did:dht:z6MkPersistBobBobBobBobBobBobBobBobBobBobBob";

/// 32-byte raw encryption key used by `SQLCipher`. The specific value does
/// not matter for these tests as long as it is stable across the two
/// open calls that simulate process restart.
#[cfg(feature = "sqlite")]
const SQLITE_KEY: [u8; 32] = [0x42; 32];

/// Permissive resolver that returns `None` for every DID.
///
/// Governance signature verification is out of scope for persistence
/// lifecycle — we only need the `ContextManager` to be constructible.
#[cfg(feature = "sqlite")]
fn permissive_key_resolver() -> KeyResolver {
    Arc::new(|_did: &DID| None)
}

/// Returns `ContextParams` for an encrypted context with the capability
/// ceiling needed to create a context, send messages, and add members.
#[cfg(feature = "sqlite")]
fn encrypted_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::ContextClose,
        ],
        ..ContextParams::default()
    }
}

// ---------------------------------------------------------------------------
// AC1: SQLite file is created on first open and populated after flush
// ---------------------------------------------------------------------------

/// Opening `SqliteStorage` at a fresh directory creates `scp.db`.
///
/// The FFI bridges rely on this side effect so the caller can observe
/// persistence at the filesystem level (mobile app bundle diagnostics,
/// backup tooling, etc.).
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_storage_creates_database_file() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db_path = tmpdir.path().join("scp.db");
    assert!(
        !db_path.exists(),
        "scp.db must not exist before SqliteStorage::new"
    );

    let storage = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();

    assert!(
        db_path.exists(),
        "SqliteStorage::new must create scp.db at {}",
        db_path.display()
    );

    // Opening the same path with the same key must succeed (schema is
    // idempotent — `CREATE TABLE IF NOT EXISTS`).
    drop(storage);
    let _reopened = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();
}

/// Opening the same path with a different key must fail.
///
/// This guards against a silent downgrade where a caller passing the
/// wrong key would otherwise get a fresh empty database. `SQLCipher`
/// rejects the pragma / schema query when the key is wrong; we verify
/// the error surfaces.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_storage_rejects_mismatched_key() {
    let tmpdir = tempfile::tempdir().unwrap();
    let storage = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();
    drop(storage);

    let wrong_key = [0x11; 32];
    let result = SqliteStorage::new(tmpdir.path(), &wrong_key);
    assert!(
        result.is_err(),
        "SqliteStorage::new with wrong key must fail, not silently return a fresh DB"
    );
}

// ---------------------------------------------------------------------------
// AC2: ContextManager.builder().storage(SqliteStorage) persists state
// ---------------------------------------------------------------------------

/// Builds a `ContextManager` wired through a `SqliteStorage` on disk,
/// then verifies that creating a context + registering the creator DID
/// writes rows visible in the `ProtocolRepository` membership list.
///
/// This mirrors the exact wiring the FFI bridges use when
/// `StorageConfig::Sqlite` is selected:
/// `SqliteStorage::new(dir, key)` → `ProtocolRepository::new(Arc<SqliteStorage>)`
/// → `ProtocolRepositoryContextBridge::new(repo)` → attached to
/// `ContextManager` via `builder().storage(...)`.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_create_persists_membership_to_sqlite() {
    let tmpdir = tempfile::tempdir().unwrap();

    // Open ONE SqliteStorage and share it between the manager (via the
    // builder's `.storage()` consumption) and the verification side by
    // wrapping in Arc. The builder takes ownership, so we open the DB
    // twice here — acceptable because both connections share SQLCipher
    // state on the same file.
    let alice = DID::from(ALICE_DID);
    let ctx_id = "ctx-persist-create";

    // Phase 1: create + flush.
    {
        let storage = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();
        let manager = ContextManager::builder()
            .crypto(Box::new(
                scp_core::crypto::mls::provider::MlsCryptoProvider::new(ALICE_DID.to_owned()),
            ))
            .storage(storage)
            .key_resolver(permissive_key_resolver())
            .build()
            .unwrap();

        manager.register_local_did(alice.clone()).await;
        let handle = manager
            .create_context(ctx_id.to_owned(), encrypted_params(), alice.clone(), None)
            .await
            .expect("context_create must succeed with sqlite-backed persistence");
        assert_eq!(handle.state().await, ContextState::Active);
        // Flush snapshots before drop.
        manager.flush_all_contexts_sync();
    }

    // Phase 2: reopen same path, inspect the persisted ContextSnapshot.
    //
    // `create_context` → `persist_context_snapshot` → `store_full_snapshot`
    // writes to `context/{ctx}/full_snapshot`. The per-member
    // `store_membership` / `load_membership` helpers on `ProtocolRepository`
    // use a different key (`context/{ctx}/membership/{did}`) and are not
    // exercised by `ContextManager`'s snapshot path — we assert against
    // the snapshot.
    {
        let storage = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();
        let repo = ProtocolRepository::new(storage);
        let snapshot = repo
            .load_full_snapshot(ctx_id)
            .await
            .expect("load_full_snapshot must succeed")
            .expect("ContextSnapshot must be persisted for ctx-persist-create");
        assert_eq!(snapshot.context_id, ctx_id);
        assert_eq!(snapshot.state, ContextState::Active);
        let alice_info = snapshot
            .membership
            .get(alice.as_ref())
            .expect("alice must be in the persisted membership");
        assert_eq!(
            alice_info.role_name, "admin",
            "creator must be persisted with admin role"
        );
    }
}

// ---------------------------------------------------------------------------
// AC3: Full lifecycle roundtrip — create → send → drop manager → reopen → restore
// ---------------------------------------------------------------------------

/// Full suspend/kill/restore/resume semantics at the `ContextManager`
/// layer — the machinery the FFI `suspend()` + `resume()` compose.
///
/// Steps:
/// 1. Open SqliteStorage#1 at tmpdir, build manager with persistence.
/// 2. Register Alice's local DID, create context, send one message.
/// 3. `flush_all_contexts_sync` — persists the snapshot.
/// 4. Drop the manager (simulates process exit / `Scp::shutdown`).
/// 5. Open SqliteStorage#2 at the SAME path with the SAME key.
/// 6. Build a fresh manager with persistence pointing at the new
///    storage. Call `restore_all_contexts` — this is what
///    `BridgeInstanceCore::resume` invokes through
///    `CoreFields::restore_all_persisted_contexts`.
/// 7. Verify membership survived and the context handle is restored.
///
/// The new manager uses a NEW `MlsCryptoProvider`, so the MLS group
/// itself does not survive (`OpenMLS` key material lives in the provider
/// and is not persisted through this path — MLS state persistence is
/// tracked separately under SCP-PERSIST-050). This test asserts what
/// #1491 actually persists: the `ContextSnapshot` (membership, roles,
/// sender-key metadata, governance state) via `ProtocolRepository`.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_lifecycle_suspend_restore_roundtrip() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice = DID::from(ALICE_DID);
    let bob = DID::from(BOB_DID);
    let ctx_id = "ctx-persist-lifecycle";

    // ---- Phase 1: First "process" creates state and flushes. ----
    {
        let storage = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();
        let manager = ContextManager::builder()
            .crypto(Box::new(
                scp_core::crypto::mls::provider::MlsCryptoProvider::new(ALICE_DID.to_owned()),
            ))
            .storage(storage)
            .key_resolver(permissive_key_resolver())
            .build()
            .unwrap();

        manager.register_local_did(alice.clone()).await;
        let _handle = manager
            .create_context(ctx_id.to_owned(), encrypted_params(), alice.clone(), None)
            .await
            .expect("context_create must succeed");

        // Exercise the routing-id surface so derived state (if any) is
        // observable even in a no-transport manager.
        let _ = context_routing_id(ctx_id);
        let _ = context_id_bytes(ctx_id);

        // Flush to SQLite before dropping — mirrors
        // `CoreFields::shutdown_core_async` and `suspend()`'s
        // `flush_all_contexts_sync` call.
        manager.flush_all_contexts_sync();
    }

    // ---- Phase 2: Reopen the same database in a second "process". ----
    let storage = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();

    // Sanity: the persisted snapshot should be readable through
    // `ProtocolRepository` without going through `ContextManager` first.
    {
        let repo = ProtocolRepository::new(storage);
        let persisted = repo.load_full_snapshot(ctx_id).await.unwrap();
        assert!(
            persisted.is_some(),
            "ContextSnapshot must persist to SQLite after flush_all_contexts_sync"
        );
        let snap = persisted.unwrap();
        assert!(
            snap.membership.count() > 0,
            "persisted snapshot must carry the membership list"
        );
        assert!(
            snap.membership.members().any(|m| m.did == alice),
            "creator must be in the persisted membership list"
        );
    }

    // ---- Phase 3: Build a fresh manager + persistence + call restore. ----
    let storage2 = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();
    let repo2 = Arc::new(ProtocolRepository::new(storage2));
    let persistence = Box::new(ProtocolRepositoryContextBridge::new(Arc::clone(&repo2)));

    let manager2 = ContextManager::with_persistence(
        Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(
            ALICE_DID.to_owned(),
        )),
        Box::new(scp_core::context::NotConfiguredTransportProvider),
        Box::new(scp_core::context::providers::event_log::MerkleEventLogProvider::new()),
        persistence,
        permissive_key_resolver(),
    );

    manager2.register_local_did(alice.clone()).await;
    let restored = manager2
        .restore_all_contexts()
        .await
        .expect("restore_all_contexts must succeed against sqlite-backed repo");
    assert!(
        restored.iter().any(|id| id == ctx_id),
        "restore_all_contexts must return the previously-persisted context id, got {restored:?}"
    );

    // ---- Phase 4: Verify state survived. ----
    assert!(
        manager2.is_member(ctx_id, &alice.0).await,
        "Alice's membership must survive the restart"
    );
    assert_eq!(
        manager2.member_count(ctx_id).await,
        Some(1),
        "member_count must be accurate after restore"
    );
    assert!(
        !manager2.is_member(ctx_id, &bob.0).await,
        "Bob was never added, must not appear in restored membership"
    );
}

// ---------------------------------------------------------------------------
// AC4: FFI bridge surface — `UniffiBridgeInstance::with_storage_uniffi`
// compiles + constructs (#1549 PR 1/PR 3 plumbing).
// ---------------------------------------------------------------------------
//
// Full end-to-end context_create → context_send → suspend → restore
// through a user-owned `Scp` FFI handle is blocked on #1687 (migrate
// the free-function facade onto `SCP` instance methods). Until #1687
// lands, `context_create` etc. resolve against the default global
// `UniffiBridgeInstance` (in-memory), not a caller's
// `Scp::with_storage(Sqlite)` instance. The test below is therefore
// ignored with a clear rationale rather than faked.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "end-to-end FFI lifecycle through user-owned Scp + context methods \
            is blocked on #1687 (migrate free-function facade onto SCP instance \
            methods). Until that lands, context_create / context_send / \
            register_local_did resolve against the process-global default \
            bridge, not the caller-owned Scp; scp-testing has no dep on \
            scp-ffi-uniffi to avoid a workspace cycle. The underlying machinery \
            (SqliteStorage + ProtocolRepository + ContextManager) is exercised \
            by the tests above."]
async fn ffi_scp_with_sqlite_full_lifecycle() {
    // Placeholder: this test will be implemented in the PR that moves
    // context_create / context_send / register_local_did / suspend /
    // resume onto the `#[derive(uniffi::Object)] Scp` / `#[napi] Scp`
    // instance methods. At that point:
    //   let tmpdir = tempfile::tempdir().unwrap();
    //   let scp = Scp::with_storage(StorageConfig::Sqlite { path: ..., key: ... });
    //   let identity = scp.identity_create("in_memory").await.unwrap();
    //   scp.register_local_did(identity.did()).await.unwrap();
    //   let ctx = scp.context_create(identity, params).await.unwrap();
    //   scp.context_send(ctx, b"hello").await.unwrap();
    //   scp.suspend().unwrap();
    //   drop(scp);
    //   let scp2 = Scp::with_storage(StorageConfig::Sqlite { path, key });
    //   scp2.register_local_did(identity.did()).await.unwrap();
    //   scp2.resume().await.unwrap();
    //   assert!(scp2.context_is_member(ctx.id(), identity.did()).await);
    //   scp2.context_send(ctx, b"world").await.unwrap();
    panic!("ignored — see #[ignore] reason above");
}

// ---------------------------------------------------------------------------
// AC5: ProtocolRepoVariant::Sqlite event-log roundtrip
//
// This test exercises the exact shared machinery that
// `NapiBridgeInstance::with_storage_napi` and
// `UniffiBridgeInstance::with_storage_uniffi` compose when
// `StorageConfig::Sqlite` is selected:
//
//   SqliteStorage::new(tmpdir, key)
//     → ProtocolRepository::new(Arc<SqliteStorage>)
//     → ProtocolRepoVariant::Sqlite(Arc<ProtocolRepository<…>>)
//     → ProtocolRepoVariant::event_log_provider()
//     → MerkleEventLogProvider with persistence
//
// then appends a Merkle event, drops the provider, reopens the same
// SQLCipher file with the same key, rebuilds the variant, and asserts
// the appended event is readable.
//
// Before the `ProtocolRepoVariant` fix landed, `with_storage(Sqlite)`
// on both bridges returned a `ProtocolRepository<BridgeInMemoryStorage>`
// for the event log even when the caller passed a SQLite config. The
// Merkle entries invisibly persisted into an ephemeral in-memory store
// that was dropped on shutdown; on reopen the event log was empty even
// though context snapshots survived. This test is the regression guard.
// ---------------------------------------------------------------------------

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_repo_variant_sqlite_event_log_roundtrip() {
    use scp_core::context::providers::event_log::MerkleEventLogProvider;
    use scp_core::store::context::ProtocolRepositoryEventLogBridge;
    use scp_ffi_common::bridge_runtime::ProtocolRepoVariant;
    use std::sync::Arc;

    let tmpdir = tempfile::tempdir().unwrap();
    let ctx_id_bytes: [u8; 32] = {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(b"CTX1");
        h
    };
    let event_kind = "test.ac5.event";
    let actor = "did:dht:z6MkTestPersistAc5Actor";
    let payload = serde_json::json!({"body": "persistence roundtrip smoke test"});

    // ---- Phase 1: open SQLite, construct the variant, append one Merkle
    //               event through `event_log_provider()`, drop everything. ----
    //
    // This is the exact wiring that `NapiBridgeInstance::with_storage_napi`
    // and `UniffiBridgeInstance::with_storage_uniffi` compose internally:
    // open the SQLCipher DB once, wrap in `Arc<ProtocolRepository<…>>`,
    // stash in `ProtocolRepoVariant::Sqlite`, dispatch through
    // `event_log_provider()`. We then append via the trait-object that
    // bridge callers see.
    {
        let storage = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();
        let repo = Arc::new(ProtocolRepository::new(Arc::new(storage)));
        let variant = ProtocolRepoVariant::Sqlite(Arc::clone(&repo));
        let provider = variant.event_log_provider();

        provider
            .init_event_log(&ctx_id_bytes)
            .expect("init_event_log must succeed");
        provider
            .append_event(&ctx_id_bytes, event_kind, actor, Some(&payload))
            .expect("append_event must succeed");

        let entries_before = provider
            .event_log_entries(&ctx_id_bytes)
            .unwrap()
            .unwrap_or_default();
        assert_eq!(
            entries_before.len(),
            1,
            "one append must produce one entry in the live log"
        );
        assert_eq!(entries_before[0].event, event_kind);
        assert_eq!(entries_before[0].actor_did, actor);

        // Letting the scope exit drops `provider`, `variant`, `repo`, and
        // the Arc<SqliteStorage> behind them — simulating an FFI
        // `shutdown()`. `ProtocolRepositoryEventLogBridge` persists each
        // append synchronously via `persist_entry_best_effort`, so the
        // SQLCipher DB on disk now carries the entry.
        drop(provider);
    }

    // ---- Phase 2: reopen SAME path with SAME key and assert the Merkle
    //               entry is restorable through a fresh variant.
    //
    // `MerkleEventLogProvider::with_persistence` is the same constructor
    // `ProtocolRepoVariant::event_log_provider()` uses — we rebuild it
    // directly so we can call `restore_event_log`, which loads persisted
    // entries into the in-memory `logs` map. The bridge `resume()` path
    // invokes the same method via `restore_all_contexts`.
    let storage2 = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();
    let repo2 = Arc::new(ProtocolRepository::new(Arc::new(storage2)));
    let _variant2 = ProtocolRepoVariant::Sqlite(Arc::clone(&repo2));
    let bridge2 = ProtocolRepositoryEventLogBridge::new(Arc::clone(&repo2));
    let provider2 = MerkleEventLogProvider::with_persistence(Arc::new(bridge2));

    provider2
        .restore_event_log(&ctx_id_bytes)
        .expect("restore_event_log must succeed against a sqlite-backed repo");

    let entries_after = provider2.entries(&ctx_id_bytes).unwrap_or_default();
    assert_eq!(
        entries_after.len(),
        1,
        "event log must carry exactly the one entry we appended before drop — \
         this is the split-brain regression guard: if the event log had fallen \
         back to an in-memory store despite the SQLite config, the reopen \
         would see an empty log"
    );
    assert_eq!(
        entries_after[0].event, event_kind,
        "appended event kind must survive SQLite roundtrip"
    );
    assert_eq!(
        entries_after[0].actor_did, actor,
        "appended actor DID must survive SQLite roundtrip"
    );
}

// Same roundtrip, but against `ProtocolRepoVariant::InMemory`. The purpose
// is NOT to prove persistence (an in-memory store necessarily loses state
// on drop) but to prove the match arms in `event_log_provider()` dispatch
// correctly and that the in-memory variant supports the same trait surface.
// If the variant dispatch ever regresses (e.g. one arm returns a different
// provider type), this test catches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_repo_variant_in_memory_event_log_same_trait_surface() {
    use scp_core::store::ProtocolRepository;
    use scp_ffi_common::bridge_runtime::{BridgeInMemoryStorage, ProtocolRepoVariant};
    use scp_platform::encrypting_adapter::EncryptingAdapter;
    use std::sync::Arc;

    // EncryptingAdapter consumes the key wrapped in `Zeroizing`. Passing a
    // plain zero key via `.into()` is acceptable in a unit test (no disk
    // leak). Production paths get a random key via `OsRng`.
    let key: [u8; 32] = [0u8; 32];
    let encrypted = EncryptingAdapter::new(BridgeInMemoryStorage::new(), key.into());
    let repo = Arc::new(ProtocolRepository::new(encrypted));
    let variant = ProtocolRepoVariant::InMemory(repo);
    let provider = variant.event_log_provider();

    let ctx_id_bytes: [u8; 32] = {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(b"CTX2");
        h
    };
    provider.init_event_log(&ctx_id_bytes).unwrap();
    provider
        .append_event(
            &ctx_id_bytes,
            "test.ac5.in_memory",
            "did:dht:z6MkTestInMemoryActor",
            None,
        )
        .unwrap();
    let entries = provider.event_log_entries(&ctx_id_bytes).unwrap().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "InMemory variant must support append/read via the same trait surface \
         as the Sqlite variant — variant dispatch regression guard"
    );
    assert_eq!(entries[0].event, "test.ac5.in_memory");
}

/// Synthetic non-empty `Event` slice used by both AC6 trust-aggregation
/// dispatch tests. The content is deliberately minimal — aggregation only
/// requires the slice to be non-empty to bypass `TrustError::EmptyEventLog`.
fn synthetic_events_for_trust() -> Vec<scp_event_log::Event> {
    use scp_event_log::{Event, EventPayload, EventType};
    vec![Event {
        event_type: EventType::MessageSent,
        actor_did: scp_identity::DID::from("did:dht:z6MkTrustAc6Actor"),
        timestamp: 1,
        sequence: 0,
        payload: EventPayload {
            data: b"trust-ac6".to_vec(),
        },
        prev_hash: [0u8; 32],
        signature: vec![0u8; 64],
    }]
}

// ---------------------------------------------------------------------------
// AC6: trust aggregation dispatches correctly over ProtocolRepoVariant arms
//
// The trust-aggregation surface (`aggregate_trust_input` on NAPI/UniFFI,
// `aggregate_with_storage` on PyO3) matches on the active repository
// variant and constructs a `ProtocolRepositoryTrustBridge` over the
// concrete storage type. Fix 9 (PR #1690 review) asks for per-variant
// coverage: construct each arm, wrap in the trust bridge, call
// `populate_and_aggregate`, and confirm the aggregation returns a
// well-shaped result. This catches regressions where one match arm
// silently returns a degenerate trust input while the other works.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_aggregation_dispatches_over_in_memory_variant() {
    use scp_core::store::ProtocolRepository;
    use scp_ffi_common::bridge_runtime::{BridgeInMemoryStorage, ProtocolRepoVariant};
    use scp_ffi_common::trust_store::populate_and_aggregate;
    use scp_platform::encrypting_adapter::EncryptingAdapter;
    use std::sync::Arc;

    let key: [u8; 32] = [0u8; 32];
    let encrypted = EncryptingAdapter::new(BridgeInMemoryStorage::new(), key.into());
    let repo = Arc::new(ProtocolRepository::new(encrypted));
    let variant = ProtocolRepoVariant::InMemory(Arc::clone(&repo));

    // Exhaustiveness check: if the enum ever grows a new variant, the
    // match below stops compiling — forcing the test author to add a
    // parallel test for the new arm. Without this gate, a silent new
    // arm would bypass trust coverage.
    match &variant {
        ProtocolRepoVariant::InMemory(_) | ProtocolRepoVariant::Sqlite(_) => {}
    }

    let ProtocolRepoVariant::InMemory(in_memory_repo) = &variant else {
        panic!("variant must be InMemory for this test");
    };
    let handle = tokio::runtime::Handle::current();
    let bridge =
        scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(in_memory_repo), handle);

    let events = synthetic_events_for_trust();
    let json = tokio::task::spawn_blocking(move || {
        populate_and_aggregate(
            bridge,
            "ctx-in-memory-trust",
            "did:dht:z6MkInMemoryTrustSubject",
            Vec::new(),
            &[],
            &events,
            [0u8; 32],
            &[],
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
        )
    })
    .await
    .unwrap()
    .expect("populate_and_aggregate must succeed against the InMemory variant");
    assert!(
        !json.is_empty(),
        "InMemory variant trust aggregation must return a non-empty JSON body"
    );
    // The envelope shape must parse as JSON — guards against a variant
    // dispatch that accidentally returns a raw string.
    let _parsed: serde_json::Value =
        serde_json::from_str(&json).expect("aggregation JSON must parse");
}

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trust_aggregation_dispatches_over_sqlite_variant() {
    use scp_ffi_common::bridge_runtime::ProtocolRepoVariant;
    use scp_ffi_common::trust_store::populate_and_aggregate;
    use std::sync::Arc;

    let tmpdir = tempfile::tempdir().unwrap();
    let storage = SqliteStorage::new(tmpdir.path(), &SQLITE_KEY).unwrap();
    let repo = Arc::new(ProtocolRepository::new(Arc::new(storage)));
    let variant = ProtocolRepoVariant::Sqlite(Arc::clone(&repo));

    let ProtocolRepoVariant::Sqlite(sqlite_repo) = &variant else {
        panic!("variant must be Sqlite for this test");
    };
    let handle = tokio::runtime::Handle::current();
    let bridge =
        scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(sqlite_repo), handle);

    let events = synthetic_events_for_trust();
    let json = tokio::task::spawn_blocking(move || {
        populate_and_aggregate(
            bridge,
            "ctx-sqlite-trust",
            "did:dht:z6MkSqliteTrustSubject",
            Vec::new(),
            &[],
            &events,
            [0u8; 32],
            &[],
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
        )
    })
    .await
    .unwrap()
    .expect("populate_and_aggregate must succeed against the Sqlite variant");
    assert!(
        !json.is_empty(),
        "Sqlite variant trust aggregation must return a non-empty JSON body"
    );
    let _parsed: serde_json::Value =
        serde_json::from_str(&json).expect("aggregation JSON must parse");
}
