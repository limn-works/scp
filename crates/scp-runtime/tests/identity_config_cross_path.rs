//! Cross-path persistence-format compatibility for the spec §17.3 storage slot
//! `identity/{did}/document`.
//!
//! Two independent code paths write that exact slot:
//!
//! - `scp_identity::Identity::create` (the standalone construction front-end,
//!   ADR-052 Phase B-P3e) — when `persistence: Some(storage)`.
//! - `scp_runtime::store::ProtocolRepository::store_identity_document` (the
//!   canonical typed repository).
//!
//! `scp-identity` sits below `scp-runtime` in the crate graph and cannot import
//! it, so the two paths historically reimplemented the on-disk format
//! independently — and diverged (one wrote bare JSON, the other a named-
//! `MessagePack` `StoredValue` envelope), making an identity written by one path
//! undeserializable by the other. Both now route through the shared
//! `scp_platform::store_value` helpers.
//!
//! This test lives in `scp-runtime` (the lowest crate that can see BOTH paths)
//! and mechanically enforces that they remain mutually readable. It is the test
//! that was missing: a single-crate round-trip can pass while the two paths
//! disagree.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use zeroize::Zeroizing;

use scp_did::DidDocument;
use scp_identity::{DidDht, Identity, IdentityConfig};
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::Storage;
use scp_runtime::store::ProtocolRepository;

use scp_did::DID;

/// A shared encrypted backend usable as both the `EncryptedStorage` argument to
/// `Identity::create` and the `Storage` backing a `ProtocolRepository`.
///
/// `Arc<EncryptingAdapter<InMemoryStorage>>` is `EncryptedStorage` (via the
/// `Arc<T: EncryptedStorage>` blanket impl) and `Clone`, so one clone can drive
/// the identity-construction path while another reads through the repository —
/// both seeing the identical encrypted byte store underneath.
fn shared_encrypted_storage() -> Arc<EncryptingAdapter<InMemoryStorage>> {
    Arc::new(EncryptingAdapter::new(
        InMemoryStorage::new(),
        Zeroizing::new([7u8; 32]),
    ))
}

/// Forward direction: write via `Identity::create`, read via
/// `ProtocolRepository::load_identity_document`.
///
/// `load_identity_document` returns the inner document bytes (the `data` field
/// of the `StoredValue` envelope), which for this slot are the document's JSON
/// serialization. If the envelope format or key convention diverged, the load
/// would return `None` (wrong key) or `Err` (wrong envelope) instead of the
/// document bytes — so a successful, equal round-trip is proof of byte-level
/// compatibility.
#[tokio::test]
async fn identity_create_persisted_document_loads_via_protocol_repository() {
    let storage = shared_encrypted_storage();

    let (identity, document, _pre_rotation) = Identity::create(IdentityConfig {
        method: DidDht::new(),
        custody: InMemoryKeyCustody::new(),
        persistence: Some(Arc::clone(&storage)),
    })
    .await
    .expect("persisted identity creation should succeed");

    // Read the same slot through the canonical repository.
    let repo = ProtocolRepository::new_for_testing(Arc::clone(&storage));
    let did = DID::from(identity.did.clone());
    let loaded_bytes = repo
        .load_identity_document(&did)
        .await
        .expect("repository load should succeed")
        .expect("a document must be present at the identity document slot");

    // The inner bytes are the document's JSON; they must decode to the same
    // document `Identity::create` returned.
    let reloaded: DidDocument =
        serde_json::from_slice(&loaded_bytes).expect("inner bytes must be the document JSON");
    assert_eq!(reloaded.id, document.id);
    assert_eq!(reloaded.id, identity.did);
}

/// Reverse direction: write via `ProtocolRepository::store_identity_document`,
/// read via the same shared-envelope helper the `Identity::create` path uses to
/// decode (`scp_platform::store_value::from_stored_value_bytes`).
///
/// This proves the repository's write is decodable by the identity crate's
/// read expectation — the other half of mutual compatibility.
#[tokio::test]
async fn protocol_repository_document_decodes_with_shared_store_value_helper() {
    let storage = shared_encrypted_storage();
    let repo = ProtocolRepository::new_for_testing(Arc::clone(&storage));

    // A real document, JSON-encoded exactly as the identity path encodes it.
    let (identity, document, _pre_rotation) = Identity::create_ephemeral(
        IdentityConfig::ephemeral(DidDht::new(), InMemoryKeyCustody::new()),
    )
    .await
    .expect("ephemeral identity creation should succeed");
    let document_json = serde_json::to_vec(&document).expect("document JSON should serialize");

    let did = DID::from(identity.did.clone());
    repo.store_identity_document(&did, &document_json)
        .await
        .expect("repository store should succeed");

    // Read the raw slot and decode it the way the identity crate would: peel the
    // shared `StoredValue` envelope, then parse the inner JSON.
    let key = scp_platform::store_value::identity_document_key(did.as_ref())
        .expect("key build should succeed");
    let raw = storage
        .retrieve(&key)
        .await
        .expect("storage retrieve should succeed")
        .expect("a document must be present at the identity document slot");
    let inner: Vec<u8> = scp_platform::store_value::from_stored_value_bytes(&raw)
        .expect("repository write must decode via the shared envelope helper");
    let reloaded: DidDocument =
        serde_json::from_slice(&inner).expect("inner bytes must be the document JSON");
    assert_eq!(reloaded.id, document.id);
}

/// The two writers produce byte-identical storage for the same document: the
/// strongest statement of compatibility. Both paths are handed the identical
/// document JSON and must yield the identical on-disk bytes under the identical
/// key.
#[tokio::test]
async fn both_paths_write_byte_identical_documents() {
    // Build a document once.
    let (identity, document, _pre_rotation) = Identity::create_ephemeral(
        IdentityConfig::ephemeral(DidDht::new(), InMemoryKeyCustody::new()),
    )
    .await
    .expect("ephemeral identity creation should succeed");
    let did = DID::from(identity.did.clone());
    let document_json = serde_json::to_vec(&document).expect("document JSON should serialize");

    // Path A: ProtocolRepository::store_identity_document into a raw in-memory
    // store (no encryption layer, so we can read the exact persisted bytes).
    let repo_storage = InMemoryStorage::new();
    let repo = ProtocolRepository::new_for_testing(repo_storage);
    repo.store_identity_document(&did, &document_json)
        .await
        .expect("repository store should succeed");
    let key = scp_platform::store_value::identity_document_key(did.as_ref())
        .expect("key build should succeed");
    let repo_bytes = repo
        .storage()
        .retrieve(&key)
        .await
        .expect("storage retrieve should succeed")
        .expect("repository must have persisted the document");

    // Path B: the identity crate's exact serialization — the shared envelope
    // wrapping the same document JSON.
    let identity_bytes = scp_platform::store_value::to_stored_value_bytes(&document_json)
        .expect("identity-path serialization should succeed");

    assert_eq!(
        repo_bytes, identity_bytes,
        "ProtocolRepository and Identity::create must write byte-identical \
         documents to the identity document slot"
    );
}
