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

use scp_dht::InMemoryDhtClient;
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
        method: DidDht::with_client(Arc::new(InMemoryDhtClient::new())),
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
    let (identity, document, _pre_rotation) =
        Identity::create_ephemeral(IdentityConfig::ephemeral(
            DidDht::with_client(Arc::new(InMemoryDhtClient::new())),
            InMemoryKeyCustody::new(),
        ))
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
    let (identity, document, _pre_rotation) =
        Identity::create_ephemeral(IdentityConfig::ephemeral(
            DidDht::with_client(Arc::new(InMemoryDhtClient::new())),
            InMemoryKeyCustody::new(),
        ))
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

/// Every test above passes only when `scp-identity/testing` compiles the mint arm
/// of `Identity::create` and `Identity::create_ephemeral`
/// (`crates/scp-identity/src/config.rs`). With that feature off, both return
/// `IdentityError::NoPreRotationBackend`, and `IdentityConfig` has no field through
/// which a test could supply a real pre-rotation backend.
///
/// This crate's `testing` feature does not forward `scp-identity/testing`, on
/// purpose: `scp-ffi/testing → scp-core/testing → scp-runtime/testing` reaches
/// every bridge test build, and the forward would compile the mint arm there. The
/// edge that carries the feature is this crate's own `[dev-dependencies]` entry for
/// `scp-identity`, which only this crate's test build activates.
///
/// A `cargo nextest run --workspace` also builds `scp-testing`'s dev-dependencies,
/// whose self-edge enables `scp-testing/helpers` and through it
/// `scp-identity/testing`, and cargo unifies that feature into this test binary.
/// So the tests above pass in every workspace lane whether or not this crate's own
/// entry exists, and only
/// `cargo nextest run -p scp-runtime --features testing --test identity_config_cross_path`
/// exposes its loss. This test reads the manifest instead, so the loss turns red
/// in the workspace lanes too.
#[test]
fn own_dev_dependency_on_scp_identity_enables_testing() {
    let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    let doc: toml_edit::DocumentMut = manifest.parse().expect("scp-runtime Cargo.toml parses");
    let identity_manifest = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scp-identity/Cargo.toml"
    ));
    let identity: toml_edit::DocumentMut = identity_manifest
        .parse()
        .expect("scp-identity Cargo.toml parses");
    let activating = identity_features_implying_testing(&identity);

    let dev_features = doc["dev-dependencies"]["scp-identity"]["features"]
        .as_array()
        .expect("`[dev-dependencies] scp-identity` carries a `features` array");
    assert!(
        dev_features
            .iter()
            .filter_map(|feature| feature.as_str())
            .any(|feature| activating.contains(feature)),
        "`[dev-dependencies] scp-identity` must enable `testing`: without it, the \
         three `Identity::create*` tests in this file take the fail-closed \
         `NoPreRotationBackend` arm on a standalone `-p scp-runtime` build"
    );

    let escaping = non_dev_activations_of_identity_testing(&doc, &activating);
    assert!(
        escaping.is_empty(),
        "only this manifest's `[dev-dependencies]` entry may activate \
         `scp-identity/testing`, because cargo builds a dev-dependency for this \
         crate's own test targets alone. These edges activate it from elsewhere and \
         reach every bridge test build through `scp-ffi/testing → scp-core/testing → \
         scp-runtime/testing`, which compiles scp-identity's in-memory pre-rotation \
         mint arm there: {escaping:?}"
    );
}

// --- BEGIN shared manifest reader (byte-identical twin — see
// check_identity_manifest_readers_match in scripts/tests/ci-gate/ci_gate_selftest.py) ---
//
// CRITERION this reader enforces: in the manifest it reads, a `[dev-dependencies]`
// entry is the ONLY edge permitted to activate `scp-identity/testing`. Cargo builds
// a dev-dependency for that crate's own test targets alone, so that edge reaches no
// consumer. Every other spelling cargo accepts reaches a consumer's build, so the
// reader reports each one it finds.
//
// Indicators, not the criterion — the spellings a literal comparison against the
// string "scp-identity/testing" over the `testing` array walks past, which is what
// an earlier revision of these two tests compared:
//
//   - `"scp-identity?/testing"`, the weak spelling, which cargo accepts wherever the
//     dependency is optional, as it is in crates/scp-ffi/common/Cargo.toml;
//   - either spelling parked in a second feature that `testing` then names, which is
//     why this reads every feature the manifest declares;
//   - either spelling written against a rename, because `identity = { package =
//     "scp-identity" }` makes `"identity/testing"` the same activation;
//   - either spelling naming a different scp-identity feature that itself turns
//     `testing` on, which is why `identity_features_implying_testing` reads
//     scp-identity's own feature table instead of matching the word `testing`;
//   - a `[dependencies]` or `[build-dependencies]` entry on scp-identity whose
//     `features` list names `testing`, which reaches strictly more builds than a
//     feature forward does;
//   - any of those under `[target.<cfg>]`.
//
// This block is duplicated verbatim in crates/scp-runtime/tests/identity_config_cross_path.rs
// and crates/scp-ffi/common/tests/dht_capability_injection.rs. Each crate asserts the
// property about its own manifest and neither dev-depends on the other, so there is no
// crate in which to put one copy; check_identity_manifest_readers_match compares the two
// blocks byte for byte, so a fix applied to one and not the other fails the gate
// self-test.

use std::collections::BTreeSet;

/// Returns every scp-identity feature whose activation turns `testing` on,
/// `testing` itself included, by reading scp-identity's own `[features]` table.
fn identity_features_implying_testing(identity: &toml_edit::DocumentMut) -> BTreeSet<String> {
    let table = identity
        .get("features")
        .and_then(|item| item.as_table_like())
        .expect("scp-identity Cargo.toml declares a `[features]` table");
    let mut implying: BTreeSet<String> = BTreeSet::from(["testing".to_string()]);
    loop {
        let mut grew = false;
        for (feature, implies) in table.iter() {
            if implying.contains(feature) {
                continue;
            }
            let reaches = implies
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|entry| entry.as_str())
                .any(|entry| implying.contains(entry));
            if reaches {
                implying.insert(feature.to_string());
                grew = true;
            }
        }
        if !grew {
            return implying;
        }
    }
}

/// Returns every dependency table `manifest` declares, each paired with the
/// heading a reader would find it under, `[target.<cfg>]` tables included.
fn dependency_sections<'a>(
    manifest: &'a toml_edit::DocumentMut,
) -> Vec<(String, &'a dyn toml_edit::TableLike)> {
    const SECTIONS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let mut found: Vec<(String, &'a dyn toml_edit::TableLike)> = Vec::new();
    for section in SECTIONS {
        if let Some(table) = manifest.get(section).and_then(|item| item.as_table_like()) {
            found.push((format!("[{section}]"), table));
        }
    }
    let targets: Vec<_> = manifest
        .get("target")
        .and_then(|item| item.as_table_like())
        .map(|table| table.iter().collect())
        .unwrap_or_default();
    for (cfg, entry) in targets {
        for section in SECTIONS {
            if let Some(table) = entry
                .as_table_like()
                .and_then(|target| target.get(section))
                .and_then(|item| item.as_table_like())
            {
                found.push((format!("[target.{cfg}.{section}]"), table));
            }
        }
    }
    found
}

/// Returns every name a `[features]` value in `manifest` can use to address
/// scp-identity: each dependency-table key that names it, and each key that
/// renames it through a `package` field.
fn scp_identity_aliases(manifest: &toml_edit::DocumentMut) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    for (_, table) in dependency_sections(manifest) {
        for (key, spec) in table.iter() {
            let renamed = spec
                .as_table_like()
                .and_then(|entry| entry.get("package"))
                .and_then(|item| item.as_str());
            if renamed.unwrap_or(key) == "scp-identity" {
                aliases.insert(key.to_string());
            }
        }
    }
    aliases
}

/// Returns one sentence per edge in `manifest` that activates a scp-identity
/// feature in `activating` from anywhere other than a `[dev-dependencies]` table.
fn non_dev_activations_of_identity_testing(
    manifest: &toml_edit::DocumentMut,
    activating: &BTreeSet<String>,
) -> Vec<String> {
    let aliases = scp_identity_aliases(manifest);
    let mut found = Vec::new();
    for (section, table) in dependency_sections(manifest) {
        if section.ends_with("dev-dependencies]") {
            continue;
        }
        for (key, spec) in table.iter() {
            if !aliases.contains(key) {
                continue;
            }
            let features = spec
                .as_table_like()
                .and_then(|entry| entry.get("features"))
                .and_then(|item| item.as_array());
            for feature in features
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str())
            {
                if activating.contains(feature) {
                    found.push(format!(
                        "{section} `{key}` names `{feature}` in its `features` list"
                    ));
                }
            }
        }
    }
    let features: Vec<_> = manifest
        .get("features")
        .and_then(|item| item.as_table_like())
        .map(|table| table.iter().collect())
        .unwrap_or_default();
    for (feature, implies) in features {
        for entry in implies
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str())
        {
            let Some((dependency, activated)) = entry.split_once('/') else {
                continue;
            };
            let dependency = dependency.strip_suffix('?').unwrap_or(dependency);
            if aliases.contains(dependency) && activating.contains(activated) {
                found.push(format!(
                    "`[features] {feature}` names \"{entry}\", which activates \
                     `scp-identity/testing`"
                ));
            }
        }
    }
    found
}

// --- END shared manifest reader ---
