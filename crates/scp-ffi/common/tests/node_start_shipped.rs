//! `node_start` validation in a shipped build (SCP-321, construction.md §"Node
//! start — `NodeStartConfig`").
//!
//! The test below compiles only without this crate's `testing` feature, so it
//! runs against the `FfiDhtClient` and `node_start` a shipped bridge links.
//! The `rust-test-napi-production` CI job runs it by name with
//! `cargo nextest run --no-tests=fail --features server`, in a lane that does
//! not unify `scp-ffi-common/testing` on.

// The whole file is shipped-build only: under `testing` its helper would be dead.
#![cfg(all(feature = "server", not(feature = "testing")))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use scp_ffi_common::dht::ClientDhtConfig;
use scp_ffi_common::error_codes::{STORAGE_8007, server_error_code};
use scp_ffi_common::node_start_config::NodeStartConfig;
use scp_ffi_common::server::{ConcreteDidMethod, InstanceStorage, NodeIdentity, node_start};
use scp_identity::{DidCache, DidMethod};
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::{InMemoryKeyCustody, InMemoryPreRotationCustody};

/// Builds an operator identity over the shipped Pkarr client. `create` signs
/// the DID document and publishes nothing, so the test needs no network.
async fn operator_identity() -> NodeIdentity {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let pre_rotation = InMemoryPreRotationCustody::new();
    let client = ClientDhtConfig {
        gateways: vec!["https://dns.example.org".to_owned()],
    }
    .into_client()
    .expect("a gateway config builds the shipped Pkarr client");
    let did_method = Arc::new(ConcreteDidMethod::with_client_and_signer(
        Arc::new(client),
        Arc::new(DidCache::new()),
        ConcreteDidMethod::make_sign_fn(Arc::clone(&custody)),
    ));
    let (identity, document, _) = did_method
        .create(custody.as_ref(), &pre_rotation)
        .await
        .expect("identity creation signs locally");
    NodeIdentity {
        identity,
        document,
        did_method,
    }
}

/// `Reach::Local` with ACME fails `scp_node::validate_reach_and_tls`, so
/// `node_start` returns `SCP-STORAGE-8007` and creates neither the blob
/// directory nor the blob file.
#[cfg(not(feature = "testing"))]
#[tokio::test]
async fn node_start_rejects_invalid_reach_tls_with_storage_8007_in_shipped_build() {
    let identity = operator_identity().await;
    let dir = std::env::temp_dir().join(format!("scp-node-start-shipped-{}", std::process::id()));
    let blob_path = dir.join("blobs.redb");
    let cfg = NodeStartConfig::from_json(
        &serde_json::json!({
            "reach": {"kind": "local"},
            "identity": identity.identity.did,
            "blob_storage": {"kind": "redb", "path": blob_path},
            "tls": {"kind": "acme"},
            "dht": {"kind": "disabled"},
            "cors_origins": {"kind": "any_origin"},
        })
        .to_string(),
    )
    .expect("the config parses; validation rejects it");

    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut *key);
    let storage = Arc::new(EncryptingAdapter::new(InMemoryStorage::new(), key));

    let err = node_start(cfg, identity, InstanceStorage::InMemoryEncrypted(storage))
        .await
        .err()
        .expect("Local reach with ACME must be refused");
    let created = dir.exists();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(server_error_code(&err), STORAGE_8007, "{err:?}");
    assert!(!created, "a refused start created {}", dir.display());
}
