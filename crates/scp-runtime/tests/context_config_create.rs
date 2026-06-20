#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! ADR-052 Phase B-P3d — `Supervisor::create(ContextConfig)` integration.
//!
//! Verifies the flat-config front-end produces an `Active` context handle
//! equivalent to calling the existing `Supervisor::create_context` engine with
//! the lowered `ContextParams`. This proves the options-object entry is a true
//! front-end over the unchanged creation engine, not a parallel path.
//!
//! See `.docs/standards/construction.md` (§"Context — `ContextConfig`") and
//! `.docs/standards/sdk-common.md` (§"Context Creation").

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use scp_identity::DID;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::params::{ContextParams, TemplateId};
use scp_protocol::context::{ContextError, ContextState};
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::config::{ContextConfig, ContextCreation};
use scp_runtime::context::supervisor::Supervisor;
use scp_runtime::crypto::mls::provider::MlsCryptoProvider;

// ---------------------------------------------------------------------------
// Mock providers (mirrors governance_integration.rs)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockTransport {
    connected: AtomicBool,
}

impl MockTransport {
    const fn connected() -> Self {
        Self {
            connected: AtomicBool::new(true),
        }
    }
}

impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn send_message(&self, _id: &[u8; 32], _encrypted_payload: &[u8]) -> Result<(), ContextError> {
        Ok(())
    }
}

#[derive(Default)]
struct MockEventLog;

impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn append_event(
        &self,
        _id: &[u8; 32],
        _event: &str,
        _actor_did: &str,
        _payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    let bytes = did.as_ref().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}

fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did, _kid: scp_identity::SigningKeyId| {
        let seed = did_to_seed(did);
        Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
    })
}

fn alice() -> DID {
    DID::from("did:dht:z6MkAlice")
}

fn new_manager() -> Arc<Supervisor> {
    scp_runtime::context::test_supervisor(
        Arc::new(MlsCryptoProvider::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
        )),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog),
        mock_key_resolver(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `Supervisor::create` with a Template config returns an `Active` handle,
/// equivalent to the engine entry called with the lowered template params.
#[tokio::test]
async fn create_with_template_config_returns_active_handle() {
    let manager = new_manager();

    let config = ContextConfig {
        ttl: Some(Duration::from_mins(5)),
        ..ContextConfig::defaults(ContextCreation::Template {
            template: TemplateId::BilateralEphemeral,
            peer: None,
        })
    };

    let handle = manager
        .create("ctx-config-template".into(), config, alice(), None)
        .await
        .unwrap();

    assert_eq!(handle.try_read_state().unwrap(), ContextState::Active);

    // The handle's params must match the equivalent `from_template` path with
    // the TTL applied — proving `create` is a front-end over the same engine.
    let mut expected = ContextParams::from_template(TemplateId::BilateralEphemeral);
    expected.ttl = Some(Duration::from_mins(5));
    assert_eq!(handle.params(), &expected);
}

/// `Supervisor::create` (template config) and `Supervisor::create_context`
/// (lowered params) produce handles in the same state with the same params.
#[tokio::test]
async fn create_matches_create_context_for_equivalent_inputs() {
    let manager = new_manager();

    let config = ContextConfig {
        ttl: Some(Duration::from_mins(5)),
        ..ContextConfig::defaults(ContextCreation::Template {
            template: TemplateId::BilateralEphemeral,
            peer: None,
        })
    };
    let (lowered_params, _peer) = config.clone().into_params();

    let via_create = manager
        .create("ctx-via-create".into(), config, alice(), None)
        .await
        .unwrap();

    let via_engine = manager
        .create_context("ctx-via-engine".into(), lowered_params, alice(), None)
        .await
        .unwrap();

    assert_eq!(via_create.try_read_state().unwrap(), ContextState::Active);
    assert_eq!(via_engine.try_read_state().unwrap(), ContextState::Active);
    assert_eq!(via_create.params(), via_engine.params());
}

/// A bilateral `peer` cannot be invited at this engine layer (invitation /
/// Welcome-delivery is a higher SDK layer not yet wired). `Supervisor::create`
/// must therefore **fail loud** rather than silently drop the peer: a config
/// carrying `ContextCreation::Template { peer: Some(_), .. }` returns
/// `ContextCreationError::BilateralPeerNotSupported` and creates no context.
#[tokio::test]
async fn create_with_template_peer_fails_loud_not_silent() {
    let manager = new_manager();

    let bob = DID::from("did:dht:z6MkBob");
    let config = ContextConfig::defaults(ContextCreation::Template {
        template: TemplateId::BilateralEphemeral,
        peer: Some(bob),
    });

    let result = manager
        .create("ctx-with-peer".into(), config, alice(), None)
        .await;

    assert!(
        matches!(result, Err(ContextCreationError::BilateralPeerNotSupported)),
        "supplying a bilateral peer must be a loud BilateralPeerNotSupported error, \
         never a silently-dropped field; got {result:?}"
    );

    // No context was created: the deterministic id is unknown to the manager.
    assert!(
        manager.read_context_state("ctx-with-peer").await.is_none(),
        "a rejected peer create must not leave a partially-created context behind"
    );
}

/// The fail-loud guard is specific to a *present* peer: an explicit-config
/// create (which carries no peer) and a template create with `peer: None` both
/// succeed. This pins that the guard rejects only `Some(peer)`, not all
/// template creation.
#[tokio::test]
async fn create_without_peer_succeeds() {
    let manager = new_manager();

    // BilateralPersistent forbids a TTL, so `peer: None` + no TTL is the valid
    // minimal form — isolating that the guard rejects only `Some(peer)`.
    let config = ContextConfig::defaults(ContextCreation::Template {
        template: TemplateId::BilateralPersistent,
        peer: None,
    });

    let handle = manager
        .create("ctx-no-peer".into(), config, alice(), None)
        .await
        .unwrap();
    assert_eq!(handle.try_read_state().unwrap(), ContextState::Active);
}
