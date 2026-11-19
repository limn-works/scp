//! Tests moved out of `scp-runtime-core` `identity::recovery` (ADR-070 §6.2): they build a
//! `Supervisor`, which needs the domain handlers only `scp-runtime` assembles.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_did::DID;
use scp_protocol::crypto::hpke::p256::P256Point;
use scp_runtime_core::identity::recovery::*;
use std::collections::HashSet;
use std::sync::Arc;

/// A valid P-256 device key, distinct per `seed`.
fn device_key(seed: u8) -> P256Point {
    P256Point::try_from(scp_crypto::p256::testing::valid_uncompressed_point(seed))
        .expect("valid point")
}

fn did(s: &str) -> DID {
    DID::from(s)
}

/// Returns a deterministic test signing key for `ProductionRecoveryBackend`.
fn test_signing_key() -> scp_runtime_core::context::actor::signer::CommandSigner {
    scp_runtime_core::context::actor::signer::CommandSigner::local_ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]),
    )
}

// -----------------------------------------------------------------------
// ProductionRecoveryBackend tests
// -----------------------------------------------------------------------

/// Helper to create a minimal `ContextManager` for testing.
///
/// After ADR-049 §15, the `ContextCryptoProvider` trait is
/// deleted and tests bind to a real
/// [`NodeMlsFactory`](scp_runtime_core::crypto::mls::provider::NodeMlsFactory)
/// — fail-injection and stub-seal overrides move to
/// backend-injection in ADR-049 §15.
fn test_context_manager() -> Arc<scp_runtime_core::context::supervisor::Supervisor> {
    use scp_protocol::context::builder::ContextCreationError;
    use scp_protocol::context::{ContextError, ContextParams};
    use scp_runtime_core::context::builder::{ContextEventLogProvider, ContextTransportProvider};

    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    struct TestTransport;
    #[async_trait::async_trait]
    impl ContextTransportProvider for TestTransport {
        fn is_connected(&self) -> bool {
            true
        }
        async fn publish_context(
            &self,
            _: &[u8; 32],
            _: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn delete_published(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn send_message(
            &self,
            _: &[u8; 32],
            _: &[u8],
            _ttl: scp_protocol::envelope::outer::BlobTtl,
        ) -> Result<(), ContextError> {
            Ok(())
        }
    }

    struct TestEventLog;
    #[async_trait::async_trait]
    impl ContextEventLogProvider for TestEventLog {
        async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _: &[u8; 32],
            _: scp_event_log::EventType,
            _actor_did: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn event_log_entries(
            &self,
            _: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
            Ok(None)
        }
    }

    // ADR-049 §15: `ContextManager` is gone. Build the
    // `Supervisor` directly via `test_supervisor`.
    scp_runtime::test_supervisor(
        Arc::new(
            scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
                TEST_DID.to_owned(),
                std::sync::Arc::new(scp_clock::SystemClock),
            ),
        ),
        Box::new(TestTransport),
        Box::new(TestEventLog),
        Arc::new(|_: &scp_did::DID, _: scp_did::SigningKeyId| None),
    )
}

/// Helper to create a context in the manager for testing.
async fn setup_context(
    manager: &Arc<scp_runtime_core::context::supervisor::Supervisor>,
    context_id: &str,
    creator_did: &DID,
) {
    setup_context_with_members(manager, context_id, creator_did, &[]).await;
}

/// Helper to create a context with the creator and additional members.
async fn setup_context_with_members(
    manager: &Arc<scp_runtime_core::context::supervisor::Supervisor>,
    context_id: &str,
    creator_did: &DID,
    additional_members: &[&DID],
) {
    use scp_protocol::context::ContextParams;
    use scp_protocol::context::membership::KeyPackage;
    use scp_protocol::context::params::{ContextMode, GovernanceModel};
    use scp_protocol::context::roles::Capability;

    let params = ContextParams {
        mode: ContextMode::Encrypted,
        governance: GovernanceModel::SingleAdmin,
        // Include role:assign capability so the admin can add members.
        ceiling: vec![
            Capability::new("messages:read").expect("known capability"),
            Capability::new("messages:write").expect("known capability"),
            Capability::new("role:assign").expect("known capability"),
        ],
        ..ContextParams::default()
    };

    // Create the context. This registers it in the manager.
    let handle = manager
        .create_context(
            context_id.to_owned(),
            params,
            creator_did.clone(),
            None,
            Vec::new(),
        )
        .await
        .expect("failed to create test context");

    // Add additional members via join_context.
    for member_did in additional_members {
        let kp = KeyPackage::mock((*member_did).clone());
        manager
            .join_context(&handle, kp, None, None)
            .await
            .expect("failed to join test member");
    }
}

/// Stands up a live registered context actor for the identity-scoped
/// recovery pseudo-context so PSK-rotation notifications can seal.
///
/// PSK rotation (spec §9.12 step 6) seals its recovery notification
/// against a synthetic `identity-private-state` context. Pre-PR-7 the
/// per-context MLS crypto was provider-resident, so seeding an MLS group
/// directly on the supervisor's shared `NodeMlsFactory` sufficed for
/// [`NodeMlsFactory::seal`] to succeed. ADR-049 PR-7
/// (SCP-CRYPTOMOVE-001) moved that crypto state onto the per-context
/// actor by a one-way take, and `dispatch_recovery_send_notification`
/// routes through [`Supervisor::dispatch_trust_recovery_command`], which
/// mailbox-dispatches to a registered actor when one exists (and only
/// falls through to the non-64-hex-rejecting supervisor-direct path when
/// none is). So the notification now seals through the actor's OWNED
/// `ContextCryptoState` — which requires a registered actor for the id,
/// created here exactly as `create_context` does for any context. This is
/// the actor-model equivalent of the retired provider-group seed.
async fn seed_identity_private_state_group(
    manager: &Arc<scp_runtime_core::context::supervisor::Supervisor>,
) {
    let owner = did("did:dht:zRecoveryIdentityPrivateStateOwner");
    setup_context(manager, "identity-private-state", &owner).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_mls_update_succeeds() {
    let manager = test_context_manager();
    let alice = did("did:dht:alice");
    let context_id = "ctx-prod-1";

    setup_context(&manager, context_id, &alice).await;

    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let key_rotation = agent_key_rotation_outcome(&alice, 1000);

    let result = backend.mls_update(context_id, &key_rotation).await;
    assert!(result.is_ok(), "mls_update should succeed: {result:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_mls_update_unknown_context_fails() {
    let manager = test_context_manager();
    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let alice = did("did:dht:alice");
    let key_rotation = agent_key_rotation_outcome(&alice, 1000);

    let result = backend
        .mls_update("nonexistent-context", &key_rotation)
        .await;
    assert!(result.is_err(), "mls_update on unknown context should fail");
    assert_eq!(result.unwrap_err().step, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_revoke_ucans_succeeds() {
    let manager = test_context_manager();
    let alice = did("did:dht:alice");
    let context_id = "ctx-prod-2";

    setup_context(&manager, context_id, &alice).await;

    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let key_rotation = agent_key_rotation_outcome(&alice, 1000);

    let result = backend.revoke_ucans(context_id, &key_rotation).await;
    assert!(result.is_ok(), "revoke_ucans should succeed: {result:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_rotate_key_packages_succeeds() {
    let manager = test_context_manager();
    let alice = did("did:dht:alice");
    let context_id = "ctx-prod-3";

    setup_context(&manager, context_id, &alice).await;

    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let key_rotation = agent_key_rotation_outcome(&alice, 1000);

    let result = backend.rotate_key_packages(context_id, &key_rotation).await;
    assert!(
        result.is_ok(),
        "rotate_key_packages should succeed: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_notify_contacts_succeeds() {
    let manager = test_context_manager();
    let alice = did("did:dht:alice");
    let bob = did("did:dht:bob");
    let carol = did("did:dht:carol");

    // Set up a shared context where alice, bob, and carol are all members.
    // recovery_notify_contact searches for shared contexts between the
    // recovering DID and each contact.
    setup_context_with_members(&manager, "ctx-shared", &alice, &[&bob, &carol]).await;

    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let key_rotation = agent_key_rotation_outcome(&alice, 1000);
    let contacts = HashSet::from([bob, carol]);

    let result = backend
        .notify_contacts(&alice, CompromiseTier::Agent, &key_rotation, &contacts)
        .await;
    assert!(result, "notify_contacts should succeed");
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_notify_contacts_empty_set() {
    let manager = test_context_manager();
    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let alice = did("did:dht:alice");
    let key_rotation = agent_key_rotation_outcome(&alice, 1000);
    let contacts = HashSet::new();

    // Empty contact set — notification is vacuously true.
    // Note: notify_contacts with empty set is not called by the orchestrator
    // (it checks `contact_dids.is_empty()` first) but the backend should
    // handle it gracefully.
    let result = backend
        .notify_contacts(&alice, CompromiseTier::Agent, &key_rotation, &contacts)
        .await;
    assert!(result, "notify_contacts with empty set should succeed");
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_rotate_psk_succeeds() {
    let manager = test_context_manager();
    seed_identity_private_state_group(&manager).await;
    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());

    let params = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![device_key(1), device_key(2)],
        compromised_device_pubkey: None,
    };

    let result = backend.rotate_psk(&params).await;
    assert!(result, "rotate_psk should succeed");
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_rotate_psk_excludes_compromised_device() {
    let manager = test_context_manager();
    seed_identity_private_state_group(&manager).await;
    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());

    let params = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![device_key(1), device_key(2), device_key(3)],
        compromised_device_pubkey: Some(device_key(2)),
    };

    let result = backend.rotate_psk(&params).await;
    assert!(
        result,
        "rotate_psk should succeed with compromised device excluded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_rotate_psk_fails_no_eligible_devices() {
    let manager = test_context_manager();
    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());

    // All devices compromised.
    let params = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![device_key(1)],
        compromised_device_pubkey: Some(device_key(1)),
    };

    let result = backend.rotate_psk(&params).await;
    assert!(!result, "rotate_psk should fail with no eligible devices");
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_full_recovery_agent_tier() {
    let manager = test_context_manager();
    let alice = did("did:dht:alice");
    let bob = did("did:dht:bob");
    let context_id = "ctx-full-recovery";

    // Set up a context with alice and bob as members so contact
    // notification can find a shared context.
    setup_context_with_members(&manager, context_id, &alice, &[&bob]).await;

    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![context_id.to_owned()]);
    let key_rotation = agent_key_rotation_outcome(&alice, 1000);
    let contacts = HashSet::from([bob]);

    let result = orch
        .execute_recovery(
            CompromiseTier::Agent,
            Some(&key_rotation),
            &contacts,
            None,
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    assert_eq!(result.tier, CompromiseTier::Agent);
    assert_eq!(result.completed_contexts, vec![context_id]);
    assert!(result.failed_contexts.is_empty());
    assert!(result.key_rotation_completed);
    assert!(result.contacts_notified);
    assert!(result.private_state_reencrypted);
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_full_recovery_active_signing_tier() {
    let manager = test_context_manager();
    let alice = did("did:dht:alice");
    let bob = did("did:dht:bob");
    let context_id = "ctx-active-recovery";

    // Set up a context with alice and bob as members so contact
    // notification can find a shared context.
    setup_context_with_members(&manager, context_id, &alice, &[&bob]).await;
    // ActiveSigning recovery rotates the PSK, which seals against the
    // synthetic identity-private-state context — seed its MLS group.
    seed_identity_private_state_group(&manager).await;

    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![context_id.to_owned()]);
    let key_rotation = active_key_rotation_outcome(&alice, 2000);
    let contacts = HashSet::from([bob]);
    let psk_params = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![device_key(1), device_key(2)],
        compromised_device_pubkey: None,
    };

    let result = orch
        .execute_recovery(
            CompromiseTier::ActiveSigning,
            Some(&key_rotation),
            &contacts,
            Some(&psk_params),
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    assert_eq!(result.tier, CompromiseTier::ActiveSigning);
    assert_eq!(result.completed_contexts, vec![context_id]);
    assert!(result.contacts_notified);
    assert!(result.private_state_reencrypted);
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_full_recovery_identity_key_tier() {
    let manager = test_context_manager();
    let alice = did("did:dht:alice");
    let bob = did("did:dht:bob");
    let carol = did("did:dht:carol");
    let context_id = "ctx-identity-recovery";

    // Set up a context with alice, bob, and carol as members so
    // contact notification can find shared contexts.
    setup_context_with_members(&manager, context_id, &alice, &[&bob, &carol]).await;
    // IdentityKey recovery rotates the PSK, which seals against the
    // synthetic identity-private-state context — seed its MLS group.
    seed_identity_private_state_group(&manager).await;

    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![context_id.to_owned()]);
    let key_rotation = identity_key_rotation_outcome(&alice, did("did:dht:alice-new"), 3000);
    let contacts = HashSet::from([bob, carol]);
    let psk_params = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![device_key(1)],
        compromised_device_pubkey: None,
    };

    let result = orch
        .execute_recovery(
            CompromiseTier::IdentityKey,
            Some(&key_rotation),
            &contacts,
            Some(&psk_params),
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    assert_eq!(result.tier, CompromiseTier::IdentityKey);
    assert_eq!(result.new_did, Some(did("did:dht:alice-new")));
    assert_eq!(result.completed_contexts, vec![context_id]);
    assert!(result.key_rotation_completed);
    assert!(result.contacts_notified);
    assert!(result.private_state_reencrypted);
}

#[tokio::test(flavor = "multi_thread")]
async fn production_backend_multi_context_with_failure_isolation() {
    let manager = test_context_manager();
    let alice = did("did:dht:alice");

    // Create two contexts. The second will exist but both should work.
    setup_context(&manager, "ctx-ok-1", &alice).await;
    setup_context(&manager, "ctx-ok-2", &alice).await;

    let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
    let orch = CompromiseRecoveryOrchestrator::new(
        alice.clone(),
        vec![
            "ctx-ok-1".to_owned(),
            "ctx-ok-2".to_owned(),
            "ctx-nonexistent".to_owned(), // This should fail.
        ],
    );
    let key_rotation = agent_key_rotation_outcome(&alice, 1000);
    let contacts = HashSet::new();

    let result = orch
        .execute_recovery(
            CompromiseTier::Agent,
            Some(&key_rotation),
            &contacts,
            None,
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    // Two contexts should succeed, one should fail.
    assert_eq!(result.completed_contexts.len(), 2);
    assert_eq!(result.failed_contexts.len(), 1);
    assert_eq!(result.failed_contexts[0].0, "ctx-nonexistent");
    assert_eq!(result.failed_contexts[0].1.step, 2);
}
