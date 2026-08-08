#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! B18: Compromise recovery protocol integration tests.
//!
//! Exercises the 3-tier compromise recovery orchestrator (§9.12): data type
//! construction, per-context failure isolation, step ordering, contact
//! notifications, PSK rotation, and error variants. Uses a mock
//! `RecoveryBackend` to drive the orchestrator without real MLS/UCAN/relay
//! infrastructure.

use std::collections::HashSet;

use async_trait::async_trait;
use scp_core::identity::recovery::{
    CompromiseRecoveryOrchestrator, CompromiseTier, ContactNotification, ContextRecoveryState,
    KeyRotationOutcome, PskRotationParams, RecoveryBackend, RecoveryError, RecoveryProgress,
    RecoveryResult, RecoveryStepError, RecoveryStepErrorCode, StepOutcome,
    active_key_rotation_outcome, agent_key_rotation_outcome, identity_key_rotation_outcome,
};
use scp_did::DID;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn did(s: &str) -> DID {
    DID::from(s)
}

/// Converts a mock's boolean success knob into the tri-state step result the
/// trait returns.
fn step_result(step: u8, ok: bool) -> Result<(), RecoveryStepError> {
    if ok {
        Ok(())
    } else {
        Err(RecoveryStepError {
            step,
            code: RecoveryStepErrorCode::Unspecified,
            description: format!("mock backend configured to fail step {step}"),
        })
    }
}

/// Mock `RecoveryBackend` that succeeds by default. Individual steps can be
/// configured to fail for specific contexts.
struct MockBackend {
    mls_update_error: Option<(String, RecoveryStepError)>,
    revoke_ucans_error: Option<(String, RecoveryStepError)>,
    /// Not keyed by context: step 4 is identity-scoped and runs once.
    rotate_key_packages_error: Option<RecoveryStepError>,
    notify_contacts_result: bool,
    rotate_psk_result: bool,
}

impl MockBackend {
    const fn new() -> Self {
        Self {
            mls_update_error: None,
            revoke_ucans_error: None,
            rotate_key_packages_error: None,
            notify_contacts_result: true,
            rotate_psk_result: true,
        }
    }
}

#[async_trait(?Send)]
impl RecoveryBackend for MockBackend {
    async fn mls_update(
        &self,
        context_id: &str,
        _key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        if let Some((ref ctx, ref err)) = self.mls_update_error
            && ctx == context_id
        {
            return Err(err.clone());
        }
        Ok(())
    }

    async fn revoke_ucans(
        &self,
        context_id: &str,
        _key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        if let Some((ref ctx, ref err)) = self.revoke_ucans_error
            && ctx == context_id
        {
            return Err(err.clone());
        }
        Ok(())
    }

    async fn rotate_key_packages(
        &self,
        _key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        self.rotate_key_packages_error
            .as_ref()
            .map_or(Ok(()), |err| Err(err.clone()))
    }

    async fn notify_contacts(
        &self,
        _did: &DID,
        _tier: CompromiseTier,
        _key_rotation: &KeyRotationOutcome,
        _contacts: &HashSet<DID>,
    ) -> Result<(), RecoveryStepError> {
        step_result(5, self.notify_contacts_result)
    }

    async fn rotate_psk(&self, _params: &PskRotationParams) -> Result<(), RecoveryStepError> {
        step_result(6, self.rotate_psk_result)
    }
}

// ---------------------------------------------------------------------------
// 1. compromise_tier_agent — Agent tier rotates agent key only, DID unchanged
// ---------------------------------------------------------------------------

#[tokio::test]
async fn compromise_tier_agent() {
    let alice = did("did:dht:alice");
    let orch = CompromiseRecoveryOrchestrator::new(
        alice.clone(),
        vec!["ctx-a".to_owned(), "ctx-b".to_owned()],
    );
    let kr = agent_key_rotation_outcome(&alice, 1000);
    let backend = MockBackend::new();

    // Agent tier: DID unchanged, only #agent scope rotated.
    assert_eq!(kr.tier, CompromiseTier::Agent);
    assert_eq!(kr.did_after, alice);
    assert!(!kr.did_changed);
    assert_eq!(kr.rotated_key_scopes, vec!["#agent"]);

    let result = orch
        .execute_recovery(
            CompromiseTier::Agent,
            Some(&kr),
            &HashSet::new(),
            None,
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    assert_eq!(result.tier, CompromiseTier::Agent);
    assert!(result.new_did.is_none());
    assert_eq!(result.completed_contexts.len(), 2);
    assert!(result.failed_contexts.is_empty());
    // Agent tier: the PSK is unaffected, so step 6 genuinely does NOT run.
    // NotApplicable is not success — the old `bool` conflated the two.
    assert!(matches!(
        result.private_state_reencryption,
        StepOutcome::NotApplicable(_)
    ));
}

// ---------------------------------------------------------------------------
// 2. compromise_tier_active_signing — ActiveSigning rotates active key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn compromise_tier_active_signing() {
    let alice = did("did:dht:alice");
    let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec!["ctx-1".to_owned()]);
    let kr = active_key_rotation_outcome(&alice, 2000);
    let contacts = HashSet::from([did("did:dht:bob")]);
    let psk_params = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
        compromised_device_pubkey: None,
    };
    let backend = MockBackend::new();

    // ActiveSigning tier: DID unchanged, #active scope rotated.
    assert_eq!(kr.tier, CompromiseTier::ActiveSigning);
    assert_eq!(kr.did_after, alice);
    assert!(!kr.did_changed);
    assert_eq!(kr.rotated_key_scopes, vec!["#active"]);

    let result = orch
        .execute_recovery(
            CompromiseTier::ActiveSigning,
            Some(&kr),
            &contacts,
            Some(&psk_params),
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    assert_eq!(result.tier, CompromiseTier::ActiveSigning);
    assert!(result.new_did.is_none());
    assert_eq!(result.completed_contexts, vec!["ctx-1"]);
    assert!(result.contact_notification.succeeded());
    assert!(result.private_state_reencryption.succeeded());
}

// ---------------------------------------------------------------------------
// 3. compromise_tier_identity_key — IdentityKey rotates identity, DID changes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn compromise_tier_identity_key() {
    let alice = did("did:dht:alice");
    let alice_new = did("did:dht:alice-migrated");
    let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec!["ctx-1".to_owned()]);
    let kr = identity_key_rotation_outcome(&alice, alice_new.clone(), 3000);
    let contacts = HashSet::from([did("did:dht:bob"), did("did:dht:carol")]);
    let psk_params = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![vec![1u8; 32]],
        compromised_device_pubkey: None,
    };
    let backend = MockBackend::new();

    // IdentityKey tier: DID changes, both #active and #agent scopes rotated.
    assert_eq!(kr.tier, CompromiseTier::IdentityKey);
    assert_eq!(kr.did_after, alice_new);
    assert!(kr.did_changed);
    assert_eq!(kr.rotated_key_scopes, vec!["#active", "#agent"]);

    let result = orch
        .execute_recovery(
            CompromiseTier::IdentityKey,
            Some(&kr),
            &contacts,
            Some(&psk_params),
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    assert_eq!(result.tier, CompromiseTier::IdentityKey);
    assert_eq!(result.new_did, Some(alice_new));
    assert!(result.key_rotation_completed);
    assert!(result.contact_notification.succeeded());
    assert!(result.private_state_reencryption.succeeded());
}

// ---------------------------------------------------------------------------
// 4. key_rotation_outcome_fields — verify construction via helper functions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn key_rotation_outcome_fields() {
    let d = did("did:dht:z6MkTest");

    // Agent outcome.
    let agent = agent_key_rotation_outcome(&d, 100);
    assert_eq!(agent.tier, CompromiseTier::Agent);
    assert_eq!(agent.did_after, d);
    assert!(!agent.did_changed);
    assert_eq!(agent.rotated_key_scopes, vec!["#agent"]);
    assert_eq!(agent.rotated_at, 100);

    // Active outcome.
    let active = active_key_rotation_outcome(&d, 200);
    assert_eq!(active.tier, CompromiseTier::ActiveSigning);
    assert_eq!(active.did_after, d);
    assert!(!active.did_changed);
    assert_eq!(active.rotated_key_scopes, vec!["#active"]);
    assert_eq!(active.rotated_at, 200);

    // Identity outcome.
    let new_d = did("did:dht:z6MkTestNew");
    let identity = identity_key_rotation_outcome(&d, new_d.clone(), 300);
    assert_eq!(identity.tier, CompromiseTier::IdentityKey);
    assert_eq!(identity.did_after, new_d);
    assert!(identity.did_changed);
    assert_eq!(identity.rotated_key_scopes, vec!["#active", "#agent"]);
    assert_eq!(identity.rotated_at, 300);
}

// ---------------------------------------------------------------------------
// 5. contact_notification_construction — kcv_reverification_required per tier
// ---------------------------------------------------------------------------

#[tokio::test]
async fn contact_notification_construction() {
    let alice = did("did:dht:alice");

    // Agent compromise: no DID change, KCV re-verification still required
    // (the agent key is part of the trust chain).
    let notif_agent = ContactNotification {
        did: alice.clone(),
        new_did: None,
        tier: CompromiseTier::Agent,
        timestamp: 1_700_000_000_000,
        kcv_reverification_required: true,
    };
    assert!(notif_agent.new_did.is_none());
    assert!(notif_agent.kcv_reverification_required);
    assert_eq!(notif_agent.tier, CompromiseTier::Agent);

    // ActiveSigning compromise: no DID change, KCV re-verification required.
    let notif_active = ContactNotification {
        did: alice.clone(),
        new_did: None,
        tier: CompromiseTier::ActiveSigning,
        timestamp: 1_700_000_001_000,
        kcv_reverification_required: true,
    };
    assert!(notif_active.new_did.is_none());
    assert!(notif_active.kcv_reverification_required);

    // IdentityKey compromise: DID changes, KCV re-verification required.
    let alice_new = did("did:dht:alice-new");
    let notif_identity = ContactNotification {
        did: alice,
        new_did: Some(alice_new.clone()),
        tier: CompromiseTier::IdentityKey,
        timestamp: 1_700_000_002_000,
        kcv_reverification_required: true,
    };
    assert_eq!(notif_identity.new_did, Some(alice_new));
    assert!(notif_identity.kcv_reverification_required);
    assert_eq!(notif_identity.tier, CompromiseTier::IdentityKey);

    // Serialization roundtrip.
    let json = serde_json::to_string(&notif_identity).unwrap();
    let parsed: ContactNotification = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, notif_identity);
}

// ---------------------------------------------------------------------------
// 6. context_recovery_state_success — successful per-context state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_recovery_state_success() {
    let state = ContextRecoveryState {
        context_id: "ctx-success".to_owned(),
        mls_updated: true,
        ucan_revoked: true,
        key_packages_rotated: true,
        requires_rejoin: false,
        error: None,
    };
    assert!(state.is_complete());
    assert!(!state.requires_rejoin);
    assert!(state.error.is_none());

    // Also complete when requires_rejoin is true (MLS Update not possible,
    // but UCAN + KeyPackage steps succeeded).
    let state_rejoin = ContextRecoveryState {
        context_id: "ctx-rejoin".to_owned(),
        mls_updated: false,
        ucan_revoked: true,
        key_packages_rotated: true,
        requires_rejoin: true,
        error: None,
    };
    assert!(state_rejoin.is_complete());
    assert!(state_rejoin.requires_rejoin);
}

// ---------------------------------------------------------------------------
// 7. context_recovery_state_failure — failed context marks error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn context_recovery_state_failure() {
    // Fresh state: nothing completed.
    let fresh = ContextRecoveryState::new("ctx-fail".to_owned());
    assert!(!fresh.is_complete());
    assert!(!fresh.mls_updated);
    assert!(!fresh.ucan_revoked);
    assert!(!fresh.key_packages_rotated);
    assert!(!fresh.requires_rejoin);
    assert!(fresh.error.is_none());

    // State with an error is never complete, even if all bools are true.
    let state_with_error = ContextRecoveryState {
        context_id: "ctx-fail".to_owned(),
        mls_updated: true,
        ucan_revoked: true,
        key_packages_rotated: true,
        requires_rejoin: false,
        error: Some(RecoveryStepError {
            step: 3,
            code: RecoveryStepErrorCode::UcanRevocationUnwired,
            description: "UCAN revocation timeout".to_owned(),
        }),
    };
    assert!(!state_with_error.is_complete());

    // Missing individual steps.
    let missing_mls = ContextRecoveryState {
        context_id: "ctx-a".to_owned(),
        mls_updated: false,
        ucan_revoked: true,
        key_packages_rotated: true,
        requires_rejoin: false,
        error: None,
    };
    assert!(!missing_mls.is_complete());

    let missing_ucan = ContextRecoveryState {
        context_id: "ctx-b".to_owned(),
        mls_updated: true,
        ucan_revoked: false,
        key_packages_rotated: true,
        requires_rejoin: false,
        error: None,
    };
    assert!(!missing_ucan.is_complete());

    let missing_kp = ContextRecoveryState {
        context_id: "ctx-c".to_owned(),
        mls_updated: true,
        ucan_revoked: true,
        key_packages_rotated: false,
        requires_rejoin: false,
        error: None,
    };
    assert!(!missing_kp.is_complete());
}

// ---------------------------------------------------------------------------
// 8. recovery_result_completed_vs_failed — mixed success/failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_result_completed_vs_failed() {
    let alice = did("did:dht:alice");
    let orch = CompromiseRecoveryOrchestrator::new(
        alice.clone(),
        vec![
            "ctx-ok".to_owned(),
            "ctx-fail".to_owned(),
            "ctx-rejoin".to_owned(),
        ],
    );

    let kr = agent_key_rotation_outcome(&alice, 5000);
    let backend = MockBackend {
        // ctx-fail: MLS update fails fatally (not a rejoin case).
        mls_update_error: Some((
            "ctx-fail".to_owned(),
            RecoveryStepError {
                step: 2,
                code: RecoveryStepErrorCode::Unspecified,
                description: "MLS group unavailable".to_owned(),
            },
        )),
        ..MockBackend::new()
    };

    let result = orch
        .execute_recovery(
            CompromiseTier::Agent,
            Some(&kr),
            &HashSet::new(),
            None,
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    // ctx-ok succeeded, ctx-fail failed at step 2, ctx-rejoin succeeded
    // (the mock only fails for ctx-fail).
    assert!(result.completed_contexts.contains(&"ctx-ok".to_owned()));
    assert!(result.completed_contexts.contains(&"ctx-rejoin".to_owned()));
    assert_eq!(result.completed_contexts.len(), 2);
    assert_eq!(result.failed_contexts.len(), 1);
    assert_eq!(result.failed_contexts[0].0, "ctx-fail");
    assert_eq!(result.failed_contexts[0].1.step, 2);
    assert!(result.key_rotation_completed);
}

// ---------------------------------------------------------------------------
// 8b. recovery with rejoin context
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_result_with_rejoin_context() {
    let alice = did("did:dht:alice");
    let orch = CompromiseRecoveryOrchestrator::new(
        alice.clone(),
        vec!["ctx-ok".to_owned(), "ctx-rejoin".to_owned()],
    );

    let kr = agent_key_rotation_outcome(&alice, 6000);
    let backend = MockBackend {
        // ctx-rejoin triggers the Tier 3 rejoin path.
        mls_update_error: Some((
            "ctx-rejoin".to_owned(),
            RecoveryStepError {
                step: 2,
                code: RecoveryStepErrorCode::RequiresRejoin,
                description: "member requires rejoin".to_owned(),
            },
        )),
        ..MockBackend::new()
    };

    let result = orch
        .execute_recovery(
            CompromiseTier::Agent,
            Some(&kr),
            &HashSet::new(),
            None,
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    // ctx-ok completed normally.
    assert!(result.completed_contexts.contains(&"ctx-ok".to_owned()));
    // ctx-rejoin goes to pending_rejoin but UCAN + KeyPackage still succeed,
    // so it also appears in completed_contexts.
    assert!(result.pending_rejoin.contains(&"ctx-rejoin".to_owned()));
    assert!(result.failed_contexts.is_empty());
}

// ---------------------------------------------------------------------------
// 9. psk_rotation_params — construction and serialization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn psk_rotation_params() {
    // Without compromised device.
    let params_clean = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![vec![0xAA; 32], vec![0xBB; 32], vec![0xCC; 32]],
        compromised_device_pubkey: None,
    };
    assert_eq!(params_clean.enrolled_device_pubkeys.len(), 3);
    assert!(params_clean.compromised_device_pubkey.is_none());

    // With compromised device excluded.
    let params_compromised = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![vec![0xAA; 32], vec![0xBB; 32], vec![0xCC; 32]],
        compromised_device_pubkey: Some(vec![0xBB; 32]),
    };
    assert_eq!(
        params_compromised.compromised_device_pubkey.as_deref(),
        Some(vec![0xBB; 32].as_slice())
    );

    // Serialization roundtrip (JSON).
    let json = serde_json::to_string(&params_compromised).unwrap();
    let parsed: PskRotationParams = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.enrolled_device_pubkeys.len(), 3);
    assert!(parsed.compromised_device_pubkey.is_some());

    // ActiveSigning without PSK params → private_state_reencrypted is false.
    let alice = did("did:dht:alice");
    let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![]);
    let kr = active_key_rotation_outcome(&alice, 7000);
    let backend = MockBackend::new();

    let clock = scp_clock::SystemClock;
    let result = orch
        .execute_recovery(
            CompromiseTier::ActiveSigning,
            Some(&kr),
            &HashSet::new(),
            None,
            &backend,
            &clock,
        )
        .await
        .unwrap();
    assert!(!result.private_state_reencryption.succeeded());

    // With PSK params → step 6 runs and succeeds.
    let result_with = orch
        .execute_recovery(
            CompromiseTier::ActiveSigning,
            Some(&kr),
            &HashSet::new(),
            Some(&params_clean),
            &backend,
            &clock,
        )
        .await
        .unwrap();
    assert!(result_with.private_state_reencryption.succeeded());
}

// ---------------------------------------------------------------------------
// 10. recovery_error_variants — all RecoveryError variants constructable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_error_variants() {
    // KeyRotationFailed.
    let e1 = RecoveryError::KeyRotationFailed("HSM unreachable".to_owned());
    assert!(e1.to_string().contains("key rotation failed"));
    assert!(e1.to_string().contains("HSM unreachable"));

    // AgentKeyNotFound.
    let e2 = RecoveryError::AgentKeyNotFound;
    assert!(e2.to_string().contains("agent key not found"));

    // PreRotationKeyNotAvailable.
    let e3 = RecoveryError::PreRotationKeyNotAvailable;
    assert!(e3.to_string().contains("pre-rotation key"));

    // DidMethodError.
    let e4 = RecoveryError::DidMethodError("DHT publish failed".to_owned());
    assert!(e4.to_string().contains("DID method error"));
    assert!(e4.to_string().contains("DHT publish failed"));

    // CustodyError.
    let e5 = RecoveryError::CustodyError("keychain locked".to_owned());
    assert!(e5.to_string().contains("custody error"));
    assert!(e5.to_string().contains("keychain locked"));

    // AllContextsFailed (total per-context failure → fail-closed, #2240).
    let progress = RecoveryProgress {
        contexts_through_per_context_steps: Vec::new(),
        failed_contexts: vec![(
            "ctx-1".to_owned(),
            RecoveryStepError {
                step: 3,
                code: RecoveryStepErrorCode::UcanRevocationUnwired,
                description: "UCAN revocation is not wired for recovery".to_owned(),
            },
        )],
        pending_rejoin: Vec::new(),
        key_package_rotation: StepOutcome::Succeeded,
        contact_notification: StepOutcome::NotApplicable("no known contacts".to_owned()),
        private_state_reencryption: StepOutcome::NotApplicable("agent tier".to_owned()),
    };
    let e6 = RecoveryError::AllContextsFailed {
        attempted: 3,
        progress: progress.clone(),
    };
    assert!(e6.to_string().contains("all 3 context"));
    assert!(e6.to_string().contains("zero contexts recovered"));
    // The honest per-step reason must survive into the Display.
    assert!(e6.to_string().contains("UCAN revocation is not wired"));
    // A step that did not run must NOT read as having succeeded.
    assert!(e6.to_string().contains("did not run"));

    // KeyPackageRotationFailed (identity-scoped → fatal regardless of context
    // count, §9.12 "Step scope").
    let e7 = RecoveryError::KeyPackageRotationFailed {
        step_error: RecoveryStepError {
            step: 4,
            code: RecoveryStepErrorCode::KeyPackageRotationUnwired,
            description: "KeyPackage rotation is not wired".to_owned(),
        },
        progress,
    };
    assert!(
        e7.to_string()
            .contains("step 4 (KeyPackage rotation) failed")
    );
    assert!(
        e7.to_string()
            .contains("no context can be reported as recovered")
    );

    // RecoveryStepError Display.
    let step_err = RecoveryStepError {
        step: 4,
        code: RecoveryStepErrorCode::KeyPackageRotationUnwired,
        description: "KeyPackage publish timeout".to_owned(),
    };
    assert_eq!(step_err.to_string(), "step 4: KeyPackage publish timeout");
}

// ---------------------------------------------------------------------------
// 11. orchestrator_accessors — did() and context_ids()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn orchestrator_accessors() {
    let orch = CompromiseRecoveryOrchestrator::new(
        did("did:dht:z6MkTest"),
        vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
    );
    assert_eq!(*orch.did(), did("did:dht:z6MkTest"));
    assert_eq!(orch.context_ids().len(), 3);
    assert_eq!(orch.context_ids()[0], "a");
    assert_eq!(orch.context_ids()[2], "c");
}

// ---------------------------------------------------------------------------
// 12. recovery_with_contact_notification_failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_with_contact_notification_failure() {
    let alice = did("did:dht:alice");
    let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec!["ctx-1".to_owned()]);
    let kr = agent_key_rotation_outcome(&alice, 8000);
    let contacts = HashSet::from([did("did:dht:bob")]);

    let backend = MockBackend {
        notify_contacts_result: false,
        ..MockBackend::new()
    };

    let result = orch
        .execute_recovery(
            CompromiseTier::Agent,
            Some(&kr),
            &contacts,
            None,
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    // Per-context steps succeed, but contact notification failed.
    assert_eq!(result.completed_contexts, vec!["ctx-1"]);
    assert!(!result.contact_notification.succeeded());
}

// ---------------------------------------------------------------------------
// 13. recovery_with_psk_rotation_failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_with_psk_rotation_failure() {
    let alice = did("did:dht:alice");
    let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![]);
    let kr = active_key_rotation_outcome(&alice, 9000);
    let psk_params = PskRotationParams {
        did: "did:dht:zRecoveryTestIdentity".to_owned(),
        enrolled_device_pubkeys: vec![vec![1u8; 32]],
        compromised_device_pubkey: Some(vec![1u8; 32]),
    };

    let backend = MockBackend {
        rotate_psk_result: false,
        ..MockBackend::new()
    };

    let result = orch
        .execute_recovery(
            CompromiseTier::ActiveSigning,
            Some(&kr),
            &HashSet::new(),
            Some(&psk_params),
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    assert!(!result.private_state_reencryption.succeeded());
}

// ---------------------------------------------------------------------------
// 14. recovery_result_serialization — JSON + MessagePack roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_result_serialization() {
    let result = RecoveryResult {
        tier: CompromiseTier::ActiveSigning,
        did: did("did:dht:alice"),
        new_did: None,
        completed_contexts: vec!["ctx-1".to_owned()],
        failed_contexts: vec![(
            "ctx-2".to_owned(),
            RecoveryStepError {
                step: 2,
                code: RecoveryStepErrorCode::Unspecified,
                description: "MLS update failed".to_owned(),
            },
        )],
        pending_rejoin: vec!["ctx-3".to_owned()],
        key_rotation_completed: true,
        contact_notification: StepOutcome::Succeeded,
        private_state_reencryption: StepOutcome::Succeeded,
        initiated_at: 1000,
        completed_at: 2000,
    };

    // JSON roundtrip.
    let json = serde_json::to_string(&result).unwrap();
    let parsed: RecoveryResult = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.tier, CompromiseTier::ActiveSigning);
    assert_eq!(parsed.completed_contexts, vec!["ctx-1"]);
    assert_eq!(parsed.failed_contexts.len(), 1);
    assert_eq!(parsed.pending_rejoin, vec!["ctx-3"]);
    assert_eq!(parsed.initiated_at, 1000);
    assert_eq!(parsed.completed_at, 2000);

    // MessagePack roundtrip.
    let bytes = rmp_serde::to_vec(&result).unwrap();
    let parsed_mp: RecoveryResult = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(parsed_mp.tier, result.tier);
    assert_eq!(parsed_mp.did, result.did);
    assert_eq!(parsed_mp.completed_contexts, result.completed_contexts);
}

// ---------------------------------------------------------------------------
// 15. recovery_with_no_contexts — edge case
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_with_no_contexts() {
    let alice = did("did:dht:alice");
    let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![]);
    let kr = agent_key_rotation_outcome(&alice, 10_000);
    let backend = MockBackend::new();

    let result = orch
        .execute_recovery(
            CompromiseTier::Agent,
            Some(&kr),
            &HashSet::new(),
            None,
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

    assert!(result.completed_contexts.is_empty());
    assert!(result.failed_contexts.is_empty());
    assert!(result.pending_rejoin.is_empty());
    assert!(result.key_rotation_completed);
    // No contacts to notify: step 5 does not run, so NotApplicable — not
    // success. (The old `bool` reported `true` here for a step that never ran.)
    assert!(matches!(
        result.contact_notification,
        StepOutcome::NotApplicable(_)
    ));
    assert!(result.completed_at >= result.initiated_at);
}
