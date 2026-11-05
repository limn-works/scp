//! Tests of the governance domain moved from `scp-runtime-core`
//! `context::actor::class_s` (ADR-070 §6.1): they call a function private to this domain.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_runtime_core::context::actor::deps::ActorDeps;
use scp_runtime_core::context::actor::state::PerContextState;

use scp_platform::in_memory::InMemoryStorage;
use scp_runtime_core::context::actor::class_s::*;
use scp_runtime_core::context::persistence::ContextPersistence;
use std::sync::Arc;

/// Minimal event log provider — accepts every call (the combinator paths do
/// not touch the event log).
struct TestEventLog;
#[async_trait::async_trait]
impl scp_runtime_core::context::builder::ContextEventLogProvider for TestEventLog {
    fn event_log_entries(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(None)
    }

    async fn init_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event_type: scp_event_log::EventType,
        _actor: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// Persistence that accepts every write (success path).
struct OkPersistence;
/// Persistence whose `persist_context` ALWAYS fails (fail-closed path).
struct FailPersistence;
/// Assemble an `ActorDeps` with the supplied persistence backend (and the
/// minimal `TestEventLog`, whose entry reads are empty).
async fn build_deps(persistence: Box<dyn ContextPersistence>) -> ActorDeps {
    build_deps_with_event_log(persistence, Box::new(TestEventLog)).await
}

/// Assemble an `ActorDeps` with the supplied persistence backend AND a custom
/// event-log provider — used by the paid-send-with-suspension test, which seeds
/// a `GovernanceAction` into a real [`MerkleEventLogProvider`] so the
/// consequence engine reads convergent `WarningCount` evidence (Source 1 of
/// `event_log_entries_for_consequences`; the receive buffer never sources
/// governance events).
async fn build_deps_with_event_log(
    persistence: Box<dyn ContextPersistence>,
    event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider>,
) -> ActorDeps {
    use scp_runtime_core::context::supervisor::supervisor::Supervisor;

    let crypto = Arc::new(
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MktestClassSCell".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ),
    );
    let transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider> =
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider);
    let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(
        scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ),
    );
    let supervisor = Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        Some(persistence),
        None,
        None,
        None,
        mls_storage,
        crate::test_support::test_domain_handlers(),
    );
    scp_runtime_core::context::supervisor::supervisor::leak_for_test(&supervisor);
    supervisor
        .build_actor_deps_loaded(&DID("did:example:class-s-cell-test".to_owned()))
        .await
        .expect("build_actor_deps")
}

/// A fresh encrypted test state.
fn fresh_state(ctx_byte: u8) -> PerContextState {
    PerContextState::new_for_test_encrypted(
        [ctx_byte; 32],
        1_700_000_000,
        DID("did:example:admin".to_owned()),
    )
}

fn ctx_hex(byte: u8) -> String {
    let mut s = String::with_capacity(64);
    for _ in 0..32 {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

// ------------------------------------------------------------------
// execute_modify_ceiling — propose-time ceiling-entry grammar gate
// (spec §5.3.1.1 / §5.3.2). A malformed proposed ceiling is rejected
// at PROPOSE/STAGE time (before the 72h notification window), and no
// pending modification is staged. A well-formed proposal stages.
// ------------------------------------------------------------------

/// Build an ACTIVE, `Governed`-ceiling-policy cell so `execute_modify_ceiling`
/// reaches its staging logic. The default `ContextParams` ceiling policy is
/// `Immutable`; ceiling modification requires `Governed`.
fn active_governed_cell(ctx_byte: u8) -> ClassSCell {
    let mut state = fresh_state(ctx_byte);
    let params = scp_protocol::context::params::ContextParams {
        ceiling_policy: scp_protocol::context::params::CeilingPolicy::Governed,
        ..scp_protocol::context::params::ContextParams::default()
    };
    // Replace the handle with one carrying the Governed policy, then activate.
    state.handle = scp_runtime_core::context::ContextHandle::new(ctx_hex(ctx_byte), params);
    state
        .handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .expect("transition to Active");
    ClassSCell::new_for_test(state)
}

fn ceiling_commit_meta() -> scp_runtime_core::context::shared::governance::CommitMeta<'static> {
    scp_runtime_core::context::shared::governance::CommitMeta {
        pid: [7u8; 32],
        actor_did: "did:example:admin",
        timestamp_secs: 1_700_000_000,
    }
}

// ------------------------------------------------------------------
// execute_modify_capability_requirements — the direction a failed
// persist leaves the live list in is chosen by the delta (spec 07
// §7.3.4.4): a tightening stays in force, anything else is restored.
// ------------------------------------------------------------------

fn self_attested_requirements(uris: &[&str]) -> scp_protocol::trust::CapabilityRequirements {
    let list: Vec<scp_protocol::trust::CapabilityRequirement> = uris
        .iter()
        .map(|uri| {
            scp_protocol::trust::RawCapabilityRequirement {
                capability: uri.parse().expect("capability URI"),
                verification_level: scp_protocol::trust::VerificationLevel::SelfAttested,
                trusted_verifiers: Vec::new(),
                retry_cap: None,
            }
            .try_into()
            .expect("valid requirement")
        })
        .collect();
    list.try_into().expect("valid requirement list")
}

/// A failed persist keeps a tightening in force and restores the old list
/// for a loosening and for a mixed change.
#[tokio::test]
async fn governance_modify_capability_requirements_failure_direction() {
    let deps = build_deps(Box::new(FailPersistence)).await;
    let schema = "scp:capability:schema-validation/v1";
    let safety = "scp:capability:content-safety/v1";
    // (old list, new list, whether the new list is a tightening)
    let cases: [(&[&str], &[&str], bool); 3] = [
        (&[schema], &[schema, safety], true),
        (&[schema, safety], &[schema], false),
        (&[schema], &[safety], false),
    ];
    for (byte, (old, new, tightening)) in (0xD0u8..).zip(cases) {
        let old = self_attested_requirements(old);
        let new = self_attested_requirements(new);
        assert_eq!(new.is_tightening_of(&old), tightening);
        let mut state = fresh_state(byte);
        state.handle = scp_runtime_core::context::ContextHandle::new(
            ctx_hex(byte),
            scp_protocol::context::params::ContextParams::default(),
        );
        state
            .handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .expect("transition to Active");
        state.governance_mut().class_s.capability_requirements =
            scp_runtime_core::context::state::Replicated::Live(old.clone());
        let mut cell = ClassSCell::new_for_test(state);

        let result = crate::helpers::execute_modify_capability_requirements(
            &mut cell,
            &deps,
            &ctx_hex(byte),
            &new,
            ceiling_commit_meta(),
        )
        .await;

        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "a failed persist surfaces; got {result:?}"
        );
        let expected = if tightening { &new } else { &old };
        assert_eq!(
            &cell.governance().class_s.capability_requirements,
            &scp_runtime_core::context::state::Replicated::Live(expected.clone()),
            "tightening {tightening}: the live list after a failed persist"
        );
    }
}

/// T21, after replication. A joiner awaiting the live list takes the list
/// a `ModifyCapabilityRequirements` sets, and admission then reads it; a
/// failed persist of that first list leaves the joiner awaiting.
#[tokio::test]
async fn awaiting_joiner_takes_the_list_governance_sets() {
    let tightened = self_attested_requirements(&[
        "scp:capability:schema-validation/v1",
        "scp:capability:code-execution/v1",
    ]);
    for (byte, persistence, expected) in [
        (
            0x71_u8,
            Box::new(scp_runtime_core::context::providers::persistence::InMemoryPersistence::new())
                as Box<dyn ContextPersistence>,
            scp_runtime_core::context::state::Replicated::Live(tightened.clone()),
        ),
        (
            0x72,
            Box::new(FailPersistence),
            scp_runtime_core::context::state::Replicated::AwaitingReplication,
        ),
    ] {
        let deps = build_deps(persistence).await;
        let mut state = fresh_state(byte);
        state.handle = scp_runtime_core::context::ContextHandle::new(
            ctx_hex(byte),
            scp_protocol::context::params::ContextParams::default(),
        );
        state
            .handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .expect("transition to Active");
        state.governance_mut().class_s.capability_requirements =
            scp_runtime_core::context::state::Replicated::AwaitingReplication;
        assert!(scp_runtime_queries::testing_access::capability_requirements(&state).is_err());
        let mut cell = ClassSCell::new_for_test(state);
        let _ = crate::helpers::execute_modify_capability_requirements(
            &mut cell,
            &deps,
            &ctx_hex(byte),
            &tightened,
            ceiling_commit_meta(),
        )
        .await;
        assert_eq!(cell.governance().class_s.capability_requirements, expected);
    }
}

#[tokio::test]
async fn execute_modify_ceiling_rejects_malformed_proposal_at_propose_time() {
    use scp_protocol::context::roles::Capability;

    let deps = build_deps(Box::new(OkPersistence)).await;
    let ctx_id = ctx_hex(0xC1);

    // Each malformed entry must be rejected BEFORE staging.
    for malformed in [
        Capability::Custom("payments".to_owned()), // no colon
        Capability::Custom("*:*".to_owned()),      // stray wildcard resource
        Capability::Custom("a:b:c".to_owned()),    // multi-colon (3 segments)
    ] {
        let mut cell = active_governed_cell(0xC1);
        let new_ceiling = vec![Capability::MessagesRead, malformed.clone()];
        let res = crate::helpers::execute_modify_ceiling(
            &mut cell,
            &deps,
            &ctx_id,
            &new_ceiling,
            ceiling_commit_meta(),
        )
        .await;
        assert!(
            matches!(res, Err(ContextError::InvalidState(_))),
            "malformed proposed ceiling entry {malformed:?} must be rejected at \
                 propose time: {res:?}"
        );
        // Fail-closed: nothing was staged.
        assert!(
            cell.governance().pending_ceiling_modification.is_none(),
            "a rejected malformed ceiling proposal must NOT stage a pending \
                 modification (entry {malformed:?})"
        );
    }
}

#[tokio::test]
async fn execute_modify_ceiling_stages_wellformed_proposal() {
    use scp_protocol::context::roles::Capability;

    let deps = build_deps(Box::new(OkPersistence)).await;
    let ctx_id = ctx_hex(0xC2);
    let mut cell = active_governed_cell(0xC2);

    let new_ceiling = vec![
        Capability::MessagesRead,
        Capability::Custom("payments:approve".to_owned()),
        Capability::Custom("billing:*".to_owned()),
    ];
    let res = crate::helpers::execute_modify_ceiling(
        &mut cell,
        &deps,
        &ctx_id,
        &new_ceiling,
        ceiling_commit_meta(),
    )
    .await;
    assert!(
        res.is_ok(),
        "well-formed ceiling proposal must stage: {res:?}"
    );
    let pending = cell
        .governance()
        .pending_ceiling_modification
        .as_ref()
        .expect("well-formed proposal stages a pending modification");
    assert_eq!(
        pending.new_capabilities, new_ceiling,
        "staged pending modification carries the proposed capabilities verbatim"
    );
}

macro_rules! impl_persistence {
    ($ty:ty, $persist_result:expr) => {
        #[async_trait::async_trait]
        impl ContextPersistence for $ty {
            async fn persist_context(
                &self,
                _: &str,
                _: &scp_runtime_core::context::state::ContextSnapshot,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                $persist_result
            }
            async fn load_context(
                &self,
                _: &str,
            ) -> Result<
                Option<scp_runtime_core::context::state::ContextSnapshot>,
                Box<dyn std::error::Error + Send + Sync>,
            > {
                Ok(None)
            }
            async fn delete_context(
                &self,
                _: &str,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
            async fn list_persisted_contexts(
                &self,
            ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
                Ok(Vec::new())
            }
        }
    };
}

impl_persistence!(OkPersistence, Ok(()));
impl_persistence!(FailPersistence, Err("induced persist failure".into()));
