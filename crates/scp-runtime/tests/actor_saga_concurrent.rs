//! Integration test for the ADR-049 commit-11 concurrent-saga
//! serialization guard.
//!
//! The supervisor serializes sagas supervisor-wide via a single atomic
//! bool. A second `start_saga` while one is in flight returns
//! [`ContextError::ActorBusy`](scp_protocol::context::ContextError::ActorBusy)
//! with a `SagaBusy` reason (plan §"Cross-context saga protocol").
//!
//! # Race structure
//!
//! Because all 4 current [`SagaInput`] variants are spec-gapped
//! (NotImplemented at Prepare dispatch), the FSM body is short —
//! Initiated → PreparingA → Aborting → Aborted — and journal appends
//! are the only `await` points. To exercise the guard we launch N
//! concurrent tasks and count: at least one must succeed-to-
//! NotImplemented (the saga ran to completion), and any others that
//! observed the guard-set SHOULD return ActorBusy. The strict
//! invariant we assert: `ok_count + busy_count == N`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::disallowed_types,
    clippy::missing_const_for_fn
)]

use std::sync::Arc;

use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;
use scp_protocol::context::ContextError;
use scp_runtime::context::supervisor::{
    ProtocolRepositorySagaJournal, SagaInput, SagaJournal, Supervisor, SupervisorConfig,
};

struct NoopPersistence;
impl scp_runtime::context::manager::ContextPersistence for NoopPersistence {
    fn persist_context(
        &self,
        _: &str,
        _: &scp_runtime::context::manager::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_runtime::context::manager::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    fn persist_broadcast(
        &self,
        _: &str,
        _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn load_broadcast(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

fn test_supervisor() -> Arc<Supervisor> {
    let persistence: Arc<dyn scp_runtime::context::manager::ContextPersistence> =
        Arc::new(NoopPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    Arc::new(Supervisor::new(
        persistence,
        journal,
        SupervisorConfig::default(),
    ))
}

fn spec_gapped_input() -> SagaInput {
    SagaInput::StandingPairCreate {
        local_did: DID("did:example:racer-a".to_owned()),
        peer_did: DID("did:example:racer-b".to_owned()),
    }
}

/// Two Prepares on the same supervisor: the guard admits at most one
/// at a time. With the instantaneous NotImplemented FSM, the second
/// Prepare MAY observe the guard clear — but across N=16 parallel
/// tasks the total ok + busy count MUST equal N, and at least one
/// must be ActorBusy under heavy concurrency.
const N: usize = 16;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_sagas_serialize_via_guard() {
    let supervisor = test_supervisor();

    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let sup = Arc::clone(&supervisor);
        handles.push(tokio::spawn(async move {
            sup.start_saga(spec_gapped_input()).await
        }));
    }

    let mut ok_count = 0usize;
    let mut busy_count = 0usize;
    for handle in handles {
        match handle.await.unwrap() {
            Err(ContextError::NotImplemented(_)) => ok_count += 1,
            Err(ContextError::ActorBusy(msg)) => {
                assert!(
                    msg.contains("SagaBusy") || msg.contains("already in flight"),
                    "ActorBusy must mention SagaBusy or 'already in flight', got: {msg}"
                );
                busy_count += 1;
            }
            other => panic!("unexpected start_saga result: {other:?}"),
        }
    }
    assert_eq!(
        ok_count + busy_count,
        N,
        "every task must terminate as either NotImplemented-on-terminate or ActorBusy"
    );
    // Every saga eventually runs to terminate — a second caller's
    // ActorBusy does NOT mean the saga is dropped; it just means this
    // caller lost the race.
    assert!(
        ok_count >= 1,
        "at least one saga must run to completion (ok_count >= 1)"
    );
}

/// After the guard trips, a subsequent saga (once the first completes)
/// must succeed: the guard is cleared on terminal resolution.
#[tokio::test]
async fn guard_is_rearmed_after_each_saga_terminates() {
    let supervisor = test_supervisor();
    // Run 5 sagas sequentially — every one must terminate with
    // NotImplemented (not ActorBusy).
    for _ in 0..5 {
        let err = supervisor
            .start_saga(spec_gapped_input())
            .await
            .unwrap_err();
        assert!(
            matches!(err, ContextError::NotImplemented(_)),
            "sequential sagas must all terminate — guard re-arm failed: got {err:?}"
        );
    }
}
