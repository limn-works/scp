//! Tests of the queries domain moved from `scp-runtime-core`
//! `context::actor::pseudonym_rotation` (ADR-070 §6.1): they call a function private to this domain.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_protocol::context::params::PseudonymRotationPolicy;
use scp_runtime_core::context::actor::state::PerContextState;

use scp_runtime_core::context::actor::pseudonym_rotation::*;

const T0: u64 = 1_700_000_000;
const I: u64 = 3_600;

fn interval_policy() -> PseudonymRotationPolicy {
    PseudonymRotationPolicy {
        interval_secs: Some(I),
        on_membership_change: false,
    }
}

const LOCAL: &str = "did:dht:z6MkRotationUnitLocal";

fn context_state(policy: Option<PseudonymRotationPolicy>) -> PerContextState {
    let mut state =
        PerContextState::new_for_test_encrypted([0x31; 32], T0, scp_did::DID(LOCAL.to_owned()));
    state.handle = scp_runtime_core::context::ContextHandle::new(
        state.handle.context_id().to_owned(),
        scp_protocol::context::ContextParams {
            pseudonym_rotation: policy,
            ..scp_protocol::context::ContextParams::default()
        },
    );
    state.creation_timestamp_secs = T0;
    state.routing.set_local_pseudonym([9; 32]);
    state
}

/// Spec 09 §9.10.4.1 "Query-only list": from the moment of the rotation,
/// the previous routing ID is on the query-only list until rotation time +
/// `MAX_BLOB_TTL`, and `local_routing_ids` reports it until then.
#[test]
fn local_routing_ids_reports_a_query_only_routing_id_until_its_expiry() {
    let policy = interval_policy();
    let mut state = context_state(Some(policy));
    state
        .class_s_mut()
        .pseudonym_rotation
        .record_rotation(1, [9; 32], Some(&policy), T0 + I)
        .unwrap();
    let expiry = T0 + I + u64::from(scp_relay_client::MAX_BLOB_TTL);
    let at_rotation = crate::helpers::local_routing_ids(&state, T0 + I).unwrap();
    assert_eq!(
        at_rotation.query_only,
        vec![QueryOnlyRoutingId {
            routing_id: [9; 32],
            expires_at_secs: expiry,
        }]
    );
    let last = crate::helpers::local_routing_ids(&state, expiry - 1).unwrap();
    assert_eq!(last.query_only.len(), 1);
    let expired = crate::helpers::local_routing_ids(&state, expiry).unwrap();
    assert!(expired.query_only.is_empty(), "{expired:?}");
}
