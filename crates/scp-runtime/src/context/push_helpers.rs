//! Push-domain helpers: the routing IDs a device registers for wakes
//! (`10-infrastructure-and-self-hosting.md` §10.7.1).
//!
//! A `PushRegistration` lists the routing IDs at which a blob for this device
//! arrives on one relay. [`push_routes`] reads one context's share of that list
//! from the actor-owned state, and
//! [`Supervisor::push_routing_ids`](crate::context::supervisor::Supervisor::push_routing_ids)
//! fans the read across every context actor and groups the answers by relay URL.

use scp_protocol::context::{ContextState, broadcast_routing_id, context_routing_id};

use crate::context::actor::state::PerContextState;

/// One context's push routes. Holds no context ID, so the relay grouping the
/// Supervisor builds from these carries none either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPushRoutes {
    /// The context's relay set, as `PerContextState::relay_urls` holds it.
    pub relay_urls: Vec<String>,
    /// The routing IDs on those relays at which a blob for this device arrives:
    /// the shared routing ID, plus this device's pseudonym routing ID in an
    /// encrypted context (`09-security-model.md` §9.10.4).
    pub routing_ids: Vec<[u8; 32]>,
}

/// Returns the push routes of the context `state` holds, or `None` when the
/// context is `Closed`, `Expired` or `Tombstoned`, because a terminal context
/// receives no traffic to wake the device for.
///
/// An encrypted context yields `context_routing_id` and the local pseudonym
/// routing ID that `state.routing` holds now, so a query after the local
/// pseudonym changes returns the new one. The all-zero pseudonym is the
/// "no pseudonym derived" sentinel (§9.10.4), not a routing ID, and is left out.
/// A broadcast context carries no pseudonym and yields `broadcast_routing_id`.
#[must_use]
pub fn push_routes(state: &PerContextState) -> Option<ContextPushRoutes> {
    if matches!(
        state.handle.state(),
        ContextState::Closed | ContextState::Expired | ContextState::Tombstoned
    ) {
        return None;
    }
    let context_id = state.handle.context_id();
    let routing_ids = match state.routing.local_pseudonym() {
        Some(pseudonym) if pseudonym == [0u8; 32] => vec![context_routing_id(context_id)],
        Some(pseudonym) => vec![context_routing_id(context_id), pseudonym],
        None => vec![broadcast_routing_id(context_id)],
    };
    Some(ContextPushRoutes {
        relay_urls: state.relay_urls.clone(),
        routing_ids,
    })
}

#[cfg(test)]
mod tests {
    use scp_did::DID;
    use scp_protocol::context::{
        ContextParams, ContextState, broadcast_routing_id, context_routing_id,
    };

    use super::{ContextPushRoutes, push_routes};
    use crate::context::ContextHandle;
    use crate::context::actor::state::{ContextRouting, PerContextState};

    const RELAY: &str = "wss://relay.example/scp/v1";

    fn admin() -> DID {
        DID("did:dht:z6MkPushRoutesAdmin".to_owned())
    }

    fn encrypted(pseudonym: [u8; 32]) -> PerContextState {
        let mut state = PerContextState::new_for_test_encrypted([0x51; 32], 1, admin());
        state.routing = ContextRouting::for_mode(false, pseudonym);
        state.relay_urls = vec![RELAY.to_owned()];
        state
    }

    #[test]
    fn encrypted_context_yields_shared_and_local_pseudonym_routing_ids() {
        let state = encrypted([0x77; 32]);
        let shared = context_routing_id(state.handle.context_id());
        assert_eq!(
            push_routes(&state),
            Some(ContextPushRoutes {
                relay_urls: vec![RELAY.to_owned()],
                routing_ids: vec![shared, [0x77; 32]],
            })
        );
    }

    #[test]
    fn zero_pseudonym_sentinel_is_not_a_routing_id() {
        let state = encrypted([0u8; 32]);
        let shared = context_routing_id(state.handle.context_id());
        assert_eq!(
            push_routes(&state).map(|r| r.routing_ids),
            Some(vec![shared])
        );
    }

    #[test]
    fn broadcast_context_yields_broadcast_routing_id() {
        let mut state = PerContextState::new_for_test_broadcast([0x52; 32], 1, admin());
        state.relay_urls = vec![RELAY.to_owned()];
        let rid = broadcast_routing_id(state.handle.context_id());
        assert_eq!(push_routes(&state).map(|r| r.routing_ids), Some(vec![rid]));
    }

    #[test]
    fn terminal_context_yields_no_routes() {
        let paths = [
            vec![ContextState::Closing, ContextState::Closed],
            vec![ContextState::Expired],
            vec![ContextState::MigratingOut, ContextState::Tombstoned],
        ];
        for path in paths {
            let mut state = encrypted([0x77; 32]);
            let context_id = state.handle.context_id().to_owned();
            state.handle = ContextHandle::new(context_id, ContextParams::default());
            assert!(
                state.handle.transition_to(&ContextState::Active).is_ok(),
                "Creating to Active"
            );
            for step in &path[..path.len() - 1] {
                assert!(
                    state.handle.transition_to(step).is_ok(),
                    "non-terminal step"
                );
                assert!(
                    push_routes(&state).is_some(),
                    "{step:?} still yields routes"
                );
            }
            let terminal = &path[path.len() - 1];
            assert!(
                state.handle.transition_to(terminal).is_ok(),
                "terminal step"
            );
            assert_eq!(push_routes(&state), None, "{terminal:?} yields no routes");
        }
    }
}
