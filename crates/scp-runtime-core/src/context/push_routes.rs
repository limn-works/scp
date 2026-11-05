//! The push routes the actor reports to the Supervisor on every turn
//! (`10-infrastructure-and-self-hosting.md` §10.7.1; ADR-070 §1.4).
use crate::context::actor::state::PerContextState;
use scp_protocol::context::ContextState;
use scp_protocol::context::broadcast_routing_id;
use scp_protocol::context::context_routing_id;

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

/// One context's push-wake pull target (ADR-029 §2, push-wake pull mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextWakeTarget {
    /// The context's ID.
    pub context_id: String,
    /// The context's persisted relay set, as `PerContextState::relay_urls`
    /// holds it. The wake dials the union of these (ADR-025 criterion 4).
    pub relay_urls: Vec<String>,
    /// The routing IDs the pull queries: the shared routing ID and the
    /// current local pseudonym routing ID. A routing ID on the query-only list
    /// is left to reconnect catch-up (`09-security-model.md` §9.10.4.1
    /// "Reconnect catch-up", ADR-029 §2). A broadcast context yields
    /// `broadcast_routing_id` alone.
    pub routing_ids: Vec<[u8; 32]>,
}
