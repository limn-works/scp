//! Tools helpers -- actor-shape signatures
//! (ADR-049 Phase 2A.4, `tools` domain migration).
//!
//! # Purpose
//!
//! This module hosts tools-domain helpers that actor handlers call with
//! actor-owned state. The legacy `&Supervisor` bodies, including the
//! sync/runtime-agnostic FFI surfaces and generic tool invocation
//! wrapper, live in [`crate::context::tools_helpers_legacy`] until
//! Phase 2A finalization removes the shim fallback.

use scp_identity::DID;

use crate::context::actor::state::PerContextState;

pub use crate::context::tools_helpers_legacy::ManagedToolInvocationOutput;

// ---------------------------------------------------------------------------
// try_consume_hard_rate_limit (actor-handler entry point)
// ---------------------------------------------------------------------------

/// Async hard-rate-limit consume for a live context actor.
///
/// Returns `true` if a token was consumed and `false` when the sender is
/// over budget. Unknown-context pass-through remains in the supervisor
/// shim fallback; once a command reaches this helper, the context actor
/// already owns the target [`PerContextState`].
#[must_use]
#[allow(clippy::needless_pass_by_ref_mut)] // PerContextState is Send + !Sync; &mut keeps actor futures Send.
pub fn try_consume_hard_rate_limit(state: &mut PerContextState, did: &DID, now_secs: u64) -> bool {
    state.governance.hard_rate_limit.try_consume(did, now_secs)
}

// ---------------------------------------------------------------------------
// refund_hard_rate_limit (actor-handler entry point)
// ---------------------------------------------------------------------------

/// Refund one hard-rate-limit token for a live context actor.
///
/// Unknown-context no-op behavior remains in the supervisor shim
/// fallback; the actor path only runs after mailbox lookup succeeds.
#[allow(clippy::needless_pass_by_ref_mut)] // PerContextState is Send + !Sync; &mut keeps actor futures Send.
pub fn refund_hard_rate_limit(state: &mut PerContextState, did: &DID) {
    state.governance.hard_rate_limit.refund(did);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_did() -> DID {
        DID::from("did:test:tools-rate-limit")
    }

    fn test_admin() -> DID {
        DID::from("did:test:admin")
    }

    #[test]
    fn consume_hard_rate_limit_uses_actor_owned_state() {
        let did = test_did();
        let mut state = PerContextState::new_for_test_encrypted([9u8; 32], 1, test_admin());

        assert!(try_consume_hard_rate_limit(&mut state, &did, 10));
    }

    #[test]
    fn refund_hard_rate_limit_restores_actor_owned_bucket() {
        let did = test_did();
        let mut state = PerContextState::new_for_test_encrypted([10u8; 32], 1, test_admin());

        for _ in 0..10 {
            assert!(try_consume_hard_rate_limit(&mut state, &did, 10));
        }
        assert!(!try_consume_hard_rate_limit(&mut state, &did, 10));
        refund_hard_rate_limit(&mut state, &did);
        assert!(try_consume_hard_rate_limit(&mut state, &did, 10));
    }
}
