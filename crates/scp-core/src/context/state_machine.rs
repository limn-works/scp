//! Context lifecycle state transition logic.
//!
//! Implements the five-state finite state machine for SCP contexts:
//! `Creating -> Active -> Closing -> Closed`, with `Expired` as a terminal
//! state reachable from `Active` when TTL elapses. See ADR-008 in
//! `.docs/adrs/phase-2.md`.
//!
//! The transition function is pure -- it validates the requested state
//! transition and returns the new state or an error. It has no side effects.
//! Side effects (MLS group creation, event log writes, etc.) are the
//! responsibility of the Context Manager (SCP-019/020).

use super::{ContextError, ContextState};

/// Validates and executes a context state transition.
///
/// Returns the new state on success, or a [`ContextError::InvalidTransition`]
/// on failure. The function is pure -- no side effects occur.
///
/// # Valid transitions
///
/// | From | To | Trigger |
/// |------|-----|---------|
/// | `Creating` | `Active` | MLS group formed, parameters committed |
/// | `Active` | `Closing` | Close initiated by admin/governance |
/// | `Active` | `Expired` | TTL elapsed (automatic) |
/// | `Closing` | `Closed` | All members processed final events |
///
/// # Invalid transitions
///
/// - `Closed -> *` (terminal state)
/// - `Expired -> *` (terminal state)
/// - `Creating -> Closing` (never active, just drop)
/// - `Closing -> Active` (no re-opening)
/// - Any self-transition (e.g., `Active -> Active`)
///
/// # Errors
///
/// Returns [`ContextError::InvalidTransition`] with the source and target
/// states when the requested transition is not permitted.
pub fn transition(
    current: &ContextState,
    target: &ContextState,
) -> Result<ContextState, ContextError> {
    // Self-transitions are always invalid.
    if current == target {
        return Err(ContextError::InvalidTransition {
            from: current.clone(),
            to: target.clone(),
        });
    }

    match (current, target) {
        // Valid transitions per ADR-008.
        (ContextState::Creating, ContextState::Active)
        | (ContextState::Active, ContextState::Closing | ContextState::Expired)
        | (ContextState::Closing, ContextState::Closed) => Ok(target.clone()),

        // Everything else is invalid.
        _ => Err(ContextError::InvalidTransition {
            from: current.clone(),
            to: target.clone(),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Valid transitions
    // -----------------------------------------------------------------------

    #[test]
    fn transition_creating_to_active_succeeds() {
        let result = transition(&ContextState::Creating, &ContextState::Active);
        assert_eq!(result.ok(), Some(ContextState::Active));
    }

    #[test]
    fn transition_active_to_closing_succeeds() {
        let result = transition(&ContextState::Active, &ContextState::Closing);
        assert_eq!(result.ok(), Some(ContextState::Closing));
    }

    #[test]
    fn transition_active_to_expired_succeeds() {
        let result = transition(&ContextState::Active, &ContextState::Expired);
        assert_eq!(result.ok(), Some(ContextState::Expired));
    }

    #[test]
    fn transition_closing_to_closed_succeeds() {
        let result = transition(&ContextState::Closing, &ContextState::Closed);
        assert_eq!(result.ok(), Some(ContextState::Closed));
    }

    // -----------------------------------------------------------------------
    // Invalid transitions from terminal state: Closed
    // -----------------------------------------------------------------------

    #[test]
    fn transition_closed_to_creating_returns_error() {
        let result = transition(&ContextState::Closed, &ContextState::Creating);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::InvalidTransition {
                from: ContextState::Closed,
                to: ContextState::Creating,
            }
        ));
    }

    #[test]
    fn transition_closed_to_active_returns_error() {
        let result = transition(&ContextState::Closed, &ContextState::Active);
        assert!(result.is_err());
    }

    #[test]
    fn transition_closed_to_closing_returns_error() {
        let result = transition(&ContextState::Closed, &ContextState::Closing);
        assert!(result.is_err());
    }

    #[test]
    fn transition_closed_to_expired_returns_error() {
        let result = transition(&ContextState::Closed, &ContextState::Expired);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Invalid transitions from terminal state: Expired
    // -----------------------------------------------------------------------

    #[test]
    fn transition_expired_to_creating_returns_error() {
        let result = transition(&ContextState::Expired, &ContextState::Creating);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::InvalidTransition {
                from: ContextState::Expired,
                to: ContextState::Creating,
            }
        ));
    }

    #[test]
    fn transition_expired_to_active_returns_error() {
        let result = transition(&ContextState::Expired, &ContextState::Active);
        assert!(result.is_err());
    }

    #[test]
    fn transition_expired_to_closing_returns_error() {
        let result = transition(&ContextState::Expired, &ContextState::Closing);
        assert!(result.is_err());
    }

    #[test]
    fn transition_expired_to_closed_returns_error() {
        let result = transition(&ContextState::Expired, &ContextState::Closed);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Invalid transitions: Creating -> Closing (never active, just drop)
    // -----------------------------------------------------------------------

    #[test]
    fn transition_creating_to_closing_returns_error() {
        let result = transition(&ContextState::Creating, &ContextState::Closing);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::InvalidTransition {
                from: ContextState::Creating,
                to: ContextState::Closing,
            }
        ));
    }

    #[test]
    fn transition_creating_to_closed_returns_error() {
        let result = transition(&ContextState::Creating, &ContextState::Closed);
        assert!(result.is_err());
    }

    #[test]
    fn transition_creating_to_expired_returns_error() {
        let result = transition(&ContextState::Creating, &ContextState::Expired);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Invalid transitions: Closing -> Active (no re-opening)
    // -----------------------------------------------------------------------

    #[test]
    fn transition_closing_to_active_returns_error() {
        let result = transition(&ContextState::Closing, &ContextState::Active);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::InvalidTransition {
                from: ContextState::Closing,
                to: ContextState::Active,
            }
        ));
    }

    #[test]
    fn transition_closing_to_creating_returns_error() {
        let result = transition(&ContextState::Closing, &ContextState::Creating);
        assert!(result.is_err());
    }

    #[test]
    fn transition_closing_to_expired_returns_error() {
        let result = transition(&ContextState::Closing, &ContextState::Expired);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Self-transitions (all invalid)
    // -----------------------------------------------------------------------

    #[test]
    fn transition_creating_to_creating_returns_error() {
        let result = transition(&ContextState::Creating, &ContextState::Creating);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::InvalidTransition {
                from: ContextState::Creating,
                to: ContextState::Creating,
            }
        ));
    }

    #[test]
    fn transition_active_to_active_returns_error() {
        let result = transition(&ContextState::Active, &ContextState::Active);
        assert!(result.is_err());
    }

    #[test]
    fn transition_closing_to_closing_returns_error() {
        let result = transition(&ContextState::Closing, &ContextState::Closing);
        assert!(result.is_err());
    }

    #[test]
    fn transition_closed_to_closed_returns_error() {
        let result = transition(&ContextState::Closed, &ContextState::Closed);
        assert!(result.is_err());
    }

    #[test]
    fn transition_expired_to_expired_returns_error() {
        let result = transition(&ContextState::Expired, &ContextState::Expired);
        assert!(result.is_err());
    }
}
