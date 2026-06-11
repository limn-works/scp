//! Context lifecycle state transition logic.
//!
//! Implements the seven-state finite state machine for SCP contexts:
//! `Creating -> Active -> Closing -> Closed`, with `Expired` as a terminal
//! state reachable from `Active` when TTL elapses, and
//! `Active -> MigratingOut -> Tombstoned` for context migration (§5.11A).
//! See ADR-008 in `.docs/adrs/phase-2.md`.
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
/// | `Active` | `MigratingOut` | Migration approved (§5.11A) |
/// | `Active` | `Poisoned` | Actor exceeded respawn budget (ADR-049 §10) |
/// | `Closing` | `Closed` | All members processed final events |
/// | `MigratingOut` | `Tombstoned` | Grace period expired (§5.11A.5) |
/// | `MigratingOut` | `Active` | Migration cancelled (§5.11A) |
/// | `Poisoned` | `Active` | Operator cleared poison; fresh respawn (ADR-049 §10) |
///
/// # Invalid transitions
///
/// - `Closed -> *` (terminal state)
/// - `Expired -> *` (terminal state)
/// - `Tombstoned -> *` (terminal state)
/// - `Poisoned -> *` except `Active` (only operator-driven recovery re-activates)
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
        // Valid transitions per ADR-008 + §5.11A migration.
        // `Creating -> Active` (MLS group formed) and `Poisoned -> Active`
        // (operator-driven respawn after the budget was cleared, ADR-049
        // §10) share the same target.
        (ContextState::Creating | ContextState::Poisoned, ContextState::Active)
        | (
            ContextState::Active,
            ContextState::Closing
            | ContextState::Expired
            | ContextState::MigratingOut
            | ContextState::Poisoned,
        )
        | (ContextState::Closing, ContextState::Closed)
        | (ContextState::MigratingOut, ContextState::Tombstoned | ContextState::Active) => {
            Ok(target.clone())
        }

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

    // -----------------------------------------------------------------------
    // Migration transitions (§5.11A)
    // -----------------------------------------------------------------------

    #[test]
    fn transition_active_to_migrating_out_succeeds() {
        let result = transition(&ContextState::Active, &ContextState::MigratingOut);
        assert_eq!(result.ok(), Some(ContextState::MigratingOut));
    }

    #[test]
    fn transition_migrating_out_to_tombstoned_succeeds() {
        let result = transition(&ContextState::MigratingOut, &ContextState::Tombstoned);
        assert_eq!(result.ok(), Some(ContextState::Tombstoned));
    }

    #[test]
    fn transition_migrating_out_to_active_succeeds() {
        // Migration cancellation returns context to Active.
        let result = transition(&ContextState::MigratingOut, &ContextState::Active);
        assert_eq!(result.ok(), Some(ContextState::Active));
    }

    #[test]
    fn transition_tombstoned_to_active_returns_error() {
        let result = transition(&ContextState::Tombstoned, &ContextState::Active);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::InvalidTransition {
                from: ContextState::Tombstoned,
                to: ContextState::Active,
            }
        ));
    }

    #[test]
    fn transition_tombstoned_to_creating_returns_error() {
        let result = transition(&ContextState::Tombstoned, &ContextState::Creating);
        assert!(result.is_err());
    }

    #[test]
    fn transition_tombstoned_to_closing_returns_error() {
        let result = transition(&ContextState::Tombstoned, &ContextState::Closing);
        assert!(result.is_err());
    }

    #[test]
    fn transition_tombstoned_to_tombstoned_returns_error() {
        let result = transition(&ContextState::Tombstoned, &ContextState::Tombstoned);
        assert!(result.is_err());
    }

    #[test]
    fn transition_migrating_out_to_closing_returns_error() {
        let result = transition(&ContextState::MigratingOut, &ContextState::Closing);
        assert!(result.is_err());
    }

    #[test]
    fn transition_migrating_out_to_migrating_out_returns_error() {
        let result = transition(&ContextState::MigratingOut, &ContextState::MigratingOut);
        assert!(result.is_err());
    }

    #[test]
    fn transition_creating_to_migrating_out_returns_error() {
        let result = transition(&ContextState::Creating, &ContextState::MigratingOut);
        assert!(result.is_err());
    }

    #[test]
    fn transition_closing_to_migrating_out_returns_error() {
        let result = transition(&ContextState::Closing, &ContextState::MigratingOut);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Poisoned (ADR-049 §10 — actor respawn budget)
    // -----------------------------------------------------------------------

    #[test]
    fn transition_active_to_poisoned_succeeds() {
        // The actor exceeded its respawn budget; the supervisor poisons the
        // live context rather than respawning it again.
        let result = transition(&ContextState::Active, &ContextState::Poisoned);
        assert_eq!(result.ok(), Some(ContextState::Poisoned));
    }

    #[test]
    fn transition_poisoned_to_active_succeeds() {
        // Operator-driven recovery: clearing the poison and respawning the
        // actor from its snapshot returns the context to Active.
        let result = transition(&ContextState::Poisoned, &ContextState::Active);
        assert_eq!(result.ok(), Some(ContextState::Active));
    }

    #[test]
    fn transition_poisoned_to_self_returns_error() {
        let result = transition(&ContextState::Poisoned, &ContextState::Poisoned);
        assert!(result.is_err());
    }

    #[test]
    fn transition_poisoned_to_closed_returns_error() {
        // Poisoned recovers only via Active — never directly to a terminal
        // state. A poisoned context that should be closed must first be
        // respawned (Active), then closed through the normal path.
        let result = transition(&ContextState::Poisoned, &ContextState::Closed);
        assert!(result.is_err());
    }

    #[test]
    fn transition_creating_to_poisoned_returns_error() {
        // Only a live (Active) context can be poisoned — a context still
        // Creating has no spawned actor to crash past budget.
        let result = transition(&ContextState::Creating, &ContextState::Poisoned);
        assert!(result.is_err());
    }
}
