//! Handler return type.
//!
//! Per ADR-049 §1 (`ContextActor` handler signature): handlers take
//! `&mut PerContextState` and `&ActorDeps`, return [`Outcome<T>`]. The
//! `mutated: bool` flag tells the actor whether the handler actually
//! changed state, which the actor uses to decide whether to mark itself
//! `dirty` for coalesced persistence.
//!
//! Without this distinction every successful query would trigger a
//! useless persist — a defect flagged in plan-review for the
//! "`dirty` set unconditionally" failure mode.
//!
//! # Conventions
//!
//! - Pure-read handlers (everything in [`QueriesCommand`]) return
//!   [`Outcome::ok`] / [`Outcome::err`] (`mutated: false`).
//! - Mutating handlers return [`Outcome::ok_mutated`] /
//!   [`Outcome::err_mutated`] (`mutated: true`).
//! - A handler that mutated state but then failed MUST report
//!   `mutated: true` so the actor persists the partial state. This is
//!   rare; most handlers roll back internally on error and report
//!   `mutated: false`. When in doubt: report what actually changed.
//!
//! [`QueriesCommand`]: https://example.invalid

use super::ContextError;

/// Handler return type. Pairs the operation's [`Result`] with a `mutated`
/// flag the actor uses to decide whether to mark itself dirty for
/// coalesced persistence.
///
/// `Outcome` is intentionally not generic over the error type — handlers
/// produce [`ContextError`] uniformly. If a handler needs to surface a
/// foreign error it converts at the boundary.
pub struct Outcome<T> {
    /// The operation's result.
    pub result: Result<T, ContextError>,
    /// `true` iff the handler mutated `PerContextState`.
    pub mutated: bool,
}

impl<T> Outcome<T> {
    /// Successful pure-read result. Sets `mutated: false`.
    #[must_use]
    pub const fn ok(value: T) -> Self {
        Self {
            result: Ok(value),
            mutated: false,
        }
    }

    /// Successful mutating result. Sets `mutated: true` so the actor
    /// marks itself dirty for coalesced persistence.
    #[must_use]
    pub const fn ok_mutated(value: T) -> Self {
        Self {
            result: Ok(value),
            mutated: true,
        }
    }

    /// Failed result without mutation. The handler either failed before
    /// touching state or rolled back internally on error. The actor will
    /// not mark itself dirty.
    #[must_use]
    pub const fn err(err: ContextError) -> Self {
        Self {
            result: Err(err),
            mutated: false,
        }
    }

    /// Failed result with partial mutation. The handler mutated state
    /// before failing AND did NOT roll back; the actor MUST persist the
    /// partial state to keep the snapshot in sync with the (broken)
    /// in-memory view.
    ///
    /// Rare — most handlers roll back internally. The `_mutated` suffix
    /// matches [`Self::ok_mutated`] for symmetry.
    #[must_use]
    pub const fn err_mutated(err: ContextError) -> Self {
        Self {
            result: Err(err),
            mutated: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_error() -> ContextError {
        ContextError::ContextNotActive
    }

    #[test]
    fn ok_constructor_marks_unmutated() {
        let outcome: Outcome<u32> = Outcome::ok(42);
        assert!(outcome.result.is_ok());
        assert_eq!(outcome.result.ok(), Some(42));
        assert!(!outcome.mutated, "ok() must report mutated=false");
    }

    #[test]
    fn ok_mutated_constructor_marks_mutated() {
        let outcome: Outcome<&'static str> = Outcome::ok_mutated("done");
        assert_eq!(outcome.result.ok(), Some("done"));
        assert!(
            outcome.mutated,
            "ok_mutated() must report mutated=true so the actor persists",
        );
    }

    #[test]
    fn err_constructor_marks_unmutated() {
        let outcome: Outcome<()> = Outcome::err(sample_error());
        assert!(outcome.result.is_err());
        assert!(matches!(
            outcome.result.unwrap_err(),
            ContextError::ContextNotActive,
        ));
        // mutated=false: handler rolled back or never touched state.
    }

    #[test]
    fn err_mutated_constructor_marks_mutated() {
        let outcome: Outcome<()> = Outcome::err_mutated(sample_error());
        assert!(outcome.result.is_err());
        assert!(
            outcome.mutated,
            "err_mutated() must report mutated=true so the actor persists \
             the partial state",
        );
    }

    #[test]
    fn outcome_carries_unit_type() {
        let outcome = Outcome::<()>::ok(());
        assert!(outcome.result.is_ok());
        assert!(!outcome.mutated);
    }

    #[test]
    fn outcome_const_constructors_compile() {
        // Compile-time witness that all four constructors are `const`.
        const OK: Outcome<u8> = Outcome::ok(1);
        const OK_MUT: Outcome<u8> = Outcome::ok_mutated(2);
        const ERR: Outcome<u8> = Outcome::err(ContextError::ContextNotActive);
        const ERR_MUT: Outcome<u8> = Outcome::err_mutated(ContextError::ContextNotActive);
        assert!(matches!(OK.result, Ok(1)));
        assert!(matches!(OK_MUT.result, Ok(2)));
        assert!(matches!(ERR.result, Err(ContextError::ContextNotActive)));
        assert!(matches!(
            ERR_MUT.result,
            Err(ContextError::ContextNotActive)
        ));
    }
}
