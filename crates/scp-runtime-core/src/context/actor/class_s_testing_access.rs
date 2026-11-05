//! Test-only reach into `ClassSCell` combinators for tests outside this crate
//! (ADR-070 §4, §6.2). Compiled only under `testing`, so no production or
//! bridge build reaches these methods.
//!
//! They sit outside `class_s.rs` on purpose: this module cannot name the cell's
//! private fields, so each method can only forward to a `pub(crate)` method
//! whose body `class_s_no_persist_mutator_whitelist_is_bounded` already checks.
//! A forwarder here adds no Class-S mutation the ADR-049 §9 tripwire has not
//! seen.

use super::class_s::{AppendOutcomeError, ClassSCell, ClassSMut};
use super::deps::ActorDeps;
use super::state::PerContextState;
use scp_protocol::context::ContextError;

impl ClassSCell {
    /// Test-only reach into [`ClassSCell::into_inner`] for tests outside this
    /// crate.
    pub fn into_inner_for_test(self) -> PerContextState {
        self.into_inner()
    }

    /// Test-only reach into [`ClassSCell::commit_class_s_then_append`] for
    /// tests outside this crate.
    ///
    /// # Errors
    ///
    /// Every error [`ClassSCell::commit_class_s_then_append`] returns.
    pub async fn commit_class_s_then_append_for_test<T, A>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(ClassSMut) -> Result<(T, A), ContextError>,
        after: impl AsyncFnOnce(&A, &PerContextState, &ActorDeps) -> Result<(), ContextError>,
    ) -> Result<T, AppendOutcomeError> {
        self.commit_class_s_then_append(deps, context_id, f, after)
            .await
    }
}
