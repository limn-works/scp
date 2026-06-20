//! `ClassSCell` — the fail-closed-persist combinator wrapper around
//! [`PerContextState`] (ADR-049 §9 Class S).
//!
//! # Why this exists
//!
//! ADR-049 §9 defines a **Class-S persistence invariant**: a Class-S field of
//! [`PerContextState`] (spending-nonce consume, executed-proposals,
//! downward-authorization transitions, saga reservation slots) must be persisted
//! **fail-closed** after any mutation — a mutation is NEVER acknowledged to a
//! caller unless it is durable, because a coalesced (best-effort) acknowledgment
//! would let an actor crash roll the mutation back and re-open a replay /
//! re-spend / re-grant window the caller already observed as closed.
//!
//! Today that invariant is enforced by a source-text scanner
//! (`scripts/check-class-s-fail-closed.sh`) which pattern-matches handler bodies
//! for "mutate then persist_fail_closed." A source-text scanner is structurally
//! non-convergent: every new way to alias a `&mut PerContextState`
//! (extern-fn, `&mut`-alias, ref-mut-destructure, autoref-method) is a fresh
//! evasion, and the gate must grow a new pattern to catch each one. The goal of
//! the refactor this file begins is to make the invariant a **compile error** to
//! violate, retiring the scanner.
//!
//! # The mechanism
//!
//! [`ClassSCell`] owns the [`PerContextState`] and exposes:
//!
//! - **Reads** via [`Deref`] — `&*cell` / `cell.<field>` yields `&PerContextState`.
//!   There is deliberately **no [`DerefMut`]**: you cannot obtain a
//!   `&mut PerContextState` by writing `&mut cell.<field>` or `*cell = …`. That is
//!   the compile-time hook — a future migration step privatizes the fields so the
//!   ONLY way to mutate Class-S state is through the combinators below, each of
//!   which performs the fail-closed persist by construction.
//! - **Mutation through a combinator** — [`ClassSCell::commit_class_s`] (with
//!   rollback), [`ClassSCell::commit_class_s_no_rollback`], and
//!   [`ClassSCell::commit_best_effort`]. The first two perform the fail-closed
//!   persist; the third performs the best-effort persist (Class C).
//!
//! # PR1 scope — pure scaffolding, no behaviour change
//!
//! This is step 1. The combinators exist and are unit-tested, but **no handler is
//! migrated to them yet** and the [`PerContextState`] fields stay public. To keep
//! every existing handler compiling unchanged, [`ClassSCell`] carries a
//! **temporary** escape hatch, [`ClassSCell::state_mut`], that hands out the bare
//! `&mut PerContextState` exactly as the actor owned it before. The source-text
//! gate is UNCHANGED and still passes — because the handler bodies it scans are
//! byte-for-byte identical (they receive `&mut PerContextState` via `state_mut`).
//! The escape hatch is removed in the final migration step once every handler
//! routes its mutations through the combinators.

use std::ops::Deref;

use super::deps::ActorDeps;
use super::state::PerContextState;
use crate::context::messaging_helpers::{persist_state_best_effort, persist_state_fail_closed};
use scp_protocol::context::ContextError;

/// Owns one [`PerContextState`] and gates every mutation behind a
/// persistence combinator (ADR-049 §9 Class S).
///
/// Reads go through [`Deref`]; there is intentionally no [`DerefMut`] (see the
/// module docs). Mutations go through [`Self::commit_class_s`] /
/// [`Self::commit_class_s_no_rollback`] (fail-closed persist) or
/// [`Self::commit_best_effort`] (best-effort persist).
pub(crate) struct ClassSCell {
    /// The wrapped state. Private — the only mutable access is through the
    /// combinators (or the PR1-temporary [`Self::state_mut`] escape hatch).
    state: PerContextState,
}

impl Deref for ClassSCell {
    type Target = PerContextState;

    /// Immutable access to the wrapped state. This is the *only* `Deref`
    /// direction: there is no `DerefMut`, so `&mut cell.<field>` does not
    /// compile (that is the compile-time enforcement hook).
    fn deref(&self) -> &PerContextState {
        &self.state
    }
}

impl ClassSCell {
    /// Wrap an owned [`PerContextState`].
    pub(crate) const fn new(state: PerContextState) -> Self {
        Self { state }
    }

    /// Unwrap, returning the owned [`PerContextState`]. Used at ownership
    /// hand-off boundaries (e.g. draining state out of the actor on shutdown /
    /// replace).
    ///
    /// `dead_code` allow: PR1 is pure scaffolding — the first production caller
    /// is the migration step that routes a state hand-off through the cell. The
    /// method is exercised by this module's unit tests today.
    #[allow(dead_code)]
    pub(crate) fn into_inner(self) -> PerContextState {
        self.state
    }

    /// **TEMPORARY — PR1 ONLY. Removed in the final migration step.**
    ///
    /// Hands out the bare `&mut PerContextState` so existing handlers keep
    /// working byte-for-byte unchanged while the combinators are introduced.
    /// Once every handler routes its mutations through [`Self::commit_class_s`]
    /// / [`Self::commit_best_effort`] and the [`PerContextState`] Class-S fields
    /// are privatized, this method is deleted — at which point the only path to
    /// a `&mut PerContextState` is through the persist-on-commit combinators,
    /// making the Class-S fail-closed invariant a compile error to violate.
    pub(in crate::context) const fn state_mut(&mut self) -> &mut PerContextState {
        &mut self.state
    }

    /// Mutate Class-S state and persist **fail-closed**, with rollback (ADR-049
    /// §9). This is the actor-owned equivalent of the established
    /// "mutate → [`persist_state_fail_closed`] → on-err undo" idiom (see
    /// `handlers/saga.rs::prepare_b`).
    ///
    /// `f` mutates the state and returns `Ok((value, rollback))`, where
    /// `rollback` is a closure that undoes exactly the staged mutation. The
    /// sequence is:
    ///
    /// 1. Run `f(&mut state)`.
    ///    - If `f` returns `Err(e)`, return `Err(e)` immediately. No persist runs
    ///      (a rejected operation that made no durable-relevant mutation must not
    ///      trigger a Class-S write).
    /// 2. On `Ok((value, rollback))`, call [`persist_state_fail_closed`].
    ///    - On persist **success**, return `Ok(value)`.
    ///    - On persist **failure**, run `rollback(&mut state)` to undo the staged
    ///      mutation, then return the persist error — so a caller NEVER observes
    ///      success for a mutation that did not durably land.
    ///
    /// The caller decides what `rollback` undoes; the combinator only guarantees
    /// it runs exactly when (and only when) the fail-closed persist fails.
    ///
    /// # Errors
    ///
    /// Returns the error from `f`, or [`ContextError::PersistenceFailed`] from
    /// [`persist_state_fail_closed`] (after running `rollback`).
    ///
    /// `dead_code` allow: PR1 is pure scaffolding — no handler is migrated to
    /// the combinator yet. Exercised by this module's unit tests; the first
    /// production caller lands with the handler migration step.
    #[allow(dead_code)]
    pub(crate) fn commit_class_s<T, R>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(&mut PerContextState) -> Result<(T, R), ContextError>,
    ) -> Result<T, ContextError>
    where
        R: FnOnce(&mut PerContextState),
    {
        let (value, rollback) = f(&mut self.state)?;
        match persist_state_fail_closed(&self.state, deps, context_id) {
            Ok(()) => Ok(value),
            Err(persist_err) => {
                rollback(&mut self.state);
                Err(persist_err)
            }
        }
    }

    /// Mutate Class-S state and persist **fail-closed**, with no rollback —
    /// for fail-closed-direction mutations whose in-memory effect must STAY
    /// even when the persist fails (e.g. recording an accepted replay nonce:
    /// un-recording it would re-open the replay window the dedup cache exists to
    /// close, so the durable-divergence is reported but the mutation is kept).
    ///
    /// Equivalent to [`Self::commit_class_s`] with an empty rollback closure.
    /// `f` mutates the state and returns `Ok(value)`; on persist success returns
    /// `Ok(value)`, on persist failure returns the persist error WITHOUT undoing
    /// the mutation. If `f` returns `Err`, that error propagates and no persist
    /// runs.
    ///
    /// # Errors
    ///
    /// Returns the error from `f`, or [`ContextError::PersistenceFailed`] from
    /// [`persist_state_fail_closed`].
    ///
    /// `dead_code` allow: PR1 scaffolding — see [`Self::commit_class_s`].
    #[allow(dead_code)]
    pub(crate) fn commit_class_s_no_rollback<T>(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(&mut PerContextState) -> Result<T, ContextError>,
    ) -> Result<T, ContextError> {
        self.commit_class_s(deps, context_id, |state| {
            // Empty rollback: the persist failure keeps the in-memory mutation
            // (fail-closed direction). The `|_state|` no-op closure is the `R`
            // type parameter; it never runs unless persist fails, and even then
            // it intentionally does nothing.
            f(state).map(|value| (value, |_state: &mut PerContextState| {}))
        })
    }

    /// Mutate Class-C state and persist **best-effort** (ADR-049 §9). Runs `f`,
    /// then [`persist_state_best_effort`] — a persist failure is logged + metered
    /// but not surfaced (the ≤50 ms coalesce-window rollback is acceptable for
    /// liveness / structural state). This is the actor-owned equivalent of the
    /// "mutate → [`persist_state_best_effort`]" idiom.
    ///
    /// `dead_code` allow: PR1 scaffolding — see [`Self::commit_class_s`].
    #[allow(dead_code)]
    pub(crate) fn commit_best_effort(
        &mut self,
        deps: &ActorDeps,
        context_id: &str,
        f: impl FnOnce(&mut PerContextState),
    ) {
        f(&mut self.state);
        persist_state_best_effort(&self.state, deps, context_id);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::persistence::ContextPersistence;
    use scp_identity::DID;
    use scp_platform::testing::InMemoryStorage;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Minimal event log provider — accepts every call (the combinator paths do
    /// not touch the event log).
    struct TestEventLog;
    impl crate::context::builder::ContextEventLogProvider for TestEventLog {
        fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _id: &[u8; 32],
            _event: &str,
            _actor: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(
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
    /// Persistence SPY: accepts every write but counts `persist_context` calls,
    /// so a test can assert a combinator actually performed its persist.
    struct SpyPersistence {
        persist_calls: Arc<AtomicUsize>,
    }

    macro_rules! impl_persistence {
        ($ty:ty, $persist_result:expr) => {
            impl ContextPersistence for $ty {
                fn persist_context(
                    &self,
                    _: &str,
                    _: &crate::context::state::ContextSnapshot,
                ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    $persist_result
                }
                fn load_context(
                    &self,
                    _: &str,
                ) -> Result<
                    Option<crate::context::state::ContextSnapshot>,
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
                fn delete_context(
                    &self,
                    _: &str,
                ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    Ok(())
                }
                fn list_persisted_contexts(
                    &self,
                ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
                    Ok(Vec::new())
                }
            }
        };
    }

    impl_persistence!(OkPersistence, Ok(()));
    impl_persistence!(FailPersistence, Err("induced persist failure".into()));

    impl ContextPersistence for SpyPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.persist_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
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

    /// Assemble an `ActorDeps` with the supplied persistence backend.
    async fn build_deps(persistence: Box<dyn ContextPersistence>) -> ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestClassSCell".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
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
        );
        supervisor
            .build_actor_deps(&DID("did:example:class-s-cell-test".to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// A fresh encrypted test state. `members` is the field the tests mutate /
    /// roll back — a plain observable `HashSet<DID>`.
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

    /// (a) `commit_class_s` runs the mutation, persists fail-closed, and returns
    /// `Ok(value)` on persist success — and the mutation is retained.
    #[tokio::test]
    async fn commit_class_s_persists_and_returns_ok_on_success() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x11));
        let ctx = ctx_hex(0x11);
        let member = DID("did:example:new-member".to_owned());

        let returned = cell
            .commit_class_s(&deps, &ctx, |state| {
                state.members.insert(member.clone());
                let member_for_rollback = member.clone();
                Ok(("committed", move |state: &mut PerContextState| {
                    state.members.remove(&member_for_rollback);
                }))
            })
            .expect("persist succeeds ⇒ Ok");

        assert_eq!(returned, "committed");
        assert!(
            cell.members.contains(&member),
            "on persist success the mutation is retained"
        );
    }

    /// (b) On a persistence that returns `Err`, the rollback closure runs and the
    /// persist error propagates — the staged mutation is undone.
    #[tokio::test]
    async fn commit_class_s_runs_rollback_and_propagates_error_on_persist_failure() {
        let deps = build_deps(Box::new(FailPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x22));
        let ctx = ctx_hex(0x22);
        let member = DID("did:example:doomed-member".to_owned());

        let result = cell.commit_class_s(&deps, &ctx, |state| {
            state.members.insert(member.clone());
            let member_for_rollback = member.clone();
            Ok(((), move |state: &mut PerContextState| {
                state.members.remove(&member_for_rollback);
            }))
        });

        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "a fail-closed persist failure propagates PersistenceFailed; got {result:?}"
        );
        assert!(
            !cell.members.contains(&member),
            "the rollback closure undid the staged mutation"
        );
    }

    /// `commit_class_s` returns `f`'s error without persisting when `f` rejects.
    #[tokio::test]
    async fn commit_class_s_returns_f_error_without_persisting() {
        // The rejecting closure below only ever returns `Err`, so the rollback
        // type `R` is unconstrained by its body — this alias pins it to a
        // concrete `fn(&mut PerContextState)` rollback shape. Declared first so
        // it precedes all statements (clippy::items_after_statements).
        type RejectingCommit = Result<((), fn(&mut PerContextState)), ContextError>;

        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x23));
        let ctx = ctx_hex(0x23);

        let result: Result<(), ContextError> = cell.commit_class_s(&deps, &ctx, |_state| {
            RejectingCommit::Err(ContextError::PermissionDenied("rejected".to_owned()))
        });

        assert!(
            matches!(result, Err(ContextError::PermissionDenied(_))),
            "f's error propagates unchanged; got {result:?}"
        );
        assert_eq!(
            persist_calls.load(Ordering::SeqCst),
            0,
            "no Class-S persist runs when f rejects"
        );
    }

    /// `commit_class_s_no_rollback` keeps the mutation even when persist fails
    /// (fail-closed direction) and returns the persist error.
    #[tokio::test]
    async fn commit_class_s_no_rollback_keeps_mutation_on_persist_failure() {
        let deps = build_deps(Box::new(FailPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x24));
        let ctx = ctx_hex(0x24);
        let member = DID("did:example:kept-member".to_owned());

        let result = cell.commit_class_s_no_rollback(&deps, &ctx, |state| {
            state.members.insert(member.clone());
            Ok(())
        });

        assert!(
            matches!(result, Err(ContextError::PersistenceFailed(_))),
            "persist failure surfaces; got {result:?}"
        );
        assert!(
            cell.members.contains(&member),
            "no-rollback variant retains the mutation even on persist failure"
        );
    }

    /// `commit_class_s_no_rollback` returns `Ok` and retains the mutation on
    /// persist success.
    #[tokio::test]
    async fn commit_class_s_no_rollback_ok_on_success() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x25));
        let ctx = ctx_hex(0x25);
        let member = DID("did:example:ok-member".to_owned());

        let value = cell
            .commit_class_s_no_rollback(&deps, &ctx, |state| {
                state.members.insert(member.clone());
                Ok(7u32)
            })
            .expect("persist succeeds ⇒ Ok");

        assert_eq!(value, 7);
        assert!(cell.members.contains(&member));
    }

    /// (c) `commit_best_effort` runs the mutation and calls the best-effort
    /// persist path (asserted via the persist-call spy).
    #[tokio::test]
    async fn commit_best_effort_runs_mutation_and_persists() {
        let persist_calls = Arc::new(AtomicUsize::new(0));
        let deps = build_deps(Box::new(SpyPersistence {
            persist_calls: Arc::clone(&persist_calls),
        }))
        .await;
        let mut cell = ClassSCell::new(fresh_state(0x26));
        let ctx = ctx_hex(0x26);
        let member = DID("did:example:best-effort-member".to_owned());

        cell.commit_best_effort(&deps, &ctx, |state| {
            state.members.insert(member.clone());
        });

        assert!(
            cell.members.contains(&member),
            "best-effort mutation is applied"
        );
        assert_eq!(
            persist_calls.load(Ordering::SeqCst),
            1,
            "commit_best_effort issues exactly one persist"
        );
    }

    /// `into_inner` returns the wrapped state with mutations intact, and `Deref`
    /// reads see the same state.
    #[tokio::test]
    async fn into_inner_returns_wrapped_state() {
        let deps = build_deps(Box::new(OkPersistence)).await;
        let mut cell = ClassSCell::new(fresh_state(0x27));
        let ctx = ctx_hex(0x27);
        let member = DID("did:example:unwrap-member".to_owned());

        cell.commit_best_effort(&deps, &ctx, |state| {
            state.members.insert(member.clone());
        });
        // Read through Deref before unwrap.
        assert!(cell.members.contains(&member));

        let state = cell.into_inner();
        assert!(
            state.members.contains(&member),
            "into_inner preserves the committed mutation"
        );
    }
}
