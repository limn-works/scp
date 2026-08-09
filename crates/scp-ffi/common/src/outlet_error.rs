//! Shared outlet-error test corpora for the FFI bridges (SCP-OUT-031).
//!
//! Gated behind the `testing` feature so the corpora are available to all three
//! bridge crates (`scp-ffi`, `scp-ffi-napi`, `scp-ffi-uniffi`) via
//! `[dev-dependencies] scp-ffi-common = { ..., features = ["testing"] }` without
//! shipping anything on a production path.
//!
//! # Why a shared corpus
//!
//! SCP-OUT-031 PR-2a made the outlet context-lifecycle rejection **state-free**
//! at every FFI seam: a caller learns *that* the context is not active, never
//! *which* lifecycle state it is in (the reserve gate runs before the
//! authorization check, so its error is reachable by an unauthorized caller).
//!
//! Asserting that property one hand-picked state at a time silently rots the
//! moment a new [`ContextState`] variant is added. [`corpus::non_active_context_states`]
//! is therefore backed by [`corpus::is_active`], an **exhaustive match**: adding a
//! variant to [`ContextState`] makes that match non-exhaustive and fails the
//! build, forcing the new variant into the corpus (and therefore into every
//! bridge's leak assertion).

/// Exhaustive lifecycle-state corpora.
pub mod corpus {
    use scp_protocol::context::ContextState;

    /// Number of [`ContextState`] variants that are not
    /// [`ContextState::Active`].
    ///
    /// Kept in lockstep with [`is_active`] by
    /// `non_active_context_states_is_exhaustive`.
    pub const NON_ACTIVE_CONTEXT_STATE_COUNT: usize = 7;

    /// Whether `state` is the one lifecycle state on which outlet operations
    /// are permitted.
    ///
    /// **This match is deliberately exhaustive and un-wildcarded.** It is the
    /// compile-time tripwire for the corpus below: a new [`ContextState`]
    /// variant breaks this function, not a runtime assertion in one bridge's
    /// test suite.
    #[must_use]
    pub const fn is_active(state: &ContextState) -> bool {
        match state {
            ContextState::Active => true,
            ContextState::Creating
            | ContextState::Closing
            | ContextState::Closed
            | ContextState::Expired
            | ContextState::MigratingOut
            | ContextState::Tombstoned
            | ContextState::Poisoned => false,
        }
    }

    /// Every non-[`Active`](ContextState::Active) lifecycle state.
    ///
    /// Use this to prove an FFI-visible outlet error never renders a lifecycle
    /// state name, for *all* states rather than one sampled state.
    #[must_use]
    pub const fn non_active_context_states() -> [ContextState; NON_ACTIVE_CONTEXT_STATE_COUNT] {
        [
            ContextState::Creating,
            ContextState::Closing,
            ContextState::Closed,
            ContextState::Expired,
            ContextState::MigratingOut,
            ContextState::Tombstoned,
            ContextState::Poisoned,
        ]
    }

    /// The lowercase `snake_case` wire spelling each FFI bridge's cached
    /// `state` getter returns for `state` (`NapiContextHandle::state`,
    /// `UniFFI` `ContextHandle::state`, `PyO3` `ContextHandle.state`).
    ///
    /// A bridge-local guard that interpolated that cached string leaked the
    /// state in THIS spelling, not the `Debug` variant name — so the leak
    /// assertion must cover both. Exhaustive and un-wildcarded for the same
    /// tripwire reason as [`is_active`].
    #[must_use]
    pub const fn wire_name(state: &ContextState) -> &'static str {
        match state {
            ContextState::Creating => "creating",
            ContextState::Active => "active",
            ContextState::Closing => "closing",
            ContextState::Closed => "closed",
            ContextState::Expired => "expired",
            ContextState::MigratingOut => "migrating_out",
            ContextState::Tombstoned => "tombstoned",
            ContextState::Poisoned => "poisoned",
        }
    }

    /// Every token a caller-visible outlet error must never contain, for every
    /// non-`Active` lifecycle state.
    ///
    /// Two tokens per state, covering the two interpolation shapes that
    /// actually occurred in the bridges:
    ///
    /// - the `Debug`/`Display` variant name (`Closing`) — covers `{state:?}`
    ///   on a `ContextState` and `{opt:?}` on an `Option<ContextState>`
    ///   (`Some(Closing)`);
    /// - the `Debug` render of the bridge's cached wire string (`"closing"`,
    ///   **quoted**) — covers `{state_str:?}` on the `String` a bridge's
    ///   `state` getter returns.
    ///
    /// The wire spelling is matched WITH its surrounding quotes deliberately:
    /// the bare word would false-positive on ordinary prose, including the
    /// state-free surface this corpus exists to bless
    /// (`protocol.context-closed-mid-stream` contains `closed`).
    #[must_use]
    pub fn leaked_state_tokens() -> Vec<String> {
        non_active_context_states()
            .iter()
            .flat_map(|s| [format!("{s:?}"), format!("{:?}", wire_name(s))])
            .collect()
    }

    /// Asserts `haystack` leaks no lifecycle state name.
    ///
    /// # Panics
    ///
    /// Panics naming the offending token and `context` if any non-`Active`
    /// state spelling appears in `haystack`.
    pub fn assert_no_lifecycle_state_leak(haystack: &str, context: &str) {
        for token in leaked_state_tokens() {
            assert!(
                !haystack.contains(token.as_str()),
                "{context}: caller-visible output leaked the lifecycle state \
                 `{token}` — SCP-OUT-031 PR-2a requires a state-free surface. \
                 Output was: {haystack}"
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            ContextState, NON_ACTIVE_CONTEXT_STATE_COUNT, assert_no_lifecycle_state_leak,
            is_active, leaked_state_tokens, non_active_context_states, wire_name,
        };

        /// The corpus must contain every non-`Active` state exactly once, and
        /// nothing else. `is_active`'s exhaustive match is what makes a newly
        /// added variant a COMPILE error; this test is what makes a variant
        /// added to the enum but forgotten in the array a TEST failure.
        #[test]
        fn non_active_context_states_is_exhaustive() {
            let states = non_active_context_states();
            assert_eq!(states.len(), NON_ACTIVE_CONTEXT_STATE_COUNT);
            for state in &states {
                assert!(!is_active(state), "{state:?} must not be Active");
                assert_ne!(wire_name(state), wire_name(&ContextState::Active));
            }
            let mut tokens = leaked_state_tokens();
            assert_eq!(tokens.len(), NON_ACTIVE_CONTEXT_STATE_COUNT * 2);
            tokens.sort_unstable();
            let before = tokens.len();
            tokens.dedup();
            assert_eq!(before, tokens.len(), "corpus must not repeat a token");
            assert!(is_active(&ContextState::Active));
        }

        /// The state-free surface itself must pass. This is the regression
        /// guard against over-broad matching: `protocol.context-closed-mid-stream`
        /// contains the bare word `closed`, so a naive lowercase substring
        /// check would reject the very output PR-2a mandates.
        #[test]
        fn assert_no_lifecycle_state_leak_accepts_state_free_text() {
            assert_no_lifecycle_state_leak(
                "[SCP-OUTLET-6101] protocol: protocol.context-closed-mid-stream",
                "state-free surface",
            );
            assert_no_lifecycle_state_leak(
                "outlet economy settle failed: actor reply channel closed",
                "unrelated prose mentioning closed",
            );
        }

        /// `{state:?}` on a `ContextState` — the `UniFFI` guard's shape.
        #[test]
        #[should_panic(expected = "leaked the lifecycle state")]
        fn assert_no_lifecycle_state_leak_rejects_debug_variant_name() {
            assert_no_lifecycle_state_leak(
                "cannot invoke outlet in context in Closing state",
                "leaky surface",
            );
        }

        /// `{opt:?}` on an `Option<ContextState>` — the streaming-saga guards'
        /// shape (`Some(Closed)`).
        #[test]
        #[should_panic(expected = "leaked the lifecycle state")]
        fn assert_no_lifecycle_state_leak_rejects_optional_debug_variant_name() {
            assert_no_lifecycle_state_leak(
                "caller context in Some(MigratingOut) state",
                "leaky surface",
            );
        }

        /// `{state_str:?}` on the bridge's cached wire `String` — the `NAPI`
        /// guard's shape. This is the spelling a `Debug`-variant-name-only
        /// check would have missed.
        #[test]
        #[should_panic(expected = "leaked the lifecycle state")]
        fn assert_no_lifecycle_state_leak_rejects_quoted_wire_spelling() {
            assert_no_lifecycle_state_leak(
                "cannot invoke outlet in context in \"closed\" state — context must be active",
                "leaky surface",
            );
        }
    }
}
