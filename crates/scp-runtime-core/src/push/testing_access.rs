//! Test access to private `PushRegistrar` state for the tests that moved to `scp-runtime`
//! (ADR-070 §6.2). Compiled only under the `testing` feature.

use super::{
    Arc, BTreeMap, KeyCustody, ProtocolRepository, PushError, PushRegistrar, PushSigningKey,
    PushTarget, PushToken, Refusal, RegistrarCommand, RelayKey, RelayOutcomes, StaleBound,
    StaleRun, Storage, Supervisor,
};

impl<C: KeyCustody, S: Storage> PushRegistrar<C, S> {
    /// Test access to the `accepted` field (ADR-070 §6.2).
    #[must_use]
    pub const fn accepted_for_test(&self) -> &BTreeMap<String, PushTarget> {
        &self.accepted
    }

    /// Test access to the `refused` field (ADR-070 §6.2).
    #[must_use]
    pub const fn refused_for_test(&self) -> &BTreeMap<RelayKey, Refusal> {
        &self.refused
    }

    /// Test access to the `signing_key` field (ADR-070 §6.2).
    #[must_use]
    pub const fn signing_key_for_test(&self) -> &PushSigningKey<C> {
        &self.signing_key
    }

    /// Test access to the `stale_runs` field (ADR-070 §6.2).
    #[must_use]
    pub const fn stale_runs_for_test(&self) -> &BTreeMap<RelayKey, StaleRun> {
        &self.stale_runs
    }

    /// Test access to the `storage` field (ADR-070 §6.2).
    #[must_use]
    pub const fn storage_for_test(&self) -> &Arc<ProtocolRepository<S>> {
        &self.storage
    }

    /// Test access to the `token` field (ADR-070 §6.2).
    #[must_use]
    pub const fn token_for_test(&self) -> &PushToken {
        &self.token
    }

    /// Test access to [`Self::handle_command`] (ADR-070 §6.2).
    pub async fn handle_command_for_test(&mut self, a0: RegistrarCommand, a1: &Supervisor) -> bool {
        self.handle_command(a0, a1).await
    }

    /// Test access to [`Self::reconcile`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::reconcile`].
    pub async fn reconcile_for_test(
        &mut self,
        a0: &Supervisor,
        a1: StaleBound,
    ) -> Result<RelayOutcomes, PushError> {
        self.reconcile(a0, a1).await
    }
}
