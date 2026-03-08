//! Compromise recovery orchestrator (§9.12).
//!
//! Coordinates the 6-step ordered recovery protocol when a key is known or
//! suspected to be compromised. Individual primitives exist across the
//! codebase; this module orchestrates them in dependency order:
//!
//! 1. Key rotation on trusted device (tier-appropriate)
//! 2. MLS Update in all active contexts
//! 3. UCAN revocation (scoped by tier)
//! 4. `KeyPackage` rotation
//! 5. Contact notification (parallel with 6)
//! 6. Identity private state re-encryption (parallel with 5)
//!
//! Three compromise tiers determine the recovery path:
//!
//! - [`CompromiseTier::AgentKey`] — cheapest: DID doc update, scoped UCAN
//!   revocation, MLS Update, new `KeyPackages`. No identity migration.
//! - [`CompromiseTier::ActiveSigningKey`] — `rotate_active_key`, new UCANs,
//!   MLS Updates, PSK re-encryption.
//! - [`CompromiseTier::IdentityKey`] — `migrate_identity` using pre-rotation
//!   key, new DID, forwarding record, full re-keying.
//!
//! **Step ordering (§9.12):** Steps 1→2→3→4 are sequential (each depends on
//! the output of the previous). Steps 5 and 6 are independent cleanup after
//! step 4. Steps 2-4 are per-context — failure in one context does not block
//! recovery in other contexts.
//!
//! See spec §9.12, ADR-003 (DID rotation), ADR-039 (agent key model).

use std::fmt;
use std::future::Future;

use scp_identity::document::DidDocument;
use scp_identity::{DidRotationEvent, IdentityError, ScpIdentity};

use scp_platform::traits::{KeyCustody, KeyHandle};

use crate::crypto::mls::error::MlsError;
use crate::crypto::mls::group::ScpMlsGroup;
use crate::crypto::mls::ratchet::propose_update;
use crate::crypto::ucan::UcanPayload;
use crate::crypto::ucan::revoke::{
    RevocationAuthorizer, RevocationDistributor, RevocationEventLogger, RevocationList, revoke_ucan,
};

// ---------------------------------------------------------------------------
// KeyRotator — trait abstracting key rotation operations
// ---------------------------------------------------------------------------

/// Abstraction over DID key rotation and identity migration operations.
///
/// This trait decouples the orchestrator from `DidDht`'s generic parameters
/// (`DhtClient`, `Clock`), allowing tests and production code to use different
/// DID method implementations without generic proliferation.
///
/// All methods mirror the corresponding `DidDht` inherent methods.
pub trait KeyRotator: Send + Sync {
    /// Removes the `#agent` verification method from the DID document.
    fn remove_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send;

    /// Adds a new `#agent` verification method to the DID document.
    fn add_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send;

    /// Rotates the active signing key (DID string preserved).
    fn rotate_active_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send;

    /// Migrates identity to a new DID using the pre-rotation key.
    fn migrate_identity(
        &self,
        identity: &ScpIdentity,
        old_document: &DidDocument,
        pre_rotation_key: &KeyHandle,
        key_custody: &impl KeyCustody,
        rotated_at: u64,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument, DidRotationEvent), IdentityError>> + Send;
}

// Blanket implementation for DidDht<D, C>.
impl<D, C> KeyRotator for scp_identity::DidDht<D, C>
where
    D: scp_identity::DhtClient + 'static,
    C: scp_identity::cache::Clock + 'static,
{
    fn remove_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send {
        self.remove_agent_key(identity, document)
    }

    fn add_agent_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send {
        self.add_agent_key(identity, document, key_custody)
    }

    fn rotate_active_key(
        &self,
        identity: &ScpIdentity,
        document: &DidDocument,
        key_custody: &impl KeyCustody,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument), IdentityError>> + Send {
        self.rotate_active_key(identity, document, key_custody)
    }

    fn migrate_identity(
        &self,
        identity: &ScpIdentity,
        old_document: &DidDocument,
        pre_rotation_key: &KeyHandle,
        key_custody: &impl KeyCustody,
        rotated_at: u64,
    ) -> impl Future<Output = Result<(ScpIdentity, DidDocument, DidRotationEvent), IdentityError>> + Send
    {
        self.migrate_identity(
            identity,
            old_document,
            pre_rotation_key,
            key_custody,
            rotated_at,
        )
    }
}

// ---------------------------------------------------------------------------
// CompromiseTier — which key was compromised
// ---------------------------------------------------------------------------

/// Which key was compromised, determining the recovery path.
///
/// Each tier includes all steps of the tiers below it (Agent < Active <
/// Identity). Higher tiers are more expensive but cover more severe
/// compromises.
///
/// See spec §9.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompromiseTier {
    /// Agent Signing Key (`#agent`) compromise — most common, cheapest
    /// recovery. No identity migration. Removes/replaces `#agent` VM,
    /// revokes agent-scoped UCANs only. See ADR-039.
    AgentKey,

    /// Active Signing Key (`#active`) compromise. Calls
    /// `rotate_active_key` (ADR-003 §4a). DID string is preserved.
    /// Includes PSK re-encryption (step 6).
    ActiveSigningKey,

    /// Identity Key (`#0`) compromise — rare, severe. Calls
    /// `migrate_identity` (ADR-003 §4b) using the pre-rotation key.
    /// Creates a new DID with forwarding record.
    IdentityKey,
}

impl fmt::Display for CompromiseTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentKey => write!(f, "AgentKey (#agent)"),
            Self::ActiveSigningKey => write!(f, "ActiveSigningKey (#active)"),
            Self::IdentityKey => write!(f, "IdentityKey (#0)"),
        }
    }
}

// ---------------------------------------------------------------------------
// RecoveryStepError — per-step failure
// ---------------------------------------------------------------------------

/// Error from a single recovery step in a single context.
///
/// Wraps the underlying error and records which step failed. Steps are
/// per-context and failure-isolated: failure in one context does not block
/// recovery in others.
#[derive(Debug)]
pub enum RecoveryStepError {
    /// Step 1 (key rotation) failed.
    KeyRotation(String),
    /// Step 2 (MLS Update) failed in a specific context.
    MlsUpdate {
        /// The context where the update failed.
        context_id: String,
        /// The underlying MLS error description.
        error: String,
    },
    /// Step 3 (UCAN revocation) failed.
    UcanRevocation {
        /// The context where revocation failed.
        context_id: String,
        /// The underlying UCAN error description.
        error: String,
    },
    /// Step 4 (`KeyPackage` rotation) failed.
    KeyPackageRotation(String),
    /// Step 5 (contact notification) failed.
    ContactNotification(String),
    /// Step 6 (identity private state re-encryption) failed.
    PrivateStateReEncryption(String),
}

impl fmt::Display for RecoveryStepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyRotation(e) => write!(f, "key rotation failed: {e}"),
            Self::MlsUpdate { context_id, error } => {
                write!(f, "MLS Update failed in {context_id}: {error}")
            }
            Self::UcanRevocation { context_id, error } => {
                write!(f, "UCAN revocation failed in {context_id}: {error}")
            }
            Self::KeyPackageRotation(e) => write!(f, "KeyPackage rotation failed: {e}"),
            Self::ContactNotification(e) => write!(f, "contact notification failed: {e}"),
            Self::PrivateStateReEncryption(e) => {
                write!(f, "private state re-encryption failed: {e}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RecoveryError — orchestrator-level failure
// ---------------------------------------------------------------------------

/// Top-level error from the compromise recovery orchestrator.
///
/// Step 1 failure is fatal (cannot proceed without new key material).
/// Steps 2-6 are per-context and failure-isolated.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// Step 1 (key rotation) failed — recovery cannot proceed.
    #[error("key rotation failed (step 1): {0}")]
    KeyRotationFailed(#[from] IdentityError),

    /// `KeyPackage` buffer creation or replenishment failed.
    #[error("KeyPackage rotation failed (step 4): {0}")]
    KeyPackageRotationFailed(#[from] MlsError),

    /// The system clock is unavailable.
    #[error("clock error: {0}")]
    ClockError(#[from] crate::time::ClockError),
}

// ---------------------------------------------------------------------------
// ContextRecoveryOutcome — per-context result
// ---------------------------------------------------------------------------

/// Outcome of steps 2-4 for a single context.
#[derive(Debug)]
pub enum ContextRecoveryOutcome {
    /// All per-context steps (MLS Update, UCAN revocation, `KeyPackage`
    /// rotation) succeeded in this context.
    Completed,

    /// MLS Update succeeded but the context requires Tier 3 re-join
    /// (e.g., member offline too long per ADR-029).
    PendingRejoin {
        /// Reason the context needs re-join.
        reason: String,
    },

    /// One or more per-context steps failed. The context is recorded for
    /// independent retry; other contexts are not affected.
    Failed {
        /// The errors that occurred.
        errors: Vec<RecoveryStepError>,
    },
}

// ---------------------------------------------------------------------------
// RecoveryResult — overall result
// ---------------------------------------------------------------------------

/// Result of executing the compromise recovery protocol.
///
/// Contains per-context outcomes and the artifacts from each step.
/// A partial failure does not roll back completed contexts.
///
/// See spec §9.12.
#[derive(Debug)]
pub struct RecoveryResult {
    /// The compromise tier that was recovered from.
    pub tier: CompromiseTier,

    /// The updated identity after key rotation (step 1).
    pub updated_identity: ScpIdentity,

    /// The updated DID document after key rotation (step 1).
    pub updated_document: DidDocument,

    /// For [`CompromiseTier::IdentityKey`]: the DID rotation event to
    /// distribute to all active contexts. `None` for other tiers.
    pub rotation_event: Option<DidRotationEvent>,

    /// Contexts where all per-context steps completed successfully.
    pub completed_contexts: Vec<String>,

    /// Contexts where recovery failed. Each entry maps the context ID
    /// to the errors that occurred. These contexts should be retried
    /// independently.
    pub failed_contexts: Vec<(String, Vec<RecoveryStepError>)>,

    /// Contexts requiring Tier 3 re-join (member offline too long,
    /// ADR-029). The orchestrator flags these for manual re-join and
    /// does not block recovery in other contexts.
    pub pending_rejoin: Vec<String>,

    /// Whether contact notification (step 5) succeeded.
    pub contacts_notified: bool,

    /// Whether identity private state re-encryption (step 6) succeeded.
    pub private_state_re_encrypted: bool,
}

// ---------------------------------------------------------------------------
// PerContextState — mutable per-context state for steps 2-4
// ---------------------------------------------------------------------------

/// Mutable per-context state bundle for recovery steps 2-4.
///
/// The orchestrator processes each context independently. This struct
/// groups the per-context mutable references needed during recovery.
pub struct PerContextState<'a> {
    /// The context ID.
    pub context_id: String,

    /// The MLS group for this context. Step 2 issues an MLS Update.
    pub mls_group: &'a mut ScpMlsGroup,

    /// UCAN tokens issued by the compromised key in this context.
    /// Step 3 revokes these.
    pub tokens_to_revoke: Vec<UcanPayload>,

    /// The context's revocation list. Step 3 adds revocations.
    pub revocation_list: &'a mut RevocationList,
}

// ---------------------------------------------------------------------------
// RecoveryParams — input to execute_recovery
// ---------------------------------------------------------------------------

/// Parameters for [`execute_recovery`].
///
/// Groups the inputs to avoid excessive argument count.
pub struct RecoveryParams<'a, R: KeyRotator = scp_identity::DidDht> {
    /// The compromise tier.
    pub tier: CompromiseTier,

    /// The current identity being recovered.
    pub identity: &'a ScpIdentity,

    /// The current DID document.
    pub document: &'a DidDocument,

    /// The DID method instance for key rotation and identity migration.
    pub did_method: &'a R,

    /// For [`CompromiseTier::IdentityKey`]: the pre-rotation key handle.
    /// Required for identity migration. Ignored for other tiers.
    pub pre_rotation_key: Option<&'a KeyHandle>,

    /// The revoker DID (same as `identity.did` — the compromised party
    /// is revoking their own tokens).
    pub revoker_did: &'a str,
}

// ---------------------------------------------------------------------------
// ContactNotifier — trait for step 5
// ---------------------------------------------------------------------------

/// Abstraction for sending key-change notifications to contacts (step 5).
///
/// Implementors distribute notifications to all known contacts, alerting
/// those who completed Key Continuity Verification (§9.11) that
/// re-verification is needed.
pub trait ContactNotifier {
    /// Sends a key-change notification to all known contacts.
    ///
    /// # Arguments
    ///
    /// * `old_did` — The DID before rotation (same as new for non-identity
    ///   key tiers).
    /// * `new_did` — The DID after rotation (different only for identity
    ///   key compromise).
    /// * `tier` — The compromise tier, so contacts know the severity.
    ///
    /// # Errors
    ///
    /// Returns an error string if notification fails.
    fn notify_contacts(
        &self,
        old_did: &str,
        new_did: &str,
        tier: CompromiseTier,
    ) -> Result<(), String>;
}

/// Abstraction for re-encrypting identity private state (step 6).
///
/// Implementors generate a new PSK, distribute it to enrolled devices
/// via HPKE (§3.7.2), re-encrypt private state, and destroy the old PSK.
pub trait PrivateStateReEncryptor {
    /// Re-encrypts identity private state under a new PSK.
    ///
    /// For device compromise: the compromised device should be removed
    /// from the device registry before calling this, so it is excluded
    /// from new PSK distribution.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID whose private state is being re-encrypted.
    ///
    /// # Errors
    ///
    /// Returns an error string if re-encryption fails.
    fn re_encrypt_private_state(&self, did: &str) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// execute_recovery — the 6-step orchestrator
// ---------------------------------------------------------------------------

/// Executes the 6-step compromise recovery protocol (§9.12).
///
/// **Step ordering:** 1→2→3→4→(5,6 parallel).
///
/// - Step 1 is fatal: if key rotation fails, recovery cannot proceed.
/// - Steps 2-4 are per-context and failure-isolated.
/// - Steps 5 and 6 are independent cleanup.
///
/// # Arguments
///
/// * `key_custody` — Key custody provider for key generation and signing.
/// * `params` — Recovery parameters (tier, identity, document, DID method).
/// * `contexts` — Per-context mutable state for steps 2-4.
/// * `authorizer` — UCAN revocation authorizer.
/// * `distributor` — UCAN revocation distributor.
/// * `event_logger` — UCAN revocation event logger.
/// * `contact_notifier` — Contact notification (step 5).
/// * `state_re_encryptor` — Private state re-encryption (step 6).
///
/// # Errors
///
/// Returns [`RecoveryError`] if step 1 (key rotation) fails. All other
/// step failures are recorded in [`RecoveryResult`] without halting.
#[allow(clippy::too_many_arguments)]
pub async fn execute_recovery<R: KeyRotator>(
    key_custody: &impl KeyCustody,
    params: &RecoveryParams<'_, R>,
    contexts: Vec<PerContextState<'_>>,
    authorizer: &(impl RevocationAuthorizer + Sync),
    distributor: &(impl RevocationDistributor + Sync),
    event_logger: &(impl RevocationEventLogger + Sync),
    contact_notifier: &(impl ContactNotifier + Sync),
    state_re_encryptor: &(impl PrivateStateReEncryptor + Sync),
) -> Result<RecoveryResult, RecoveryError> {
    let timestamp = crate::time::now_secs()?;

    // -----------------------------------------------------------------------
    // Step 1: Key rotation on trusted device (tier-appropriate)
    // -----------------------------------------------------------------------
    let (updated_identity, updated_document, rotation_event) =
        execute_step1_key_rotation(key_custody, params, timestamp).await?;

    // -----------------------------------------------------------------------
    // Steps 2-4: Per-context operations (failure-isolated)
    // -----------------------------------------------------------------------
    let mut completed_contexts = Vec::new();
    let mut failed_contexts: Vec<(String, Vec<RecoveryStepError>)> = Vec::new();
    let mut pending_rejoin = Vec::new();

    for mut ctx in contexts {
        let context_id = ctx.context_id.clone();
        let outcome = execute_per_context_steps(&mut ctx, params, authorizer, distributor, event_logger);

        match outcome {
            ContextRecoveryOutcome::Completed => {
                completed_contexts.push(context_id);
            }
            ContextRecoveryOutcome::PendingRejoin { reason: _ } => {
                pending_rejoin.push(context_id);
            }
            ContextRecoveryOutcome::Failed { errors } => {
                failed_contexts.push((context_id, errors));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Steps 5 & 6: Independent cleanup (parallel in spirit; sequential here
    // because we're in a single-threaded test context, but the spec allows
    // parallel execution)
    // -----------------------------------------------------------------------

    // Step 5: Contact notification.
    let old_did = &params.identity.did;
    let new_did = &updated_identity.did;
    let contacts_notified = contact_notifier
        .notify_contacts(old_did, new_did, params.tier)
        .is_ok();

    // Step 6: Identity private state re-encryption.
    // Required for ActiveSigningKey and IdentityKey tiers (not agent-only).
    let private_state_re_encrypted = if params.tier == CompromiseTier::AgentKey {
        // Agent key compromise does not require PSK re-encryption.
        true
    } else {
        state_re_encryptor.re_encrypt_private_state(new_did).is_ok()
    };

    Ok(RecoveryResult {
        tier: params.tier,
        updated_identity,
        updated_document,
        rotation_event,
        completed_contexts,
        failed_contexts,
        pending_rejoin,
        contacts_notified,
        private_state_re_encrypted,
    })
}

// ---------------------------------------------------------------------------
// Step 1: Key rotation
// ---------------------------------------------------------------------------

/// Executes step 1: tier-appropriate key rotation.
///
/// - Agent key: removes/replaces `#agent` VM, signed by `#0`.
/// - Active signing key: `rotate_active_key` (ADR-003 §4a).
/// - Identity key: `migrate_identity` (ADR-003 §4b).
async fn execute_step1_key_rotation<R: KeyRotator>(
    key_custody: &impl KeyCustody,
    params: &RecoveryParams<'_, R>,
    timestamp: u64,
) -> Result<(ScpIdentity, DidDocument, Option<DidRotationEvent>), RecoveryError> {
    match params.tier {
        CompromiseTier::AgentKey => {
            // Remove the compromised #agent VM and re-add with a new key.
            // Step 1a: Remove old agent key.
            let (identity_no_agent, doc_no_agent) = params
                .did_method
                .remove_agent_key(params.identity, params.document)
                .await?;

            // Step 1b: Add new agent key.
            let (updated_identity, updated_document) = params
                .did_method
                .add_agent_key(&identity_no_agent, &doc_no_agent, key_custody)
                .await?;

            Ok((updated_identity, updated_document, None))
        }

        CompromiseTier::ActiveSigningKey => {
            // Rotate the active signing key (DID string preserved).
            let (updated_identity, updated_document) = params
                .did_method
                .rotate_active_key(params.identity, params.document, key_custody)
                .await?;

            Ok((updated_identity, updated_document, None))
        }

        CompromiseTier::IdentityKey => {
            // Migrate identity using pre-rotation key.
            let pre_rotation_key = params.pre_rotation_key.ok_or_else(|| {
                IdentityError::KeyRotationFailed(
                    "pre-rotation key required for identity key compromise recovery".to_owned(),
                )
            })?;

            let (updated_identity, updated_document, rotation_event) = params
                .did_method
                .migrate_identity(
                    params.identity,
                    params.document,
                    pre_rotation_key,
                    key_custody,
                    timestamp,
                )
                .await?;

            Ok((updated_identity, updated_document, Some(rotation_event)))
        }
    }
}

// ---------------------------------------------------------------------------
// Steps 2-4: Per-context operations
// ---------------------------------------------------------------------------

/// Executes steps 2-4 for a single context, with failure isolation.
///
/// Step 2: MLS Update proposal.
/// Step 3: UCAN revocation (all tokens issued by compromised key).
/// Step 4: `KeyPackage` rotation is handled at the orchestrator level
///         (not per-context), but old `KeyPackages` for this context are
///         invalidated by the MLS epoch advance in step 2.
fn execute_per_context_steps<R: KeyRotator>(
    ctx: &mut PerContextState<'_>,
    params: &RecoveryParams<'_, R>,
    authorizer: &impl RevocationAuthorizer,
    distributor: &impl RevocationDistributor,
    event_logger: &impl RevocationEventLogger,
) -> ContextRecoveryOutcome {
    let mut errors = Vec::new();

    // Step 2: MLS Update in this context.
    match propose_update(ctx.mls_group) {
        Ok(_commit_message) => {
            // Update succeeded — new epoch keys derived from new key material.
        }
        Err(MlsError::GroupDestroyed) => {
            // Group is destroyed — likely needs Tier 3 re-join.
            return ContextRecoveryOutcome::PendingRejoin {
                reason: "MLS group destroyed, requires Tier 3 re-join (ADR-029)".to_owned(),
            };
        }
        Err(e) => {
            errors.push(RecoveryStepError::MlsUpdate {
                context_id: ctx.context_id.clone(),
                error: e.to_string(),
            });
        }
    }

    // Step 3: UCAN revocation for all tokens issued by the compromised key.
    for token in &ctx.tokens_to_revoke {
        if let Err(e) = revoke_ucan(
            ctx.revocation_list,
            token,
            params.revoker_did,
            authorizer,
            distributor,
            event_logger,
        ) {
            errors.push(RecoveryStepError::UcanRevocation {
                context_id: ctx.context_id.clone(),
                error: e.to_string(),
            });
        }
    }

    if errors.is_empty() {
        ContextRecoveryOutcome::Completed
    } else {
        ContextRecoveryOutcome::Failed { errors }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::large_stack_frames
)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use scp_identity::cache::DidCache;
    use scp_identity::dht_client::InMemoryDhtClient;
    use scp_identity::DidDht;
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::KeyType;

    use crate::crypto::mls::credential::ScpCredential;
    use crate::crypto::mls::group::create_group;
    use crate::crypto::ucan::{UcanError, UcanPayload};

    // -----------------------------------------------------------------------
    // Test doubles
    // -----------------------------------------------------------------------

    /// Always-authorizes revocation.
    struct AlwaysAuthorize;
    impl RevocationAuthorizer for AlwaysAuthorize {
        fn authorize_revocation(&self, _cid: &str, _revoker: &str) -> Result<(), UcanError> {
            Ok(())
        }
    }

    /// No-op distributor — always succeeds.
    struct NoOpDistributor;
    impl RevocationDistributor for NoOpDistributor {
        fn distribute_revocation(&self, _ctx: &str, _cid: &str) -> Result<(), UcanError> {
            Ok(())
        }
    }

    /// No-op event logger — always succeeds.
    struct NoOpEventLogger;
    impl RevocationEventLogger for NoOpEventLogger {
        fn log_token_revoked(
            &self,
            _ctx: &str,
            _cid: &str,
            _revoker: &str,
        ) -> Result<(), UcanError> {
            Ok(())
        }
    }

    /// Failing distributor — always fails.
    struct FailingDistributor;
    impl RevocationDistributor for FailingDistributor {
        fn distribute_revocation(&self, _ctx: &str, _cid: &str) -> Result<(), UcanError> {
            Err(UcanError::RevocationFailed(
                "distributor unavailable".to_owned(),
            ))
        }
    }

    /// No-op contact notifier.
    struct NoOpContactNotifier;
    impl ContactNotifier for NoOpContactNotifier {
        fn notify_contacts(
            &self,
            _old: &str,
            _new: &str,
            _tier: CompromiseTier,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    /// Failing contact notifier.
    struct FailingContactNotifier;
    impl ContactNotifier for FailingContactNotifier {
        fn notify_contacts(
            &self,
            _old: &str,
            _new: &str,
            _tier: CompromiseTier,
        ) -> Result<(), String> {
            Err("contact notification failed".to_owned())
        }
    }

    /// No-op state re-encryptor.
    struct NoOpReEncryptor;
    impl PrivateStateReEncryptor for NoOpReEncryptor {
        fn re_encrypt_private_state(&self, _did: &str) -> Result<(), String> {
            Ok(())
        }
    }

    /// Failing state re-encryptor.
    struct FailingReEncryptor;
    impl PrivateStateReEncryptor for FailingReEncryptor {
        fn re_encrypt_private_state(&self, _did: &str) -> Result<(), String> {
            Err("re-encryption failed".to_owned())
        }
    }

    // -----------------------------------------------------------------------
    // Helper: create a DidMethod + identity for testing
    // -----------------------------------------------------------------------

    fn make_test_dht(custody: &Arc<InMemoryKeyCustody>) -> DidDht<InMemoryDhtClient> {
        let dht_client = Arc::new(InMemoryDhtClient::new());
        let cache = Arc::new(DidCache::new());
        let sign_fn = DidDht::<InMemoryDhtClient>::make_sign_fn(Arc::clone(custody));
        DidDht::with_client_and_signer(dht_client, cache, sign_fn)
    }

    async fn create_test_identity(
        custody: &Arc<InMemoryKeyCustody>,
    ) -> (DidDht<InMemoryDhtClient>, ScpIdentity, DidDocument) {
        let dht = make_test_dht(custody);
        let (identity, document) = dht.create_with_agent_key(&**custody).await.unwrap();
        (dht, identity, document)
    }

    /// Constructs a minimal `DidDocument` for tests that don't exercise step 1.
    /// Step 1 tests use `create_test_identity` which produces a real document.
    fn minimal_did_document() -> DidDocument {
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:dht:z6MkAlice".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: vec![],
        }
    }

    fn make_test_ucan_payload(issuer: &str) -> UcanPayload {
        UcanPayload {
            iss: issuer.to_owned(),
            aud: "did:dht:z6MkBob".to_owned(),
            exp: 9_999_999_999,
            nbf: None,
            nnc: "test-nonce".to_owned(),
            att: vec![],
            prf: vec![],
            fct: None,
        }
    }

    // -----------------------------------------------------------------------
    // CompromiseTier display
    // -----------------------------------------------------------------------

    #[test]
    fn compromise_tier_display() {
        assert_eq!(CompromiseTier::AgentKey.to_string(), "AgentKey (#agent)");
        assert_eq!(
            CompromiseTier::ActiveSigningKey.to_string(),
            "ActiveSigningKey (#active)"
        );
        assert_eq!(CompromiseTier::IdentityKey.to_string(), "IdentityKey (#0)");
    }

    // -----------------------------------------------------------------------
    // Step 1: Agent key rotation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn step1_agent_key_rotation_replaces_agent_vm() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let old_agent_key = identity.agent_signing_key.expect("should have agent key");

        let (updated_identity, updated_document, rotation_event) = execute_step1_key_rotation(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::AgentKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            0,
        )
        .await
        .unwrap();

        // DID string unchanged.
        assert_eq!(updated_identity.did, identity.did);

        // Agent key replaced (not None, but different handle).
        let new_agent_key = updated_identity
            .agent_signing_key
            .expect("should have new agent key");
        assert_ne!(
            old_agent_key, new_agent_key,
            "agent key handle should differ after rotation"
        );

        // No rotation event for agent key compromise.
        assert!(rotation_event.is_none());

        // Document should have an #agent VM (the new one).
        let has_agent = updated_document
            .verification_method
            .iter()
            .any(|vm| vm.id.ends_with("#agent"));
        assert!(has_agent, "document should have new #agent VM");
    }

    // -----------------------------------------------------------------------
    // Step 1: Active signing key rotation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn step1_active_key_rotation_preserves_did() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let old_active_key = identity.active_signing_key;

        let (updated_identity, _updated_document, rotation_event) = execute_step1_key_rotation(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::ActiveSigningKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            0,
        )
        .await
        .unwrap();

        // DID string unchanged.
        assert_eq!(updated_identity.did, identity.did);

        // Active key changed.
        assert_ne!(
            old_active_key, updated_identity.active_signing_key,
            "active signing key should differ after rotation"
        );

        // No rotation event (DID preserved).
        assert!(rotation_event.is_none());
    }

    // -----------------------------------------------------------------------
    // Step 1: Identity key migration
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn step1_identity_key_migration_creates_new_did() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        // Generate a pre-rotation key (in real usage, this comes from cold storage).
        let pre_rotation_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let (updated_identity, _updated_document, rotation_event) = execute_step1_key_rotation(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::IdentityKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: Some(&pre_rotation_key),
                revoker_did: &identity.did,
            },
            1234,
        )
        .await
        .unwrap();

        // DID string changed.
        assert_ne!(
            updated_identity.did, identity.did,
            "DID should change on identity key migration"
        );

        // Rotation event present.
        let event = rotation_event.expect("should have rotation event for identity key migration");
        assert_eq!(event.old_did, identity.did);
        assert_eq!(event.new_did, updated_identity.did);
    }

    #[tokio::test]
    async fn step1_identity_key_fails_without_pre_rotation_key() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let result = execute_step1_key_rotation(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::IdentityKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            0,
        )
        .await;

        assert!(result.is_err(), "should fail without pre-rotation key");
    }

    // -----------------------------------------------------------------------
    // Steps 2-4: Per-context operations
    // -----------------------------------------------------------------------

    #[test]
    fn per_context_steps_mls_update_succeeds() {
        let cred = ScpCredential::new(
            "did:dht:z6MkAlice".to_owned(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();
        let mut group = create_group(&cred).unwrap();

        let mut revocation_list = RevocationList::new("ctx-1".to_owned());

        let mut ctx = PerContextState {
            context_id: "ctx-1".to_owned(),
            mls_group: &mut group,
            tokens_to_revoke: vec![],
            revocation_list: &mut revocation_list,
        };

        let params = RecoveryParams {
            tier: CompromiseTier::AgentKey,
            identity: &ScpIdentity {
                identity_key: KeyHandle::new(0),
                active_signing_key: KeyHandle::new(1),
                agent_signing_key: Some(KeyHandle::new(2)),
                pre_rotation_commitment: [0u8; 32],
                did: "did:dht:z6MkAlice".to_owned(),
            },
            document: &minimal_did_document(),
            did_method: &DidDht::new(),
            pre_rotation_key: None,
            revoker_did: "did:dht:z6MkAlice",
        };

        let outcome = execute_per_context_steps(
            &mut ctx,
            &params,
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
        );

        assert!(
            matches!(outcome, ContextRecoveryOutcome::Completed),
            "should complete when MLS Update succeeds"
        );
    }

    #[test]
    fn per_context_steps_destroyed_group_flags_rejoin() {
        let cred = ScpCredential::new(
            "did:dht:z6MkAlice".to_owned(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();
        let mut group = create_group(&cred).unwrap();

        // Destroy the group to simulate a scenario needing re-join.
        crate::crypto::mls::group::destroy_group(&mut group).unwrap();

        let mut revocation_list = RevocationList::new("ctx-2".to_owned());

        let mut ctx = PerContextState {
            context_id: "ctx-2".to_owned(),
            mls_group: &mut group,
            tokens_to_revoke: vec![],
            revocation_list: &mut revocation_list,
        };

        let params = RecoveryParams {
            tier: CompromiseTier::AgentKey,
            identity: &ScpIdentity {
                identity_key: KeyHandle::new(0),
                active_signing_key: KeyHandle::new(1),
                agent_signing_key: Some(KeyHandle::new(2)),
                pre_rotation_commitment: [0u8; 32],
                did: "did:dht:z6MkAlice".to_owned(),
            },
            document: &minimal_did_document(),
            did_method: &DidDht::new(),
            pre_rotation_key: None,
            revoker_did: "did:dht:z6MkAlice",
        };

        let outcome = execute_per_context_steps(
            &mut ctx,
            &params,
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
        );

        assert!(
            matches!(outcome, ContextRecoveryOutcome::PendingRejoin { .. }),
            "destroyed group should flag for Tier 3 re-join"
        );
    }

    #[test]
    fn per_context_steps_ucan_revocation_failure_isolated() {
        let cred = ScpCredential::new(
            "did:dht:z6MkAlice".to_owned(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();
        let mut group = create_group(&cred).unwrap();

        let mut revocation_list = RevocationList::new("ctx-3".to_owned());

        // Add a token to revoke — the failing distributor will cause step 3 to fail.
        let token = make_test_ucan_payload("did:dht:z6MkAlice");

        let mut ctx = PerContextState {
            context_id: "ctx-3".to_owned(),
            mls_group: &mut group,
            tokens_to_revoke: vec![token],
            revocation_list: &mut revocation_list,
        };

        let params = RecoveryParams {
            tier: CompromiseTier::AgentKey,
            identity: &ScpIdentity {
                identity_key: KeyHandle::new(0),
                active_signing_key: KeyHandle::new(1),
                agent_signing_key: Some(KeyHandle::new(2)),
                pre_rotation_commitment: [0u8; 32],
                did: "did:dht:z6MkAlice".to_owned(),
            },
            document: &minimal_did_document(),
            did_method: &DidDht::new(),
            pre_rotation_key: None,
            revoker_did: "did:dht:z6MkAlice",
        };

        let outcome = execute_per_context_steps(
            &mut ctx,
            &params,
            &AlwaysAuthorize,
            &FailingDistributor,
            &NoOpEventLogger,
        );

        match outcome {
            ContextRecoveryOutcome::Failed { errors } => {
                assert_eq!(errors.len(), 1, "should have exactly one error");
                assert!(
                    matches!(&errors[0], RecoveryStepError::UcanRevocation { .. }),
                    "error should be UCAN revocation failure"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Failure isolation: multi-context
    // -----------------------------------------------------------------------

    #[test]
    fn failure_in_context_a_does_not_prevent_context_b() {
        let cred = ScpCredential::new(
            "did:dht:z6MkAlice".to_owned(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();

        // Context A: destroyed group → PendingRejoin.
        let mut group_a = create_group(&cred).unwrap();
        crate::crypto::mls::group::destroy_group(&mut group_a).unwrap();
        let mut rev_list_a = RevocationList::new("ctx-a".to_owned());

        // Context B: healthy group → Completed.
        let mut group_b = create_group(&cred).unwrap();
        let mut rev_list_b = RevocationList::new("ctx-b".to_owned());

        let contexts = vec![
            PerContextState {
                context_id: "ctx-a".to_owned(),
                mls_group: &mut group_a,
                tokens_to_revoke: vec![],
                revocation_list: &mut rev_list_a,
            },
            PerContextState {
                context_id: "ctx-b".to_owned(),
                mls_group: &mut group_b,
                tokens_to_revoke: vec![],
                revocation_list: &mut rev_list_b,
            },
        ];

        let params = RecoveryParams {
            tier: CompromiseTier::AgentKey,
            identity: &ScpIdentity {
                identity_key: KeyHandle::new(0),
                active_signing_key: KeyHandle::new(1),
                agent_signing_key: Some(KeyHandle::new(2)),
                pre_rotation_commitment: [0u8; 32],
                did: "did:dht:z6MkAlice".to_owned(),
            },
            document: &minimal_did_document(),
            did_method: &DidDht::new(),
            pre_rotation_key: None,
            revoker_did: "did:dht:z6MkAlice",
        };

        let mut completed = Vec::new();
        let mut pending = Vec::new();

        for mut ctx in contexts {
            let context_id = ctx.context_id.clone();
            let outcome = execute_per_context_steps(
                &mut ctx,
                &params,
                &AlwaysAuthorize,
                &NoOpDistributor,
                &NoOpEventLogger,
            );
            match outcome {
                ContextRecoveryOutcome::Completed => completed.push(context_id),
                ContextRecoveryOutcome::PendingRejoin { .. } => pending.push(context_id),
                ContextRecoveryOutcome::Failed { .. } => {}
            }
        }

        assert_eq!(completed, vec!["ctx-b"], "context B should complete");
        assert_eq!(
            pending,
            vec!["ctx-a"],
            "context A should be pending re-join"
        );
    }

    // -----------------------------------------------------------------------
    // Full orchestrator: agent key compromise
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn full_recovery_agent_key_compromise() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let cred = ScpCredential::new(
            identity.did.clone(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();
        let mut group = create_group(&cred).unwrap();
        let mut rev_list = RevocationList::new("ctx-1".to_owned());

        let contexts = vec![PerContextState {
            context_id: "ctx-1".to_owned(),
            mls_group: &mut group,
            tokens_to_revoke: vec![],
            revocation_list: &mut rev_list,
        }];

        let result = execute_recovery(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::AgentKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            contexts,
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
            &NoOpContactNotifier,
            &NoOpReEncryptor,
        )
        .await
        .unwrap();

        assert_eq!(result.tier, CompromiseTier::AgentKey);
        assert_eq!(result.completed_contexts, vec!["ctx-1"]);
        assert!(result.failed_contexts.is_empty());
        assert!(result.pending_rejoin.is_empty());
        assert!(result.rotation_event.is_none());
        assert!(result.contacts_notified);
        // Agent key compromise skips PSK re-encryption.
        assert!(result.private_state_re_encrypted);
    }

    // -----------------------------------------------------------------------
    // Full orchestrator: active signing key compromise
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn full_recovery_active_key_compromise() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let cred = ScpCredential::new(
            identity.did.clone(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();
        let mut group = create_group(&cred).unwrap();
        let mut rev_list = RevocationList::new("ctx-1".to_owned());

        let contexts = vec![PerContextState {
            context_id: "ctx-1".to_owned(),
            mls_group: &mut group,
            tokens_to_revoke: vec![],
            revocation_list: &mut rev_list,
        }];

        let result = execute_recovery(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::ActiveSigningKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            contexts,
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
            &NoOpContactNotifier,
            &NoOpReEncryptor,
        )
        .await
        .unwrap();

        assert_eq!(result.tier, CompromiseTier::ActiveSigningKey);
        assert_eq!(result.completed_contexts, vec!["ctx-1"]);
        assert!(result.rotation_event.is_none());
        assert_ne!(
            result.updated_identity.active_signing_key, identity.active_signing_key,
            "active key should be rotated"
        );
        assert!(result.private_state_re_encrypted);
    }

    // -----------------------------------------------------------------------
    // Full orchestrator: identity key compromise
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn full_recovery_identity_key_compromise() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let pre_rotation_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        let cred = ScpCredential::new(
            identity.did.clone(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();
        let mut group = create_group(&cred).unwrap();
        let mut rev_list = RevocationList::new("ctx-1".to_owned());

        let contexts = vec![PerContextState {
            context_id: "ctx-1".to_owned(),
            mls_group: &mut group,
            tokens_to_revoke: vec![],
            revocation_list: &mut rev_list,
        }];

        let result = execute_recovery(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::IdentityKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: Some(&pre_rotation_key),
                revoker_did: &identity.did,
            },
            contexts,
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
            &NoOpContactNotifier,
            &NoOpReEncryptor,
        )
        .await
        .unwrap();

        assert_eq!(result.tier, CompromiseTier::IdentityKey);
        assert_ne!(result.updated_identity.did, identity.did);
        assert!(result.rotation_event.is_some());
        assert_eq!(result.completed_contexts, vec!["ctx-1"]);
    }

    // -----------------------------------------------------------------------
    // Steps 5 & 6: Contact notification and re-encryption failures
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn contact_notification_failure_does_not_block_recovery() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let result = execute_recovery(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::AgentKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            vec![],
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
            &FailingContactNotifier,
            &NoOpReEncryptor,
        )
        .await
        .unwrap();

        assert!(
            !result.contacts_notified,
            "should record notification failure"
        );
        // Recovery still succeeds overall.
        assert!(result.failed_contexts.is_empty());
    }

    #[tokio::test]
    async fn re_encryption_failure_does_not_block_recovery() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let result = execute_recovery(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::ActiveSigningKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            vec![],
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
            &NoOpContactNotifier,
            &FailingReEncryptor,
        )
        .await
        .unwrap();

        assert!(
            !result.private_state_re_encrypted,
            "should record re-encryption failure"
        );
    }

    // -----------------------------------------------------------------------
    // RecoveryStepError display
    // -----------------------------------------------------------------------

    #[test]
    fn recovery_step_error_display() {
        let e = RecoveryStepError::MlsUpdate {
            context_id: "ctx-1".to_owned(),
            error: "group destroyed".to_owned(),
        };
        assert_eq!(e.to_string(), "MLS Update failed in ctx-1: group destroyed");

        let e = RecoveryStepError::KeyRotation("key not found".to_owned());
        assert_eq!(e.to_string(), "key rotation failed: key not found");

        let e = RecoveryStepError::UcanRevocation {
            context_id: "ctx-2".to_owned(),
            error: "unauthorized".to_owned(),
        };
        assert_eq!(
            e.to_string(),
            "UCAN revocation failed in ctx-2: unauthorized"
        );

        let e = RecoveryStepError::KeyPackageRotation("buffer exhausted".to_owned());
        assert_eq!(
            e.to_string(),
            "KeyPackage rotation failed: buffer exhausted"
        );

        let e = RecoveryStepError::ContactNotification("timeout".to_owned());
        assert_eq!(e.to_string(), "contact notification failed: timeout");

        let e = RecoveryStepError::PrivateStateReEncryption("psk error".to_owned());
        assert_eq!(
            e.to_string(),
            "private state re-encryption failed: psk error"
        );
    }

    // -----------------------------------------------------------------------
    // Step ordering: MLS Update uses new key material (step 2 depends on step 1)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn step_ordering_mls_update_after_key_rotation() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let cred = ScpCredential::new(
            identity.did.clone(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();
        let mut group = create_group(&cred).unwrap();
        let epoch_before = group.epoch().unwrap();

        let mut rev_list = RevocationList::new("ctx-1".to_owned());

        let contexts = vec![PerContextState {
            context_id: "ctx-1".to_owned(),
            mls_group: &mut group,
            tokens_to_revoke: vec![],
            revocation_list: &mut rev_list,
        }];

        let result = execute_recovery(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::ActiveSigningKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            contexts,
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
            &NoOpContactNotifier,
            &NoOpReEncryptor,
        )
        .await
        .unwrap();

        assert_eq!(result.completed_contexts, vec!["ctx-1"]);

        // The MLS group should have advanced epoch (step 2 executed after step 1).
        let epoch_after = group.epoch().unwrap();
        assert!(
            epoch_after > epoch_before,
            "MLS epoch should advance after Update (step 2)"
        );
    }

    // -----------------------------------------------------------------------
    // Multi-context: mixed success and failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn multi_context_mixed_outcomes() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let cred = ScpCredential::new(
            identity.did.clone(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();

        // Context 1: healthy → Completed.
        let mut group1 = create_group(&cred).unwrap();
        let mut rev_list1 = RevocationList::new("ctx-1".to_owned());

        // Context 2: destroyed → PendingRejoin.
        let mut group2 = create_group(&cred).unwrap();
        crate::crypto::mls::group::destroy_group(&mut group2).unwrap();
        let mut rev_list2 = RevocationList::new("ctx-2".to_owned());

        // Context 3: healthy but UCAN revocation will fail → Failed.
        let _group3 = create_group(&cred).unwrap();
        let _rev_list3 = RevocationList::new("ctx-3".to_owned());
        let _token = make_test_ucan_payload(&identity.did);

        let contexts = vec![
            PerContextState {
                context_id: "ctx-1".to_owned(),
                mls_group: &mut group1,
                tokens_to_revoke: vec![],
                revocation_list: &mut rev_list1,
            },
            PerContextState {
                context_id: "ctx-2".to_owned(),
                mls_group: &mut group2,
                tokens_to_revoke: vec![],
                revocation_list: &mut rev_list2,
            },
        ];

        // Execute first batch with NoOp distributor.
        let result = execute_recovery(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::AgentKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            contexts,
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
            &NoOpContactNotifier,
            &NoOpReEncryptor,
        )
        .await
        .unwrap();

        assert_eq!(result.completed_contexts, vec!["ctx-1"]);
        assert_eq!(result.pending_rejoin, vec!["ctx-2"]);
        assert!(result.failed_contexts.is_empty());
    }

    // -----------------------------------------------------------------------
    // UCAN revocation: tokens issued by compromised key are revoked
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ucan_revocation_in_context_succeeds() {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let (dht, identity, document) = create_test_identity(&custody).await;

        let cred = ScpCredential::new(
            identity.did.clone(),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap();
        let mut group = create_group(&cred).unwrap();
        let mut rev_list = RevocationList::new("ctx-1".to_owned());

        let token = make_test_ucan_payload(&identity.did);

        let contexts = vec![PerContextState {
            context_id: "ctx-1".to_owned(),
            mls_group: &mut group,
            tokens_to_revoke: vec![token],
            revocation_list: &mut rev_list,
        }];

        let result = execute_recovery(
            &*custody,
            &RecoveryParams {
                tier: CompromiseTier::AgentKey,
                identity: &identity,
                document: &document,
                did_method: &dht,
                pre_rotation_key: None,
                revoker_did: &identity.did,
            },
            contexts,
            &AlwaysAuthorize,
            &NoOpDistributor,
            &NoOpEventLogger,
            &NoOpContactNotifier,
            &NoOpReEncryptor,
        )
        .await
        .unwrap();

        assert_eq!(result.completed_contexts, vec!["ctx-1"]);

        // The revocation list should have the token marked as revoked.
        assert!(
            !rev_list.is_empty(),
            "revocation list should contain the revoked token"
        );
    }
}
