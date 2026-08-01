//! Runtime-side key destruction orchestration.
//!
//! Hosts the concrete-typed key-destruction orchestrators that were
//! previously defined as trait-based stubs in
//! [`scp_protocol::context::memory_scope`] and
//! [`scp_protocol::context::close`]. After ADR-049 §15 the
//! orchestrators operate directly on the concrete
//! [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider),
//! so they cannot live in `scp-protocol` (which is a forward dependency
//! of `scp-runtime`).
//!
//! The companion pure-data types (attestations, request/response enums,
//! verification window, close events / actions) remain in
//! `scp-protocol` — only the orchestrators, which actually invoke the
//! crypto provider, moved here.
//!
//! Implements ADR-018 (`.docs/adrs/phase-4.md`), sections 5-9:
//!
//! - [`KeyDestructionOrchestrator`] — Orchestrates MLS group state destruction,
//!   sender key destruction, and relay deletion requests for ephemeral close.
//! - [`CloseOrchestrator`] — Dispatches context close to the correct destruction
//!   path based on [`MemoryScope`].

use scp_protocol::context::ContextError;
use scp_protocol::context::MemoryScope;
use scp_protocol::context::close::{
    CloseAction, CloseEvent, ContextCloseReason, DEFAULT_VERIFICATION_WINDOW_SECS,
    SummaryVerificationWindow,
};
use scp_protocol::context::memory_scope::{
    BlobId, KeyDestructionAttestation, KeyDestructionLevel, KeyDestructionResult,
    RelayDeletionRequest,
};

// ---------------------------------------------------------------------------
// KeyDestructionOrchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the relay-deletion + attestation side of ephemeral (and
/// summary, post-window) context close.
///
/// #2148 (ADR-049 birth-into-actor): the actual MLS-group + sender-key
/// destruction is performed by the ACTOR that owns the context's crypto — the
/// `LifecycleCommand::CloseContext` the caller dispatches BEFORE invoking this
/// orchestrator routes through the actor's close handler, which disposes the
/// actor-owned `ContextCryptoState` (running `OpenMLS` `destroy_group` +
/// zeroizing the sender key material) for Ephemeral/Summary scope. The provider holds NO
/// per-context crypto (its `destroy_mls_group` / `destroy_sender_key` methods are
/// DELETED), so this orchestrator no longer touches crypto directly. It issues
/// the relay deletion requests for the encrypted event data and produces the
/// destruction attestation.
///
/// See ADR-018 acceptance criteria 5 and 6.
#[derive(Default)]
pub struct KeyDestructionOrchestrator;

impl KeyDestructionOrchestrator {
    /// Creates a new orchestrator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Issues relay deletion requests + builds the destruction attestation for
    /// an ephemeral context close.
    ///
    /// #2148 (ADR-049 birth-into-actor): the MLS group + sender-key destruction
    /// itself is performed by the context's ACTOR (via the `CloseContext`
    /// command the caller dispatched first); this method issues the
    /// [`RelayDeletionRequest`]s for all encrypted event data and records the
    /// attestation.
    ///
    /// The `attestation_level` parameter records the platform's attestation
    /// level for key destruction. This is metadata -- not a gate.
    ///
    /// # Errors
    ///
    /// Infallible in practice (returns `Result` for signature stability with the
    /// summary-window caller).
    pub fn destroy_ephemeral_keys(
        &self,
        context_id: &str,
        relay_urls: &[String],
        blob_ids: &[BlobId],
        attestation_level: KeyDestructionLevel,
        now: u64,
    ) -> Result<KeyDestructionResult, ContextError> {
        // Issue relay deletion requests for all encrypted event data.
        let deletion_requests: Vec<RelayDeletionRequest> = relay_urls
            .iter()
            .map(|url| RelayDeletionRequest {
                relay_url: url.clone(),
                blob_ids: blob_ids.to_vec(),
                context_id: context_id.to_owned(),
                requested_at: now,
            })
            .collect();

        let attestation = KeyDestructionAttestation {
            context_id: context_id.to_owned(),
            level: attestation_level,
            attested_at: now,
            mls_group_destroyed: true,
            sender_keys_destroyed: true,
        };

        Ok(KeyDestructionResult {
            attestation,
            deletion_requests,
        })
    }
}

// ---------------------------------------------------------------------------
// CloseOrchestrator
// ---------------------------------------------------------------------------

/// Dispatches context close to the correct destruction path based on
/// [`MemoryScope`].
///
/// The orchestrator coordinates the close sequencing:
/// - **Ephemeral:** Immediate key destruction via [`KeyDestructionOrchestrator`].
/// - **Summary:** Opens a [`SummaryVerificationWindow`], then destroys keys
///   after the window closes.
/// - **Full:** Preserves all keys and data; no destruction occurs.
///
/// The orchestrator does not own the context state machine transitions --
/// those are handled by the caller (e.g., `close_context` and
/// `finalize_close` in `ttl.rs`) and, for the actual crypto teardown, by the
/// context's actor (#2148 birth-into-actor). This module provides the
/// relay-deletion + attestation logic only.
#[derive(Default)]
pub struct CloseOrchestrator {
    /// Relay-deletion + attestation orchestrator for Ephemeral and Summary scopes.
    key_destruction: KeyDestructionOrchestrator,
}

impl CloseOrchestrator {
    /// Creates a new close orchestrator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            key_destruction: KeyDestructionOrchestrator::new(),
        }
    }

    /// Initiates the close sequence based on the context's memory scope and
    /// close reason.
    ///
    /// Returns a [`CloseAction`] that describes what the caller should do
    /// next:
    /// - [`CloseAction::KeysDestroyed`] for Ephemeral scope (immediate).
    /// - [`CloseAction::VerificationWindowOpened`] for Summary scope.
    /// - [`CloseAction::Preserved`] for Full scope (no destruction).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if key destruction fails
    /// (Ephemeral scope only).
    #[allow(clippy::too_many_arguments)]
    pub fn initiate_close(
        &self,
        context_id: &str,
        reason: ContextCloseReason,
        memory_scope: MemoryScope,
        relay_urls: &[String],
        blob_ids: &[BlobId],
        attestation_level: KeyDestructionLevel,
        member_count: usize,
        verification_window_secs: Option<u64>,
        now: u64,
    ) -> Result<CloseAction, ContextError> {
        match memory_scope {
            MemoryScope::Ephemeral => {
                let result = self.key_destruction.destroy_ephemeral_keys(
                    context_id,
                    relay_urls,
                    blob_ids,
                    attestation_level,
                    now,
                )?;

                Ok(CloseAction::KeysDestroyed {
                    reason,
                    result,
                    event: CloseEvent::KeysDestroyed {
                        attestation_level,
                        destroyed_at: now,
                    },
                })
            }

            MemoryScope::Summary => {
                let window_duration =
                    verification_window_secs.unwrap_or(DEFAULT_VERIFICATION_WINDOW_SECS);
                let window = SummaryVerificationWindow::new(
                    context_id.to_owned(),
                    now,
                    window_duration,
                    member_count,
                );

                let event = CloseEvent::SummaryWindowOpened {
                    opened_at: now,
                    deadline: now.saturating_add(window_duration),
                    member_count,
                };

                Ok(CloseAction::VerificationWindowOpened {
                    reason,
                    window,
                    event,
                })
            }

            MemoryScope::Full => Ok(CloseAction::Preserved {
                reason,
                event: CloseEvent::FullCloseCompleted { completed_at: now },
            }),
        }
    }

    /// Completes a summary close after the verification window has closed.
    ///
    /// Destroys keys using the same path as ephemeral close. This should be
    /// called only after [`SummaryVerificationWindow::is_window_closed`]
    /// returns `true`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CryptoFailed`] if key destruction fails.
    /// Returns [`ContextError::ContextNotActive`] if the verification
    /// window has not yet closed.
    pub fn complete_summary_close(
        &self,
        window: &SummaryVerificationWindow,
        relay_urls: &[String],
        blob_ids: &[BlobId],
        attestation_level: KeyDestructionLevel,
        now: u64,
    ) -> Result<KeyDestructionResult, ContextError> {
        if !window.is_window_closed(now) {
            return Err(ContextError::ContextNotActive);
        }

        self.key_destruction.destroy_ephemeral_keys(
            window.context_id(),
            relay_urls,
            blob_ids,
            attestation_level,
            now,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn destroy_ephemeral_keys_happy_path() {
        // #2148 (ADR-049 birth-into-actor): the orchestrator no longer holds a
        // crypto provider — it issues relay-deletion requests + the attestation;
        // the actor destroys its own crypto via the dispatched CloseContext.
        let orchestrator = KeyDestructionOrchestrator::new();

        let result = orchestrator.destroy_ephemeral_keys(
            "ctx-1",
            &["wss://relay1.example.com".to_owned()],
            &[[0x01; 32]],
            KeyDestructionLevel::SoftwareOnly,
            1_700_000_000,
        );

        assert!(result.is_ok());
        let out = result.unwrap();
        assert_eq!(out.deletion_requests.len(), 1);
        assert_eq!(out.attestation.level, KeyDestructionLevel::SoftwareOnly);
        assert!(out.attestation.mls_group_destroyed);
        assert!(out.attestation.sender_keys_destroyed);
    }

    #[test]
    fn initiate_close_full_scope_preserves_data() {
        let orchestrator = CloseOrchestrator::new();

        let action = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::GovernanceClosed,
                MemoryScope::Full,
                &[],
                &[],
                KeyDestructionLevel::SoftwareOnly,
                0,
                None,
                1_700_000_000,
            )
            .unwrap();

        assert!(matches!(action, CloseAction::Preserved { .. }));
    }

    #[test]
    fn initiate_close_ephemeral_scope_destroys_keys() {
        let orchestrator = CloseOrchestrator::new();

        let action = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::TtlExpired,
                MemoryScope::Ephemeral,
                &["wss://relay.example.com".to_owned()],
                &[[0x42; 32]],
                KeyDestructionLevel::HardwareAttested,
                2,
                None,
                1_700_000_000,
            )
            .unwrap();

        match action {
            CloseAction::KeysDestroyed { result, .. } => {
                assert_eq!(result.deletion_requests.len(), 1);
                assert!(result.attestation.mls_group_destroyed);
            }
            _ => panic!("expected KeysDestroyed"),
        }
    }

    #[test]
    fn initiate_close_summary_scope_opens_window() {
        let orchestrator = CloseOrchestrator::new();

        let action = orchestrator
            .initiate_close(
                "ctx-1",
                ContextCloseReason::GovernanceClosed,
                MemoryScope::Summary,
                &[],
                &[],
                KeyDestructionLevel::SoftwareOnly,
                3,
                Some(600),
                1_700_000_000,
            )
            .unwrap();

        match action {
            CloseAction::VerificationWindowOpened { window, .. } => {
                assert_eq!(window.context_id(), "ctx-1");
                assert_eq!(window.member_count(), 3);
            }
            _ => panic!("expected VerificationWindowOpened"),
        }
    }

    // #2148 (ADR-049 birth-into-actor): the former
    // `destroy_ephemeral_keys_real_context_via_chokepoint_not_raw_primitive`
    // test was DELETED. It exercised a provider mechanic that no longer exists —
    // the orchestrator used to resolve the context-id string to bytes and call
    // the provider's `destroy_mls_group` / `destroy_sender_key` under the decoded
    // digest. The orchestrator no longer touches crypto at all (the context's
    // actor disposes its own owned crypto via the dispatched `CloseContext`), so
    // there is no provider-residency to assert and no id-resolution to guard here.
    // The ADR-056 decode-not-rehash keying invariant is now proved at the birth
    // seam / actor level (see `builder::create_context` tests), not the close
    // orchestrator.
}
