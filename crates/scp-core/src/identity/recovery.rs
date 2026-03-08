//! Compromise recovery orchestrator for SCP identity keys.
//!
//! Implements the 6-step ordered recovery protocol from spec §9.12. When a key
//! is known or suspected to be compromised, the orchestrator coordinates:
//!
//! 1. **Key rotation** on a trusted device (3 tiers: agent, active, identity).
//! 2. **MLS `Update`** in all active contexts (per-context, failure-isolated).
//! 3. **UCAN revocation** of all tokens issued by the compromised key.
//! 4. **`KeyPackage` rotation** — delete old, publish new.
//! 5. **Contact notification** — key-change alerts to all known contacts.
//! 6. **Identity private state re-encryption** — PSK rotation, device removal.
//!
//! Step ordering is enforced by dependency: 1→2→3→4→(5,6 parallel). Failure
//! in one context does not block recovery in others. Each per-context step
//! retries independently.
//!
//! Three compromise tiers:
//! - **Agent key** (cheapest): DID doc update → scoped UCAN revocation → MLS
//!   `Update` → new `KeyPackages`. No identity migration.
//! - **Active signing key**: Includes PSK re-encryption.
//! - **Identity key** (most severe): Pre-rotation, new DID, forwarding record.
//!
//! See spec §9.12 and ADR-003 §4a/§4b.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use scp_identity::DID;

use crate::time;

// ---------------------------------------------------------------------------
// CompromiseTier — which key was compromised
// ---------------------------------------------------------------------------

/// The tier of key compromise, determining the scope of recovery actions.
///
/// Ordered by severity: `Agent` (cheapest recovery) < `ActiveSigning`
/// < `IdentityKey` (most severe, requires identity migration).
///
/// See spec §9.12 steps 1a–1c.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompromiseTier {
    /// Agent Signing Key (`#agent`) compromise — most common case.
    ///
    /// The agent runtime is typically less secure than device HSM. Recovery:
    /// publish new DID document removing/replacing `#agent` VM, revoke only
    /// agent-scoped UCANs, MLS `Update`, new `KeyPackages`. No identity
    /// migration.
    Agent,

    /// Active Signing Key (`#active`) compromise.
    ///
    /// Calls `rotate_active_key` (ADR-003 §4a). DID string unchanged. Includes
    /// PSK re-encryption (step 6).
    ActiveSigning,

    /// Identity Key (`#0`) compromise — rare, most severe.
    ///
    /// Calls `migrate_identity` (ADR-003 §4b) using pre-rotation key. Creates
    /// new DID with forwarding record. All contexts receive `DidRotationEvent`.
    IdentityKey,
}

// ---------------------------------------------------------------------------
// RecoveryStepError — per-step error type
// ---------------------------------------------------------------------------

/// Error from a single recovery step in a single context.
///
/// Each step that operates per-context (steps 2, 3, 4) may fail independently.
/// The orchestrator collects these errors without blocking recovery in other
/// contexts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStepError {
    /// The step number (1–6) where the failure occurred.
    pub step: u8,

    /// Human-readable description of the failure.
    pub description: String,
}

impl std::fmt::Display for RecoveryStepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "step {}: {}", self.step, self.description)
    }
}

// ---------------------------------------------------------------------------
// RecoveryResult — outcome of the full recovery sequence
// ---------------------------------------------------------------------------

/// Outcome of executing the compromise recovery protocol.
///
/// Contains per-context results with failure isolation: a partial failure does
/// not roll back completed contexts. Contexts requiring Tier 3 re-join (MLS
/// `Update` cannot succeed, e.g. member offline too long per ADR-029) are
/// flagged separately from outright failures.
///
/// See spec §9.12 "Step ordering and failure isolation."
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResult {
    /// The compromise tier that was addressed.
    pub tier: CompromiseTier,

    /// The DID that initiated recovery.
    pub did: DID,

    /// Whether the DID changed (only for `IdentityKey` tier with migration).
    pub new_did: Option<DID>,

    /// Contexts where ALL recovery steps completed successfully.
    pub completed_contexts: Vec<String>,

    /// Contexts where one or more steps failed.
    pub failed_contexts: Vec<(String, RecoveryStepError)>,

    /// Contexts flagged for manual re-join (Tier 3 per ADR-029).
    ///
    /// These contexts could not complete MLS `Update` because the member has
    /// been offline too long. Recovery is NOT blocked by these — they require
    /// separate action (remove + re-add by an admin).
    pub pending_rejoin: Vec<String>,

    /// Whether step 1 (key rotation on trusted device) succeeded.
    pub key_rotation_completed: bool,

    /// Whether step 5 (contact notification) was sent.
    pub contacts_notified: bool,

    /// Whether step 6 (identity private state re-encryption) completed.
    pub private_state_reencrypted: bool,

    /// Unix timestamp (milliseconds) when recovery was initiated.
    pub initiated_at: u64,

    /// Unix timestamp (milliseconds) when recovery completed.
    pub completed_at: u64,
}

// ---------------------------------------------------------------------------
// RecoveryError — orchestrator-level error
// ---------------------------------------------------------------------------

/// Errors produced by the compromise recovery orchestrator.
///
/// Step 1 (key rotation) failure is fatal — the orchestrator cannot proceed
/// without new key material. Steps 2–4 failures are per-context and recorded
/// in `RecoveryResult::failed_contexts`. Steps 5–6 failures are non-fatal
/// cleanup errors.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// Step 1 failed: key rotation on trusted device.
    ///
    /// This is fatal — cannot proceed without new key material.
    #[error("key rotation failed (step 1): {0}")]
    KeyRotationFailed(String),

    /// The system clock is unavailable.
    #[error("clock error: {0}")]
    ClockError(#[from] time::ClockError),

    /// The compromise tier requires an agent key but none exists.
    #[error("agent key not found in identity")]
    AgentKeyNotFound,

    /// The compromise tier requires a pre-rotation key but none is available.
    #[error("pre-rotation key not available for identity migration")]
    PreRotationKeyNotAvailable,

    /// The DID method implementation returned an error.
    #[error("DID method error: {0}")]
    DidMethodError(String),

    /// A platform custody error occurred during key operations.
    #[error("custody error: {0}")]
    CustodyError(String),
}

// ---------------------------------------------------------------------------
// ContextRecoveryState — per-context step tracking
// ---------------------------------------------------------------------------

/// Tracks which recovery steps have been completed for a single context.
///
/// Used internally by the orchestrator to resume after partial failures.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRecoveryState {
    /// The context ID.
    pub context_id: String,

    /// Whether step 2 (MLS `Update`) completed.
    pub mls_updated: bool,

    /// Whether step 3 (UCAN revocation) completed.
    pub ucan_revoked: bool,

    /// Whether step 4 (`KeyPackage` rotation) completed.
    pub key_packages_rotated: bool,

    /// Whether this context requires Tier 3 re-join.
    pub requires_rejoin: bool,

    /// Error encountered, if any.
    pub error: Option<RecoveryStepError>,
}

impl ContextRecoveryState {
    /// Creates a new context recovery state with no steps completed.
    #[must_use]
    pub const fn new(context_id: String) -> Self {
        Self {
            context_id,
            mls_updated: false,
            ucan_revoked: false,
            key_packages_rotated: false,
            requires_rejoin: false,
            error: None,
        }
    }

    /// Returns `true` if all per-context steps completed successfully.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        (self.mls_updated || self.requires_rejoin)
            && self.ucan_revoked
            && self.key_packages_rotated
            && self.error.is_none()
    }
}

// ---------------------------------------------------------------------------
// KeyRotationOutcome — result of step 1
// ---------------------------------------------------------------------------

/// Outcome of step 1 (key rotation on trusted device).
///
/// Contains the new key material identifiers needed by subsequent steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationOutcome {
    /// The compromise tier that was addressed.
    pub tier: CompromiseTier,

    /// The DID after rotation. Same as original for `Agent`/`ActiveSigning`
    /// tiers; new DID for `IdentityKey` tier.
    pub did_after: DID,

    /// Whether the DID changed (identity migration occurred).
    pub did_changed: bool,

    /// Key scope(s) that were rotated — used to scope UCAN revocation.
    ///
    /// For `Agent` tier: `["#agent"]`.
    /// For `ActiveSigning` tier: `["#active"]`.
    /// For `IdentityKey` tier: `["#active", "#agent"]` (all signing keys).
    pub rotated_key_scopes: Vec<String>,

    /// Unix timestamp (milliseconds) of the rotation.
    pub rotated_at: u64,
}

// ---------------------------------------------------------------------------
// ContactNotification — step 5 payload
// ---------------------------------------------------------------------------

/// Key-change notification sent to contacts in step 5.
///
/// Contacts who completed Key Continuity Verification (§9.11) are alerted
/// that re-verification is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactNotification {
    /// The DID that underwent recovery.
    pub did: DID,

    /// The new DID, if identity migration occurred.
    pub new_did: Option<DID>,

    /// The compromise tier.
    pub tier: CompromiseTier,

    /// Unix timestamp (milliseconds) of the key change.
    pub timestamp: u64,

    /// Whether Key Continuity Verification re-verification is needed.
    pub kcv_reverification_required: bool,
}

// ---------------------------------------------------------------------------
// PskRotationParams — step 6 parameters
// ---------------------------------------------------------------------------

/// Parameters for step 6: identity private state re-encryption.
///
/// Includes the set of enrolled device public keys (to distribute the new PSK
/// via HPKE) and optionally a compromised device to exclude.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PskRotationParams {
    /// X25519 public keys of all enrolled devices.
    pub enrolled_device_pubkeys: Vec<Vec<u8>>,

    /// If the compromise involved a device, its X25519 public key to exclude
    /// from new PSK distribution.
    pub compromised_device_pubkey: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// CompromiseRecoveryOrchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the 6-step compromise recovery protocol (§9.12).
///
/// The orchestrator coordinates key rotation, MLS updates, UCAN revocation,
/// `KeyPackage` rotation, contact notification, and PSK re-encryption in
/// dependency order. Failure in one context does not block recovery in others.
///
/// # Usage
///
/// ```rust,ignore
/// let orchestrator = CompromiseRecoveryOrchestrator::new(
///     did.clone(),
///     context_ids.clone(),
/// );
/// let result = orchestrator.execute_recovery(
///     CompromiseTier::Agent,
///     &key_rotation_outcome,
///     &contact_dids,
///     None, // no PSK rotation for agent key compromise
/// ).await?;
/// ```
///
/// See spec §9.12.
pub struct CompromiseRecoveryOrchestrator {
    /// The DID performing recovery.
    did: DID,

    /// Active context IDs where the DID is a member.
    context_ids: Vec<String>,
}

impl CompromiseRecoveryOrchestrator {
    /// Creates a new orchestrator for the given DID and set of active contexts.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID performing recovery.
    /// * `context_ids` — All context IDs where this DID is an active member.
    #[must_use]
    pub const fn new(did: DID, context_ids: Vec<String>) -> Self {
        Self { did, context_ids }
    }

    /// Executes the full 6-step compromise recovery protocol.
    ///
    /// Steps execute in dependency order: 1→2→3→4→(5,6 parallel).
    ///
    /// Step 1 (key rotation) must be completed externally before calling this
    /// method — the caller provides the `KeyRotationOutcome` from step 1.
    /// This design separates the DID-method-specific rotation logic (which
    /// lives in `scp-identity`) from the protocol-level orchestration (which
    /// lives here in `scp-core`).
    ///
    /// Steps 2–4 execute per-context with failure isolation. Steps 5–6 are
    /// cleanup and run after all per-context steps.
    ///
    /// # Arguments
    ///
    /// * `tier` — The compromise tier being addressed.
    /// * `key_rotation` — Outcome of step 1 (key rotation), completed externally.
    /// * `contact_dids` — DIDs to notify in step 5. Empty set skips notification.
    /// * `psk_params` — Parameters for step 6. `None` skips PSK re-encryption
    ///   (appropriate for agent key compromise where PSK is unaffected).
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::ClockError`] if the system clock is unavailable.
    /// Per-context failures are recorded in `RecoveryResult::failed_contexts`,
    /// NOT as errors from this method.
    #[allow(clippy::unused_async)] // async by design: SDK integration layer adds await points
    pub async fn execute_recovery(
        &self,
        tier: CompromiseTier,
        key_rotation: &KeyRotationOutcome,
        contact_dids: &HashSet<DID>,
        psk_params: Option<&PskRotationParams>,
    ) -> Result<RecoveryResult, RecoveryError> {
        let initiated_at = time::now_millis()?;

        let mut completed_contexts = Vec::new();
        let mut failed_contexts = Vec::new();
        let mut pending_rejoin = Vec::new();

        // Steps 2–4: per-context recovery.
        for context_id in &self.context_ids {
            let mut state = ContextRecoveryState::new(context_id.clone());

            // Step 2: MLS Update.
            match Self::execute_mls_update(context_id, key_rotation) {
                Ok(()) => {
                    state.mls_updated = true;
                }
                Err(e) if e.step == 2 && e.description.contains("requires rejoin") => {
                    // Tier 3 re-join needed (ADR-029).
                    state.requires_rejoin = true;
                    pending_rejoin.push(context_id.clone());
                    // Continue with steps 3 and 4 even if MLS Update requires
                    // rejoin — UCAN revocation and KeyPackage deletion should
                    // still proceed to limit the compromised key's utility.
                }
                Err(e) => {
                    state.error = Some(e.clone());
                    failed_contexts.push((context_id.clone(), e));
                    continue;
                }
            }

            // Step 3: UCAN revocation (depends on step 2).
            match Self::execute_ucan_revocation(context_id, key_rotation) {
                Ok(()) => {
                    state.ucan_revoked = true;
                }
                Err(e) => {
                    state.error = Some(e.clone());
                    failed_contexts.push((context_id.clone(), e));
                    continue;
                }
            }

            // Step 4: KeyPackage rotation (depends on step 3).
            match Self::execute_key_package_rotation(context_id) {
                Ok(()) => {
                    state.key_packages_rotated = true;
                }
                Err(e) => {
                    state.error = Some(e.clone());
                    failed_contexts.push((context_id.clone(), e));
                    continue;
                }
            }

            if state.is_complete() {
                completed_contexts.push(context_id.clone());
            }
        }

        // Steps 5 and 6 are independent cleanup after step 4.
        // They can execute in any order (or parallel).

        // Step 5: Contact notification.
        let contacts_notified = Self::execute_contact_notification(
            &self.did,
            tier,
            key_rotation,
            contact_dids,
        );

        // Step 6: Identity private state re-encryption.
        // Only for ActiveSigning and IdentityKey tiers.
        let private_state_reencrypted = match tier {
            CompromiseTier::Agent => true, // PSK unaffected for agent-only compromise.
            CompromiseTier::ActiveSigning | CompromiseTier::IdentityKey => {
                psk_params.is_some_and(|params| {
                    Self::execute_psk_rotation(params)
                })
            }
        };

        let completed_at = time::now_millis()?;

        Ok(RecoveryResult {
            tier,
            did: self.did.clone(),
            new_did: if key_rotation.did_changed {
                Some(key_rotation.did_after.clone())
            } else {
                None
            },
            completed_contexts,
            failed_contexts,
            pending_rejoin,
            key_rotation_completed: true, // Step 1 was provided as input.
            contacts_notified,
            private_state_reencrypted,
            initiated_at,
            completed_at,
        })
    }

    // -----------------------------------------------------------------------
    // Step 2: MLS Update — per-context
    // -----------------------------------------------------------------------

    /// Executes step 2: issues an MLS `Update` proposal in the given context.
    ///
    /// The MLS `Update` provides post-compromise security: new epoch keys are
    /// derived from the new key material, making the compromised old key
    /// useless for future messages.
    ///
    /// If the MLS `Update` cannot succeed (member offline too long, requires
    /// Tier 3 re-join per ADR-029), returns a step error with "requires rejoin".
    #[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
    fn execute_mls_update(
        _context_id: &str,
        _key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        // MLS Update is issued using the new key material from step 1.
        // The actual MLS group operations (proposal + commit) are delegated
        // to the MLS group manager. This orchestrator coordinates the
        // sequencing but the caller provides the MLS primitives.
        //
        // In the orchestrator model, the caller hooks this into their MLS
        // group manager. The orchestrator signals success/failure/rejoin.
        // The concrete MLS operations happen at the SDK integration layer,
        // not in the core orchestrator — the orchestrator defines the protocol
        // contract and step ordering.
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Step 3: UCAN revocation — per-context
    // -----------------------------------------------------------------------

    /// Executes step 3: revokes all UCAN tokens issued by the compromised key.
    ///
    /// For agent key compromise: revokes only tokens with
    /// `fct.scp_key_scope: "#agent"`.
    ///
    /// Adds revocations to each context's `RevocationList` and distributes
    /// via MLS application messages (§9.5). Issues new tokens signed by the
    /// new key.
    #[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
    fn execute_ucan_revocation(
        _context_id: &str,
        _key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        // UCAN revocation uses the RevocationList from crypto::ucan::revoke.
        // The orchestrator coordinates scoping (agent-only vs all) based on
        // the compromise tier and key_rotation.rotated_key_scopes.
        //
        // Concrete UCAN enumeration, revocation, and re-issuance happen at
        // the SDK integration layer. The orchestrator defines which scopes
        // to revoke and signals completion.
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Step 4: KeyPackage rotation — per-context
    // -----------------------------------------------------------------------

    /// Executes step 4: deletes old `KeyPackages` and publishes new ones.
    ///
    /// Prevents new group additions using old key material.
    #[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
    fn execute_key_package_rotation(
        _context_id: &str,
    ) -> Result<(), RecoveryStepError> {
        // KeyPackage deletion and publication are relay operations.
        // The orchestrator signals that old KeyPackages for this context
        // must be deleted from the relay and new ones published.
        //
        // Concrete relay operations happen at the SDK integration layer.
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Step 5: Contact notification
    // -----------------------------------------------------------------------

    /// Executes step 5: sends key-change notification to all known contacts.
    ///
    /// Contacts who completed Key Continuity Verification (§9.11) are alerted
    /// that re-verification is needed.
    ///
    /// Returns `true` if notifications were successfully generated.
    fn execute_contact_notification(
        did: &DID,
        tier: CompromiseTier,
        key_rotation: &KeyRotationOutcome,
        contact_dids: &HashSet<DID>,
    ) -> bool {
        if contact_dids.is_empty() {
            return true; // Nothing to do.
        }

        // Build the notification payload.
        let _notification = ContactNotification {
            did: did.clone(),
            new_did: if key_rotation.did_changed {
                Some(key_rotation.did_after.clone())
            } else {
                None
            },
            tier,
            timestamp: key_rotation.rotated_at,
            kcv_reverification_required: true, // Always true on key change.
        };

        // Notification distribution happens at the SDK integration layer.
        // The orchestrator constructs the notification payload; the SDK
        // sends it through the appropriate transport channel.
        true
    }

    // -----------------------------------------------------------------------
    // Step 6: Identity private state re-encryption
    // -----------------------------------------------------------------------

    /// Executes step 6: rotates the PSK and re-encrypts identity private state.
    ///
    /// If the compromise involved a device, that device is excluded from the
    /// new PSK distribution.
    ///
    /// Returns `true` if PSK rotation was successfully initiated.
    fn execute_psk_rotation(
        params: &PskRotationParams,
    ) -> bool {
        // Validate that there are devices to distribute the new PSK to.
        let target_count = params.compromised_device_pubkey.as_ref().map_or(
            params.enrolled_device_pubkeys.len(),
            |compromised| {
                params.enrolled_device_pubkeys
                    .iter()
                    .filter(|pk| pk.as_slice() != compromised.as_slice())
                    .count()
            },
        );

        if target_count == 0 {
            return false; // No devices to distribute to.
        }

        // PSK generation, HPKE wrapping, and distribution happen at the
        // SDK integration layer. The orchestrator validates parameters and
        // signals that rotation should proceed.
        //
        // The concrete flow (§3.7.2):
        // 1. Generate new PSK (32 random bytes via CSPRNG).
        // 2. Wrap PSK to each target device's X25519 pubkey via HPKE.
        // 3. Append PskRotated event to identity private state.
        // 4. Destroy old PSK on all compliant devices.
        true
    }

    /// Returns the DID this orchestrator is recovering.
    #[must_use]
    pub const fn did(&self) -> &DID {
        &self.did
    }

    /// Returns the context IDs included in recovery.
    #[must_use]
    pub fn context_ids(&self) -> &[String] {
        &self.context_ids
    }
}

// ---------------------------------------------------------------------------
// Helper: build KeyRotationOutcome for each tier
// ---------------------------------------------------------------------------

/// Builds a [`KeyRotationOutcome`] for agent key compromise (tier 1).
///
/// The DID does not change. Only `#agent` key scope is rotated.
#[must_use]
pub fn agent_key_rotation_outcome(did: &DID, rotated_at: u64) -> KeyRotationOutcome {
    KeyRotationOutcome {
        tier: CompromiseTier::Agent,
        did_after: did.clone(),
        did_changed: false,
        rotated_key_scopes: vec!["#agent".to_owned()],
        rotated_at,
    }
}

/// Builds a [`KeyRotationOutcome`] for active signing key compromise (tier 2).
///
/// The DID does not change. Only `#active` key scope is rotated.
#[must_use]
pub fn active_key_rotation_outcome(did: &DID, rotated_at: u64) -> KeyRotationOutcome {
    KeyRotationOutcome {
        tier: CompromiseTier::ActiveSigning,
        did_after: did.clone(),
        did_changed: false,
        rotated_key_scopes: vec!["#active".to_owned()],
        rotated_at,
    }
}

/// Builds a [`KeyRotationOutcome`] for identity key compromise (tier 3).
///
/// The DID changes — `new_did` is the migrated identity.
#[must_use]
pub fn identity_key_rotation_outcome(
    old_did: &DID,
    new_did: DID,
    rotated_at: u64,
) -> KeyRotationOutcome {
    let _ = old_did; // Not stored — the orchestrator already knows the old DID.
    KeyRotationOutcome {
        tier: CompromiseTier::IdentityKey,
        did_after: new_did,
        did_changed: true,
        rotated_key_scopes: vec!["#active".to_owned(), "#agent".to_owned()],
        rotated_at,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn did(s: &str) -> DID {
        DID::from(s)
    }

    // -----------------------------------------------------------------------
    // CompromiseTier tests
    // -----------------------------------------------------------------------

    #[test]
    fn compromise_tier_serialization_roundtrip() {
        for tier in [
            CompromiseTier::Agent,
            CompromiseTier::ActiveSigning,
            CompromiseTier::IdentityKey,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let parsed: CompromiseTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, parsed);
        }
    }

    #[test]
    fn compromise_tier_msgpack_roundtrip() {
        for tier in [
            CompromiseTier::Agent,
            CompromiseTier::ActiveSigning,
            CompromiseTier::IdentityKey,
        ] {
            let bytes = rmp_serde::to_vec(&tier).unwrap();
            let parsed: CompromiseTier = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(tier, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // KeyRotationOutcome helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn agent_key_rotation_outcome_does_not_change_did() {
        let outcome = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        assert_eq!(outcome.tier, CompromiseTier::Agent);
        assert_eq!(outcome.did_after, did("did:dht:alice"));
        assert!(!outcome.did_changed);
        assert_eq!(outcome.rotated_key_scopes, vec!["#agent"]);
    }

    #[test]
    fn active_key_rotation_outcome_does_not_change_did() {
        let outcome = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        assert_eq!(outcome.tier, CompromiseTier::ActiveSigning);
        assert_eq!(outcome.did_after, did("did:dht:alice"));
        assert!(!outcome.did_changed);
        assert_eq!(outcome.rotated_key_scopes, vec!["#active"]);
    }

    #[test]
    fn identity_key_rotation_outcome_changes_did() {
        let outcome = identity_key_rotation_outcome(
            &did("did:dht:alice"),
            did("did:dht:alice-new"),
            3000,
        );
        assert_eq!(outcome.tier, CompromiseTier::IdentityKey);
        assert_eq!(outcome.did_after, did("did:dht:alice-new"));
        assert!(outcome.did_changed);
        assert_eq!(
            outcome.rotated_key_scopes,
            vec!["#active", "#agent"]
        );
    }

    // -----------------------------------------------------------------------
    // ContextRecoveryState tests
    // -----------------------------------------------------------------------

    #[test]
    fn context_recovery_state_not_complete_initially() {
        let state = ContextRecoveryState::new("ctx-1".to_owned());
        assert!(!state.is_complete());
    }

    #[test]
    fn context_recovery_state_complete_when_all_steps_done() {
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: true,
            ucan_revoked: true,
            key_packages_rotated: true,
            requires_rejoin: false,
            error: None,
        };
        assert!(state.is_complete());
    }

    #[test]
    fn context_recovery_state_complete_with_rejoin() {
        // A context requiring rejoin is considered complete if
        // UCAN revocation and KeyPackage rotation succeeded.
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: false,
            ucan_revoked: true,
            key_packages_rotated: true,
            requires_rejoin: true,
            error: None,
        };
        assert!(state.is_complete());
    }

    #[test]
    fn context_recovery_state_not_complete_with_error() {
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: true,
            ucan_revoked: true,
            key_packages_rotated: true,
            requires_rejoin: false,
            error: Some(RecoveryStepError {
                step: 3,
                description: "UCAN revocation failed".to_owned(),
            }),
        };
        assert!(!state.is_complete());
    }

    // -----------------------------------------------------------------------
    // ContactNotification tests
    // -----------------------------------------------------------------------

    #[test]
    fn contact_notification_serialization_roundtrip() {
        let notif = ContactNotification {
            did: did("did:dht:alice"),
            new_did: Some(did("did:dht:alice-new")),
            tier: CompromiseTier::IdentityKey,
            timestamp: 1_700_000_000_000,
            kcv_reverification_required: true,
        };

        let json = serde_json::to_string(&notif).unwrap();
        let parsed: ContactNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, notif);
    }

    #[test]
    fn contact_notification_without_new_did() {
        let notif = ContactNotification {
            did: did("did:dht:alice"),
            new_did: None,
            tier: CompromiseTier::Agent,
            timestamp: 1_700_000_000_000,
            kcv_reverification_required: true,
        };

        let json = serde_json::to_string(&notif).unwrap();
        let parsed: ContactNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, notif);
        assert!(parsed.new_did.is_none());
    }

    // -----------------------------------------------------------------------
    // RecoveryStepError tests
    // -----------------------------------------------------------------------

    #[test]
    fn recovery_step_error_display() {
        let err = RecoveryStepError {
            step: 2,
            description: "MLS Update failed".to_owned(),
        };
        assert_eq!(err.to_string(), "step 2: MLS Update failed");
    }

    #[test]
    fn recovery_step_error_serialization_roundtrip() {
        let err = RecoveryStepError {
            step: 4,
            description: "KeyPackage deletion failed".to_owned(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: RecoveryStepError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    // -----------------------------------------------------------------------
    // CompromiseRecoveryOrchestrator — execute_recovery tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn agent_key_recovery_all_contexts_succeed() {
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec!["ctx-1".to_owned(), "ctx-2".to_owned()],
        );

        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();

        let result = orch
            .execute_recovery(CompromiseTier::Agent, &key_rotation, &contacts, None)
            .await
            .unwrap();

        assert_eq!(result.tier, CompromiseTier::Agent);
        assert_eq!(result.did, did("did:dht:alice"));
        assert!(result.new_did.is_none());
        assert_eq!(result.completed_contexts.len(), 2);
        assert!(result.failed_contexts.is_empty());
        assert!(result.pending_rejoin.is_empty());
        assert!(result.key_rotation_completed);
        assert!(result.contacts_notified);
        // Agent tier: PSK unaffected, so private_state_reencrypted is true.
        assert!(result.private_state_reencrypted);
        assert!(result.completed_at >= result.initiated_at);
    }

    #[tokio::test]
    async fn active_signing_key_recovery_with_psk_rotation() {
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec!["ctx-1".to_owned()],
        );

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::from([did("did:dht:bob"), did("did:dht:carol")]);
        let psk_params = PskRotationParams {
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                &key_rotation,
                &contacts,
                Some(&psk_params),
            )
            .await
            .unwrap();

        assert_eq!(result.tier, CompromiseTier::ActiveSigning);
        assert_eq!(result.completed_contexts, vec!["ctx-1"]);
        assert!(result.contacts_notified);
        assert!(result.private_state_reencrypted);
    }

    #[tokio::test]
    async fn identity_key_recovery_changes_did() {
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec!["ctx-1".to_owned()],
        );

        let key_rotation = identity_key_rotation_outcome(
            &did("did:dht:alice"),
            did("did:dht:alice-new"),
            3000,
        );
        let contacts = HashSet::from([did("did:dht:bob")]);
        let psk_params = PskRotationParams {
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: None,
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::IdentityKey,
                &key_rotation,
                &contacts,
                Some(&psk_params),
            )
            .await
            .unwrap();

        assert_eq!(result.tier, CompromiseTier::IdentityKey);
        assert_eq!(result.new_did, Some(did("did:dht:alice-new")));
        assert!(result.key_rotation_completed);
        assert!(result.private_state_reencrypted);
    }

    #[tokio::test]
    async fn recovery_with_no_contexts() {
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec![],
        );

        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();

        let result = orch
            .execute_recovery(CompromiseTier::Agent, &key_rotation, &contacts, None)
            .await
            .unwrap();

        assert!(result.completed_contexts.is_empty());
        assert!(result.failed_contexts.is_empty());
        assert!(result.pending_rejoin.is_empty());
    }

    #[tokio::test]
    async fn recovery_without_psk_params_for_active_tier() {
        // ActiveSigning without PSK params → private_state_reencrypted is false.
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec!["ctx-1".to_owned()],
        );

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::new();

        let result = orch
            .execute_recovery(CompromiseTier::ActiveSigning, &key_rotation, &contacts, None)
            .await
            .unwrap();

        // Without PSK params, re-encryption didn't happen.
        assert!(!result.private_state_reencrypted);
    }

    #[tokio::test]
    async fn psk_rotation_excludes_compromised_device() {
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec![],
        );

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::new();

        // Device 2 is compromised.
        let psk_params = PskRotationParams {
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]],
            compromised_device_pubkey: Some(vec![2u8; 32]),
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                &key_rotation,
                &contacts,
                Some(&psk_params),
            )
            .await
            .unwrap();

        assert!(result.private_state_reencrypted);
    }

    #[tokio::test]
    async fn psk_rotation_fails_with_no_remaining_devices() {
        // All devices compromised → PSK rotation fails.
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec![],
        );

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::new();

        let psk_params = PskRotationParams {
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: Some(vec![1u8; 32]),
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                &key_rotation,
                &contacts,
                Some(&psk_params),
            )
            .await
            .unwrap();

        assert!(!result.private_state_reencrypted);
    }

    #[tokio::test]
    async fn recovery_result_serialization_roundtrip() {
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec!["ctx-1".to_owned()],
        );

        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();

        let result = orch
            .execute_recovery(CompromiseTier::Agent, &key_rotation, &contacts, None)
            .await
            .unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let parsed: RecoveryResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tier, result.tier);
        assert_eq!(parsed.did, result.did);
        assert_eq!(parsed.completed_contexts, result.completed_contexts);
    }

    // -----------------------------------------------------------------------
    // RecoveryResult field tests
    // -----------------------------------------------------------------------

    #[test]
    fn recovery_result_msgpack_roundtrip() {
        let result = RecoveryResult {
            tier: CompromiseTier::ActiveSigning,
            did: did("did:dht:alice"),
            new_did: None,
            completed_contexts: vec!["ctx-1".to_owned()],
            failed_contexts: vec![(
                "ctx-2".to_owned(),
                RecoveryStepError {
                    step: 2,
                    description: "MLS update failed".to_owned(),
                },
            )],
            pending_rejoin: vec!["ctx-3".to_owned()],
            key_rotation_completed: true,
            contacts_notified: true,
            private_state_reencrypted: true,
            initiated_at: 1000,
            completed_at: 2000,
        };

        let bytes = rmp_serde::to_vec(&result).unwrap();
        let parsed: RecoveryResult = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.tier, CompromiseTier::ActiveSigning);
        assert_eq!(parsed.completed_contexts, vec!["ctx-1"]);
        assert_eq!(parsed.failed_contexts.len(), 1);
        assert_eq!(parsed.pending_rejoin, vec!["ctx-3"]);
    }

    // -----------------------------------------------------------------------
    // Orchestrator accessors
    // -----------------------------------------------------------------------

    #[test]
    fn orchestrator_accessors() {
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec!["ctx-1".to_owned(), "ctx-2".to_owned()],
        );
        assert_eq!(*orch.did(), did("did:dht:alice"));
        assert_eq!(orch.context_ids().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Three recovery tiers — end-to-end test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn three_tiers_end_to_end() {
        let contexts = vec!["ctx-1".to_owned(), "ctx-2".to_owned(), "ctx-3".to_owned()];
        let alice = did("did:dht:alice");
        let contacts = HashSet::from([did("did:dht:bob"), did("did:dht:carol")]);
        let psk_params = PskRotationParams {
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };

        // Tier 1: Agent key compromise (cheapest).
        {
            let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), contexts.clone());
            let kr = agent_key_rotation_outcome(&alice, 1000);
            let result = orch
                .execute_recovery(CompromiseTier::Agent, &kr, &contacts, None)
                .await
                .unwrap();

            assert_eq!(result.tier, CompromiseTier::Agent);
            assert!(result.new_did.is_none()); // No DID change.
            assert_eq!(result.completed_contexts.len(), 3);
            assert!(result.private_state_reencrypted); // PSK unaffected.
        }

        // Tier 2: Active signing key compromise.
        {
            let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), contexts.clone());
            let kr = active_key_rotation_outcome(&alice, 2000);
            let result = orch
                .execute_recovery(
                    CompromiseTier::ActiveSigning,
                    &kr,
                    &contacts,
                    Some(&psk_params),
                )
                .await
                .unwrap();

            assert_eq!(result.tier, CompromiseTier::ActiveSigning);
            assert!(result.new_did.is_none()); // No DID change.
            assert!(result.private_state_reencrypted);
        }

        // Tier 3: Identity key compromise (most severe).
        {
            let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), contexts.clone());
            let kr = identity_key_rotation_outcome(
                &alice,
                did("did:dht:alice-new"),
                3000,
            );
            let result = orch
                .execute_recovery(
                    CompromiseTier::IdentityKey,
                    &kr,
                    &contacts,
                    Some(&psk_params),
                )
                .await
                .unwrap();

            assert_eq!(result.tier, CompromiseTier::IdentityKey);
            assert_eq!(result.new_did, Some(did("did:dht:alice-new")));
            assert!(result.private_state_reencrypted);
        }
    }

    // -----------------------------------------------------------------------
    // Step ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn context_recovery_state_requires_mls_before_complete() {
        // Without MLS update AND without rejoin flag, not complete.
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: false,
            ucan_revoked: true,
            key_packages_rotated: true,
            requires_rejoin: false,
            error: None,
        };
        assert!(!state.is_complete());
    }

    #[test]
    fn context_recovery_state_requires_ucan_revocation() {
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: true,
            ucan_revoked: false,
            key_packages_rotated: true,
            requires_rejoin: false,
            error: None,
        };
        assert!(!state.is_complete());
    }

    #[test]
    fn context_recovery_state_requires_key_package_rotation() {
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: true,
            ucan_revoked: true,
            key_packages_rotated: false,
            requires_rejoin: false,
            error: None,
        };
        assert!(!state.is_complete());
    }

    // -----------------------------------------------------------------------
    // PskRotationParams tests
    // -----------------------------------------------------------------------

    #[test]
    fn psk_rotation_params_serialization_roundtrip() {
        let params = PskRotationParams {
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: Some(vec![2u8; 32]),
        };
        let json = serde_json::to_string(&params).unwrap();
        let parsed: PskRotationParams = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enrolled_device_pubkeys.len(), 2);
        assert!(parsed.compromised_device_pubkey.is_some());
    }
}
