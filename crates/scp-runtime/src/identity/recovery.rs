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
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use scp_did::DID;

// ContextManager type deleted in ADR-049 commit 12; recovery binds to
// the supervisor directly.
use scp_clock::Clock;

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
    /// The identity DID. Bound into the HPKE `info` for each wrapped PSK
    /// (`"scp-private-state-v1" || len(did) || did || "psk-rotate"`, §3.7.2),
    /// preventing a wrap intended for one identity from opening under another.
    pub did: String,

    /// X25519 public keys of all enrolled devices.
    pub enrolled_device_pubkeys: Vec<Vec<u8>>,

    /// If the compromise involved a device, its X25519 public key to exclude
    /// from new PSK distribution.
    pub compromised_device_pubkey: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// RecoveryBackend — trait for platform-specific recovery operations
// ---------------------------------------------------------------------------

/// Backend trait for platform-specific recovery operations.
///
/// The orchestrator defines step ordering and failure isolation; the backend
/// provides the concrete MLS, UCAN, `KeyPackage`, notification, and PSK
/// operations. Each method corresponds to one recovery step (2–6).
///
/// SDK integration layers implement this trait to wire the orchestrator into
/// the actual MLS group manager, UCAN store, relay transport, etc.
///
/// See spec §9.12.
///
/// The trait is `async` (via [`macro@async_trait`], ADR-049 Decision 7) so the
/// production backend can `.await` the supervisor mailbox directly rather than
/// bridging through `block_in_place` + `Handle::block_on`. It is consumed as
/// `&dyn RecoveryBackend`, so `#[async_trait(?Send)]` is used — the trait
/// object is deliberately not `Sync` (the orchestrator holds it across await
/// points on a single task; see [`CompromiseRecoveryOrchestrator::execute_recovery`]).
#[async_trait(?Send)]
pub trait RecoveryBackend {
    /// Step 2: Issue an MLS `Update` proposal in the given context.
    ///
    /// The MLS `Update` provides post-compromise security: new epoch keys are
    /// derived from the new key material, making the compromised old key
    /// useless for future messages.
    ///
    /// If the member has been offline too long (Tier 3 per ADR-029), return
    /// a `RecoveryStepError` with `description` containing "requires rejoin".
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryStepError`] if the MLS update proposal cannot be
    /// issued (e.g., the member requires rejoin or the MLS group is
    /// unavailable).
    async fn mls_update(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError>;

    /// Step 3: Revoke all UCAN tokens issued by the compromised key.
    ///
    /// For agent key compromise: revoke only tokens with
    /// `fct.scp_key_scope: "#agent"`. The `key_rotation.rotated_key_scopes`
    /// field indicates which scopes to revoke.
    ///
    /// Adds revocations to the context's `RevocationList` and distributes
    /// via MLS application messages (§9.5). Issues new tokens signed by the
    /// new key.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryStepError`] if UCAN revocation or re-issuance fails.
    async fn revoke_ucans(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError>;

    /// Step 4: Delete old `KeyPackages` and publish new ones.
    ///
    /// Prevents new group additions using old key material. The
    /// `key_rotation` outcome is used to identify the recovering member's
    /// DID for the notification payload.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryStepError`] if old key packages cannot be deleted
    /// or new ones cannot be published.
    async fn rotate_key_packages(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError>;

    /// Step 5: Send key-change notification to contacts.
    ///
    /// Contacts who completed Key Continuity Verification (§9.11) are alerted
    /// that re-verification is needed. Returns `true` if notifications were
    /// successfully sent.
    async fn notify_contacts(
        &self,
        did: &DID,
        tier: CompromiseTier,
        key_rotation: &KeyRotationOutcome,
        contacts: &HashSet<DID>,
    ) -> bool;

    /// Step 6: Rotate the PSK and re-encrypt identity private state.
    ///
    /// If the compromise involved a device, that device is excluded from the
    /// new PSK distribution. Returns `true` if PSK rotation succeeded.
    async fn rotate_psk(&self, params: &PskRotationParams) -> bool;
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
/// Step operations are delegated to a [`RecoveryBackend`] implementation,
/// which provides the platform-specific MLS, UCAN, relay, and notification
/// primitives.
///
/// # Usage
///
/// ```rust,ignore
/// let backend = MyRecoveryBackend::new(/* ... */);
/// let orchestrator = CompromiseRecoveryOrchestrator::new(
///     did.clone(),
///     context_ids.clone(),
/// );
/// let result = orchestrator.execute_recovery(
///     CompromiseTier::Agent,
///     &key_rotation_outcome,
///     &contact_dids,
///     None, // no PSK rotation for agent key compromise
///     &backend,
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
    /// Steps 2–4 execute per-context with failure isolation via the
    /// [`RecoveryBackend`]. Steps 5–6 are cleanup and run after all
    /// per-context steps.
    ///
    /// # Arguments
    ///
    /// * `tier` — The compromise tier being addressed.
    /// * `key_rotation` — Outcome of step 1 (key rotation), completed externally.
    /// * `contact_dids` — DIDs to notify in step 5. Empty set skips notification.
    /// * `psk_params` — Parameters for step 6. `None` skips PSK re-encryption
    ///   (appropriate for agent key compromise where PSK is unaffected).
    /// * `backend` — Platform-specific implementation of recovery operations.
    ///
    /// # Errors
    ///
    /// Per-context failures are recorded in `RecoveryResult::failed_contexts`,
    /// NOT as errors from this method.
    #[allow(clippy::future_not_send)] // backend trait object is not Sync by design
    pub async fn execute_recovery(
        &self,
        tier: CompromiseTier,
        key_rotation: &KeyRotationOutcome,
        contact_dids: &HashSet<DID>,
        psk_params: Option<&PskRotationParams>,
        backend: &dyn RecoveryBackend,
        clock: &dyn Clock,
    ) -> Result<RecoveryResult, RecoveryError> {
        let initiated_at = clock.now_millis();

        let mut completed_contexts = Vec::new();
        let mut failed_contexts = Vec::new();
        let mut pending_rejoin = Vec::new();

        // Steps 2–4: per-context recovery.
        for context_id in &self.context_ids {
            let mut state = ContextRecoveryState::new(context_id.clone());

            // Step 2: MLS Update.
            match backend.mls_update(context_id, key_rotation).await {
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
            match backend.revoke_ucans(context_id, key_rotation).await {
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
            match backend.rotate_key_packages(context_id, key_rotation).await {
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
        let contacts_notified = if contact_dids.is_empty() {
            true // Nothing to do.
        } else {
            backend
                .notify_contacts(&self.did, tier, key_rotation, contact_dids)
                .await
        };

        // Step 6: Identity private state re-encryption.
        // Only for ActiveSigning and IdentityKey tiers.
        let private_state_reencrypted = match tier {
            CompromiseTier::Agent => true, // PSK unaffected for agent-only compromise.
            CompromiseTier::ActiveSigning | CompromiseTier::IdentityKey => match psk_params {
                Some(params) => backend.rotate_psk(params).await,
                None => false,
            },
        };

        let completed_at = clock.now_millis();

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
// PSK wrapping helper (RFC 9180 HPKE, §3.7.2)
// ---------------------------------------------------------------------------

/// HPKE `info` domain separator for PSK distribution (§3.7.2).
const PSK_HPKE_INFO_PREFIX: &[u8] = b"scp-private-state-v1";

/// Purpose string for PSK rotation re-wraps (§3.7.2, spec edit S5).
const PSK_PURPOSE_ROTATE: &[u8] = b"psk-rotate";

/// Wire length of a wrapped PSK: HPKE `enc` (32) || `ct` (48) = 80 bytes.
const WRAPPED_PSK_LEN: usize = 32 + 48;

/// Builds the §3.7.2 PSK HPKE `info`:
/// `"scp-private-state-v1" || BE32(len(did)) || did || purpose`.
///
/// `did` carries a 4-byte big-endian length prefix (§9.5.1); `purpose` is a
/// fixed-version UTF-8 string with no length prefix. The `aad` is empty — the
/// `info` binds the DID and a fresh HPKE context is used per device, so there
/// is no cross-recipient substitution surface.
fn build_psk_hpke_info(did: &str, purpose: &[u8]) -> Vec<u8> {
    let did_bytes = did.as_bytes();
    let mut info =
        Vec::with_capacity(PSK_HPKE_INFO_PREFIX.len() + 4 + did_bytes.len() + purpose.len());
    info.extend_from_slice(PSK_HPKE_INFO_PREFIX);
    #[allow(clippy::cast_possible_truncation)] // DID length << u32::MAX
    let did_len = did_bytes.len() as u32;
    info.extend_from_slice(&did_len.to_be_bytes());
    info.extend_from_slice(did_bytes);
    info.extend_from_slice(purpose);
    info
}

/// Wraps a 32-byte PSK for a single device via RFC 9180 HPKE Base mode
/// (§3.7.2). AES-128-GCM (the X25519 KEM is the ~128-bit floor; §9.5).
///
/// Returns `Some(wrapped)` where `wrapped` is `enc(32) || ct(48)` = 80 bytes,
/// or `None` if HPKE sealing fails. The `info` binds the identity `did` and
/// the `purpose` string (`"psk-rotate"` for rotation re-wraps); `aad` is empty.
fn wrap_psk_for_device(psk: &[u8; 32], device_pk: &[u8; 32], did: &str) -> Option<Vec<u8>> {
    let info = build_psk_hpke_info(did, PSK_PURPOSE_ROTATE);
    let (enc, ct) = scp_protocol::crypto::hpke::seal(device_pk, &info, &[], psk).ok()?;

    let mut wrapped = Vec::with_capacity(WRAPPED_PSK_LEN);
    wrapped.extend_from_slice(&enc);
    wrapped.extend_from_slice(&ct);
    Some(wrapped)
}

// ---------------------------------------------------------------------------
// ProductionRecoveryBackend — real implementation of RecoveryBackend
// ---------------------------------------------------------------------------

/// Production implementation of [`RecoveryBackend`] that dispatches MLS,
/// UCAN, `KeyPackage`, notification, and PSK operations through the
/// supervisor's trust-recovery actor mailbox.
///
/// [`RecoveryBackend`] is an `async` trait (ADR-049 Decision 7), so this
/// struct's methods `.await` the supervisor mailbox directly — there is no
/// `block_in_place` + `Handle::block_on` bridge (the former `block_on_async`
/// helper was deleted when the trait became async).
///
/// # ADR-049 Phase 2B — mailbox dispatch
///
/// Each per-context step builds a
/// [`TrustRecoveryCommand`](crate::context::actor::commands::TrustRecoveryCommand)
/// and routes it through
/// [`Supervisor::dispatch_trust_recovery_command`](crate::context::supervisor::Supervisor::dispatch_trust_recovery_command).
/// When the target context has a registered actor the command runs in
/// that actor's mailbox turn against owned `&mut PerContextState`; the
/// backend never reaches the supervisor's per-context state map directly.
/// This replaced the earlier direct supervisor-scoped calls that read
/// the `contexts` `DashMap` outside the actor mailbox.
///
/// # Construction
///
/// ```rust,ignore
/// let backend = ProductionRecoveryBackend::new(
///     supervisor.clone(),
///     post_rotation_signing_key,
/// );
/// ```
///
/// # Step mapping
///
/// | Trait method         | Mailbox command                                          |
/// |----------------------|----------------------------------------------------------|
/// | `mls_update`         | `RecoveryAdvanceEpoch` + `RecoverySendNotification` (seq 0) |
/// | `revoke_ucans`       | `RecoverySendNotification` (seq 1)                       |
/// | `rotate_key_packages`| `RecoverySendNotification` (seq 2)                       |
/// | `notify_contacts`    | `RecoveryNotifyContact` (cross-context fan-out)          |
/// | `rotate_psk`         | `RecoverySendNotification` (seq 3)                       |
///
/// See spec §9.12 and the [`CompromiseRecoveryOrchestrator`] for step
/// ordering and failure isolation semantics.
pub struct ProductionRecoveryBackend {
    /// The supervisor that owns crypto, transport, and event log providers.
    manager: Arc<crate::context::supervisor::Supervisor>,
    /// The signing key for the recovering identity (post-rotation).
    ///
    /// Recovery notifications must be signed by the real key so receivers can
    /// verify them against the sender's public key. An ephemeral key would
    /// produce signatures that don't match.
    signing_key: ed25519_dalek::SigningKey,
}

impl ProductionRecoveryBackend {
    /// Creates a new production recovery backend.
    ///
    /// # Arguments
    ///
    /// * `manager` — The context manager for the local node. Must be shared
    ///   via `Arc` because the orchestrator may run concurrently with other
    ///   context operations.
    /// * `signing_key` — The post-rotation signing key for the recovering
    ///   identity. Recovery notifications are signed with this key so
    ///   receivers can verify them against the sender's public key.
    #[must_use]
    pub const fn new(
        manager: Arc<crate::context::supervisor::Supervisor>,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Self {
        Self {
            manager,
            signing_key,
        }
    }

    /// Maps a dispatch-level [`ContextError`](scp_protocol::context::ContextError)
    /// into a [`RecoveryStepError`].
    ///
    /// The `RecoveryBackend` trait is `async` (ADR-049 Decision 7), so backends
    /// `.await` the supervisor mailbox directly — there is no longer a
    /// `block_in_place` + `Handle::block_on` bridge. This helper only performs
    /// the error-shape conversion the former bridge also did: `step` is set to
    /// `0` and each caller overrides it with the concrete recovery-step number.
    // Takes the error by value so it can be used directly as a `.map_err(...)`
    // fn-pointer (which hands the closure the owned error).
    #[allow(clippy::needless_pass_by_value)]
    fn dispatch_step_error(e: scp_protocol::context::ContextError) -> RecoveryStepError {
        RecoveryStepError {
            step: 0, // Caller overrides this.
            description: e.to_string(),
        }
    }

    /// Dispatches a [`TrustRecoveryCommand`] through the supervisor's
    /// trust-recovery mailbox (ADR-049 Phase 2B) and awaits the typed
    /// reply that the command carries on its embedded oneshot.
    ///
    /// `build_cmd` receives the freshly-created reply sender and returns
    /// the fully-constructed command. Routing decision lives entirely in
    /// [`Supervisor::dispatch_trust_recovery_command`]: when a context
    /// actor is registered the command runs against that actor's owned
    /// `&mut PerContextState` (no per-context map lookup); otherwise it
    /// falls through to the supervisor-scoped direct path. Either way the typed
    /// result returns on `reply`.
    ///
    /// This replaces the previous direct supervisor-scoped calls that
    /// read the supervisor's per-context state map outside the actor
    /// mailbox.
    ///
    /// The dispatch error (the `Outcome` channel) and the command's own
    /// typed reply are folded into a single `Result`: a closed reply
    /// channel surfaces as a [`ContextError::TransportFailed`] so the
    /// caller's [`Self::dispatch_step_error`] maps it to a [`RecoveryStepError`].
    async fn dispatch_trust_recovery<F, T>(
        &self,
        build_cmd: F,
    ) -> Result<T, scp_protocol::context::ContextError>
    where
        F: FnOnce(
            tokio::sync::oneshot::Sender<Result<T, scp_protocol::context::ContextError>>,
        ) -> crate::context::actor::commands::TrustRecoveryCommand,
    {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = build_cmd(reply_tx);
        // The dispatch-level `Outcome` only reports the mailbox/timeout
        // envelope; the operation's typed result rides the command's own
        // oneshot. Propagate a dispatch-level error first (e.g. no
        // supervisor attached) before awaiting the reply.
        self.manager.dispatch_trust_recovery_command(cmd).await?;
        reply_rx.await.map_err(|_| {
            scp_protocol::context::ContextError::TransportFailed(
                "trust-recovery reply channel closed before a result was sent".to_owned(),
            )
        })?
    }

    /// Dispatches a `RecoverySendNotification` for a named context
    /// through the trust-recovery mailbox and awaits its reply.
    ///
    /// Wraps the shared payload construction (context, sender DID,
    /// sequence, signing key) used by every recovery step that sends a
    /// notification to an already-known context (spec §9.12 steps 2–4,
    /// 6). The signing key is copied into the boxed payload via
    /// [`SigningKeyBytes::from_signing_key`] so it zeroizes on drop while
    /// the command is in flight.
    async fn dispatch_recovery_send_notification(
        &self,
        context_id: &str,
        sender_did: &str,
        payload: &[u8],
        sequence: u64,
    ) -> Result<(), scp_protocol::context::ContextError> {
        use crate::context::actor::commands::{
            RecoverySendNotificationPayload, SigningKeyBytes, TrustRecoveryCommand,
        };

        let send_payload = Box::new(RecoverySendNotificationPayload {
            context_id: context_id.to_owned(),
            sender_did: sender_did.to_owned(),
            payload: payload.to_vec(),
            sequence,
            signing_key: SigningKeyBytes::from_signing_key(&self.signing_key),
        });
        self.dispatch_trust_recovery(|reply| TrustRecoveryCommand::RecoverySendNotification {
            payload: send_payload,
            reply,
        })
        .await
    }
}

#[async_trait(?Send)]
impl RecoveryBackend for ProductionRecoveryBackend {
    async fn mls_update(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        // Step 2: Advance the MLS epoch for post-compromise security.
        // The ContextManager increments the epoch counter, places the old
        // epoch into the grace window, and emits an event log entry.
        use crate::context::actor::commands::TrustRecoveryCommand;
        let result = self
            .dispatch_trust_recovery(|reply| TrustRecoveryCommand::RecoveryAdvanceEpoch {
                context_id: context_id.to_owned(),
                reply,
            })
            .await
            .map_err(Self::dispatch_step_error);
        match result {
            Ok(_epoch) => {
                // Send a scoped epoch-advance notification including the
                // rotated key scopes so recipients know which keys were
                // compromised and can adjust their local trust state.
                let scoped_payload = serde_json::json!({
                    "event": "recovery:epoch_advanced",
                    "rotated_key_scopes": key_rotation.rotated_key_scopes,
                    "did_after": key_rotation.did_after.as_ref(),
                    "did_changed": key_rotation.did_changed,
                });
                match serde_json::to_vec(&scoped_payload) {
                    Ok(payload_bytes) => {
                        let notify_result = self
                            .dispatch_recovery_send_notification(
                                context_id,
                                key_rotation.did_after.as_ref(),
                                &payload_bytes,
                                0, // sequence 0: MLS epoch-advance notification
                            )
                            .await
                            .map_err(Self::dispatch_step_error);
                        // Notification failure is non-fatal — the epoch was
                        // already advanced, which is the critical security step.
                        if let Err(e) = notify_result {
                            tracing::warn!(
                                context_id = %context_id,
                                error = %e,
                                "failed to send scoped epoch-advance notification"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            context_id = %context_id,
                            error = %e,
                            "failed to serialize epoch-advance notification payload, skipping notification"
                        );
                    }
                }
                Ok(())
            }
            Err(mut e) => {
                e.step = 2;
                // Detect Tier 3 re-join requirement (ADR-029).
                if e.description.contains("requires rejoin") {
                    return Err(RecoveryStepError {
                        step: 2,
                        description: "member requires rejoin (Tier 3, ADR-029)".to_owned(),
                    });
                }
                Err(e)
            }
        }
    }

    async fn revoke_ucans(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        // Step 3: Revoke all UCAN tokens issued by the compromised key.
        //
        // Build a per-context RevocationList and mark all tokens from the
        // compromised key scopes as Revoked. Then distribute the revocation
        // via a recovery notification so other members update their local
        // revocation lists.
        use scp_protocol::crypto::ucan::revoke::RevocationList;

        let scopes = key_rotation.rotated_key_scopes.join(",");

        // Create a revocation list for this context and add a blanket
        // revocation entry keyed by the compromised scopes and timestamp.
        // This acts as a revocation marker: all tokens issued by the
        // compromised key scopes before the rotation timestamp are invalid.
        let mut revocation_list = RevocationList::new(context_id.to_owned());
        let revocation_cid = format!(
            "recovery:{}:scopes={}:before={}",
            context_id, scopes, key_rotation.rotated_at,
        );
        revocation_list.revoke(revocation_cid);

        // Serialize the revocation list for distribution.
        let revocation_payload =
            serde_json::to_vec(&revocation_list).map_err(|e| RecoveryStepError {
                step: 3,
                description: format!("failed to serialize revocation list: {e}"),
            })?;

        // Distribute the revocation via the context manager's recovery
        // notification channel so all members receive and merge it.
        let result = self
            .dispatch_recovery_send_notification(
                context_id,
                key_rotation.did_after.as_ref(),
                &revocation_payload,
                1, // sequence 1: UCAN revocation notification
            )
            .await
            .map_err(Self::dispatch_step_error);
        match result {
            Ok(()) => Ok(()),
            Err(mut e) => {
                e.step = 3;
                Err(e)
            }
        }
    }

    async fn rotate_key_packages(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        // Step 4: Delete old KeyPackages and publish new ones.
        //
        // Old key packages are implicitly invalidated by the MLS epoch
        // advancement in step 2. This step signals to other members that
        // they should discard cached key packages for this member and
        // records the rotation in the event log.
        //
        // NOTE: This implementation is notification-only — it does not
        // interact with the relay to delete/publish actual KeyPackage
        // objects because the RecoveryBackend trait does not expose relay
        // transport APIs. The notification informs other members to purge
        // their cached key packages for the recovering member. Actual
        // KeyPackage lifecycle management happens at the SDK integration
        // layer. See issue #1083 finding 6.
        //
        // We build a key-package-rotation notification and send it via
        // the context manager. The payload tells recipients to purge
        // cached key packages for the recovering member.
        let payload = format!("recovery:key_package_rotation:context={context_id}");

        // Use the recovering member's DID from the key rotation outcome
        // as the sender — this is the authoritative identity performing
        // recovery, not an arbitrary first member from the context.
        let sender_did = key_rotation.did_after.as_ref();

        // Send the key-package-rotation notification via the recovery
        // notification channel. This records the event and alerts members.
        let result = self
            .dispatch_recovery_send_notification(
                context_id,
                sender_did,
                payload.as_bytes(),
                2, // sequence 2: key-package rotation notification
            )
            .await
            .map_err(Self::dispatch_step_error);
        match result {
            Ok(()) => Ok(()),
            Err(mut e) => {
                e.step = 4;
                Err(e)
            }
        }
    }

    async fn notify_contacts(
        &self,
        did: &DID,
        tier: CompromiseTier,
        key_rotation: &KeyRotationOutcome,
        contacts: &HashSet<DID>,
    ) -> bool {
        // Step 5: Send key-change notification to contacts.
        //
        // Build a ContactNotification and serialize it, then attempt to
        // send it to each contact's known context. If we can reach at least
        // one context per contact, notification succeeds.
        //
        // For contacts we share contexts with, the notification is sent as
        // a recovery message via the existing context transport.
        let notification = ContactNotification {
            did: did.clone(),
            new_did: if key_rotation.did_changed {
                Some(key_rotation.did_after.clone())
            } else {
                None
            },
            tier,
            timestamp: key_rotation.rotated_at,
            kcv_reverification_required: true,
        };

        // Serialize the notification. If serialization fails, notification
        // cannot proceed.
        let payload = match serde_json::to_vec(&notification) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize contact notification — skipping");
                return false;
            }
        };

        // Attempt to notify each contact via shared contexts. The manager
        // exposes `is_member` and `recovery_send_notification` which we use
        // to find contexts where both the recovering DID and the contact are
        // members, then send the notification payload through those contexts.
        //
        // Even partial delivery counts as success since contacts will
        // re-verify on next interaction (§9.11).
        let mut any_sent = false;

        // Retrieve all context IDs known to the orchestrator by looking up
        // contexts where the recovering DID is a member. The orchestrator
        // was constructed with these context IDs, but the backend doesn't
        // have direct access — we check membership per contact per context.
        for contact in contacts {
            let contact_did_str = contact.as_ref();
            let did_str = did.as_ref();

            // Try sending to a shared context where both the recovering DID
            // and the contact DID are members. The supervisor's
            // `RecoveryNotifyContact` mailbox command searches registered
            // contexts to find a suitable channel, then dispatches a
            // `RecoverySendNotification` through it.
            let send_result = self
                .dispatch_trust_recovery(|reply| {
                    use crate::context::actor::commands::{
                        RecoveryNotifyContactPayload, SigningKeyBytes, TrustRecoveryCommand,
                    };
                    TrustRecoveryCommand::RecoveryNotifyContact {
                        payload: Box::new(RecoveryNotifyContactPayload {
                            recovering_did: did_str.to_owned(),
                            contact_did: contact_did_str.to_owned(),
                            payload: payload.clone(),
                            signing_key: SigningKeyBytes::from_signing_key(&self.signing_key),
                        }),
                        reply,
                    }
                })
                .await
                .map_err(Self::dispatch_step_error);

            if send_result.is_ok() {
                any_sent = true;
            }
            // Best-effort: failure for one contact doesn't block others.
        }

        // Contact notification is best-effort per spec §9.12 — the protocol
        // does not require delivery confirmation. Return true if at least one
        // notification was sent, or if there were no contacts to notify.
        any_sent || contacts.is_empty()
    }

    async fn rotate_psk(&self, params: &PskRotationParams) -> bool {
        // Step 6: Rotate the PSK and re-encrypt identity private state.
        //
        // Generate a fresh 32-byte PSK, then wrap it for each enrolled
        // device's X25519 public key (excluding the compromised device if
        // specified) using X25519 ECDH + HKDF + AES-256-GCM (HPKE mode
        // Base, matching the sender key wrapping pattern in §9.16.2).
        // The wrapped PSKs are distributed as a recovery notification.

        use rand::RngCore as _;
        use zeroize::Zeroizing;

        // Filter out the compromised device, if any.
        let eligible_devices: Vec<&[u8]> = params
            .enrolled_device_pubkeys
            .iter()
            .filter(|pk| {
                params
                    .compromised_device_pubkey
                    .as_ref()
                    .is_none_or(|cpk| pk.as_slice() != cpk.as_slice())
            })
            .map(Vec::as_slice)
            .collect();

        // Must have at least one eligible device to distribute the new PSK.
        if eligible_devices.is_empty() {
            return false;
        }

        // Generate a fresh PSK (32 bytes of random data). Held in `Zeroizing`
        // so the plaintext PSK is wiped on drop regardless of which return
        // path is taken (including the early `device_pk.len() != 32` reject
        // below), preserving forward secrecy of the rotated key.
        let mut new_psk = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(new_psk.as_mut());

        // For each eligible device, wrap the new PSK via RFC 9180 HPKE Base
        // mode (§3.7.2): DHKEM(X25519, HKDF-SHA256) Encap to the device key,
        // AES-128-GCM seal under info "scp-private-state-v1" || len(did) ||
        // did || "psk-rotate". Output is enc(32) || ct(48) = 80 bytes; the
        // AEAD nonce is internal per RFC 9180. Only the holder of the device's
        // X25519 private key can complete Decap and unwrap the PSK.
        let mut wrapped_psks: Vec<Vec<u8>> = Vec::with_capacity(eligible_devices.len());
        for device_pk in &eligible_devices {
            // Device public key must be exactly 32 bytes (X25519).
            if device_pk.len() != 32 {
                return false;
            }
            let mut pk_bytes = [0u8; 32];
            pk_bytes.copy_from_slice(device_pk);
            match wrap_psk_for_device(&new_psk, &pk_bytes, &params.did) {
                // `&new_psk` deref-coerces `&Zeroizing<[u8; 32]>` to `&[u8; 32]`.
                Some(wrapped) => wrapped_psks.push(wrapped),
                None => return false,
            }
        }

        // The plaintext PSK is wiped automatically when `new_psk` (a
        // `Zeroizing<[u8; 32]>`) is dropped at end of scope — no explicit
        // call needed, and every early return is now covered too.

        // Distribute the wrapped PSKs as a recovery notification via the
        // context manager. Each entry in the serialized payload corresponds
        // to one eligible device's wrapped PSK (§3.7 private state events).
        let psk_event = serde_json::json!({
            "event": "recovery:psk_rotation",
            "wrapped_psks": wrapped_psks.iter().map(hex::encode).collect::<Vec<_>>(),
        });
        let payload = match serde_json::to_vec(&psk_event) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize PSK rotation event — skipping");
                return false;
            }
        };

        // Send via recovery notification. We use a synthetic context ID
        // derived from "identity-private-state" since PSK rotation is
        // identity-scoped, not context-scoped.
        let result = self
            .dispatch_recovery_send_notification(
                "identity-private-state",
                "system",
                &payload,
                3, // sequence 3: PSK rotation notification
            )
            .await
            .map_err(Self::dispatch_step_error);

        result.is_ok()
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

    /// Returns a deterministic test signing key for `ProductionRecoveryBackend`.
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    // -----------------------------------------------------------------------
    // Mock backend for testing
    // -----------------------------------------------------------------------

    /// A mock `RecoveryBackend` that succeeds for all operations by default.
    /// Individual steps can be configured to fail.
    struct MockRecoveryBackend {
        /// If set, `mls_update` returns this error for the matching context.
        mls_update_error: Option<(String, RecoveryStepError)>,
        /// If set, `revoke_ucans` returns this error for the matching context.
        revoke_ucans_error: Option<(String, RecoveryStepError)>,
        /// If set, `rotate_key_packages` returns this error for the matching context.
        rotate_key_packages_error: Option<(String, RecoveryStepError)>,
        /// Whether `notify_contacts` succeeds.
        notify_contacts_result: bool,
        /// Whether `rotate_psk` succeeds.
        rotate_psk_result: bool,
    }

    impl MockRecoveryBackend {
        fn new() -> Self {
            Self {
                mls_update_error: None,
                revoke_ucans_error: None,
                rotate_key_packages_error: None,
                notify_contacts_result: true,
                rotate_psk_result: true,
            }
        }
    }

    #[async_trait(?Send)]
    impl RecoveryBackend for MockRecoveryBackend {
        async fn mls_update(
            &self,
            context_id: &str,
            _key_rotation: &KeyRotationOutcome,
        ) -> Result<(), RecoveryStepError> {
            if let Some((ref ctx, ref err)) = self.mls_update_error
                && ctx == context_id
            {
                return Err(err.clone());
            }
            Ok(())
        }

        async fn revoke_ucans(
            &self,
            context_id: &str,
            _key_rotation: &KeyRotationOutcome,
        ) -> Result<(), RecoveryStepError> {
            if let Some((ref ctx, ref err)) = self.revoke_ucans_error
                && ctx == context_id
            {
                return Err(err.clone());
            }
            Ok(())
        }

        async fn rotate_key_packages(
            &self,
            context_id: &str,
            _key_rotation: &KeyRotationOutcome,
        ) -> Result<(), RecoveryStepError> {
            if let Some((ref ctx, ref err)) = self.rotate_key_packages_error
                && ctx == context_id
            {
                return Err(err.clone());
            }
            Ok(())
        }

        async fn notify_contacts(
            &self,
            _did: &DID,
            _tier: CompromiseTier,
            _key_rotation: &KeyRotationOutcome,
            _contacts: &HashSet<DID>,
        ) -> bool {
            self.notify_contacts_result
        }

        async fn rotate_psk(&self, _params: &PskRotationParams) -> bool {
            self.rotate_psk_result
        }
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
        let outcome =
            identity_key_rotation_outcome(&did("did:dht:alice"), did("did:dht:alice-new"), 3000);
        assert_eq!(outcome.tier, CompromiseTier::IdentityKey);
        assert_eq!(outcome.did_after, did("did:dht:alice-new"));
        assert!(outcome.did_changed);
        assert_eq!(outcome.rotated_key_scopes, vec!["#active", "#agent"]);
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
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                &key_rotation,
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
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
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::from([did("did:dht:bob"), did("did:dht:carol")]);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                &key_rotation,
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
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
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);

        let key_rotation =
            identity_key_rotation_outcome(&did("did:dht:alice"), did("did:dht:alice-new"), 3000);
        let contacts = HashSet::from([did("did:dht:bob")]);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: None,
        };
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::IdentityKey,
                &key_rotation,
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
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
        let orch = CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec![]);

        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                &key_rotation,
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert!(result.completed_contexts.is_empty());
        assert!(result.failed_contexts.is_empty());
        assert!(result.pending_rejoin.is_empty());
    }

    #[tokio::test]
    async fn recovery_without_psk_params_for_active_tier() {
        // ActiveSigning without PSK params → private_state_reencrypted is false.
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                &key_rotation,
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        // Without PSK params, re-encryption didn't happen.
        assert!(!result.private_state_reencrypted);
    }

    #[tokio::test]
    async fn psk_rotation_excludes_compromised_device() {
        let orch = CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec![]);

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        // Device 2 is compromised.
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]],
            compromised_device_pubkey: Some(vec![2u8; 32]),
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                &key_rotation,
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert!(result.private_state_reencrypted);
    }

    #[tokio::test]
    async fn psk_rotation_fails_with_no_remaining_devices() {
        // All devices compromised → PSK rotation fails.
        let orch = CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec![]);

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::new();

        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: Some(vec![1u8; 32]),
        };

        // Backend reports PSK rotation failure (no remaining devices).
        let backend = MockRecoveryBackend {
            rotate_psk_result: false,
            ..MockRecoveryBackend::new()
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                &key_rotation,
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert!(!result.private_state_reencrypted);
    }

    #[tokio::test]
    async fn recovery_result_serialization_roundtrip() {
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);

        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                &key_rotation,
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
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
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };
        let backend = MockRecoveryBackend::new();

        // Tier 1: Agent key compromise (cheapest).
        {
            let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), contexts.clone());
            let kr = agent_key_rotation_outcome(&alice, 1000);
            let result = orch
                .execute_recovery(
                    CompromiseTier::Agent,
                    &kr,
                    &contacts,
                    None,
                    &backend,
                    &scp_clock::SystemClock,
                )
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
                    &backend,
                    &scp_clock::SystemClock,
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
            let kr = identity_key_rotation_outcome(&alice, did("did:dht:alice-new"), 3000);
            let result = orch
                .execute_recovery(
                    CompromiseTier::IdentityKey,
                    &kr,
                    &contacts,
                    Some(&psk_params),
                    &backend,
                    &scp_clock::SystemClock,
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
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: Some(vec![2u8; 32]),
        };
        let json = serde_json::to_string(&params).unwrap();
        let parsed: PskRotationParams = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enrolled_device_pubkeys.len(), 2);
        assert!(parsed.compromised_device_pubkey.is_some());
    }

    // -----------------------------------------------------------------------
    // ProductionRecoveryBackend tests
    // -----------------------------------------------------------------------

    /// Helper to create a minimal `ContextManager` for testing.
    ///
    /// After ADR-049 commit 12c.9e, the `ContextCryptoProvider` trait is
    /// deleted and tests bind to a real
    /// [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider)
    /// — fail-injection and stub-seal overrides move to
    /// backend-injection in commit 12c.9f.
    fn test_context_manager() -> Arc<crate::context::supervisor::Supervisor> {
        use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
        use scp_protocol::context::builder::ContextCreationError;
        use scp_protocol::context::{ContextError, ContextParams};

        const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        struct TestTransport;
        impl ContextTransportProvider for TestTransport {
            fn is_connected(&self) -> bool {
                true
            }
            fn publish_context(
                &self,
                _: &[u8; 32],
                _: &ContextParams,
            ) -> Result<(), ContextCreationError> {
                Ok(())
            }
            fn delete_published(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
                Ok(())
            }
            fn send_message(&self, _: &[u8; 32], _: &[u8]) -> Result<(), ContextError> {
                Ok(())
            }
        }

        struct TestEventLog;
        #[async_trait::async_trait]
        impl ContextEventLogProvider for TestEventLog {
            async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
                Ok(())
            }
            async fn append_event(
                &self,
                _: &[u8; 32],
                _: scp_event_log::EventType,
                _actor_did: &str,
                _payload: scp_event_log::EventPayload,
                _timestamp_secs: u64,
            ) -> Result<(), ContextCreationError> {
                Ok(())
            }
            async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
                Ok(())
            }
            fn event_log_entries(
                &self,
                _: &[u8; 32],
            ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
                Ok(None)
            }
        }

        // ADR-049 commit 12: `ContextManager` is gone. Build the
        // `Supervisor` directly via `test_supervisor`.
        crate::context::test_supervisor(
            Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
                TEST_DID.to_owned(),
                std::sync::Arc::new(scp_clock::SystemClock),
            )),
            Box::new(TestTransport),
            Box::new(TestEventLog),
            Arc::new(|_: &scp_did::DID, _: scp_did::SigningKeyId| None),
        )
    }

    /// Helper to create a context in the manager for testing.
    async fn setup_context(
        manager: &Arc<crate::context::supervisor::Supervisor>,
        context_id: &str,
        creator_did: &DID,
    ) {
        setup_context_with_members(manager, context_id, creator_did, &[]).await;
    }

    /// Helper to create a context with the creator and additional members.
    async fn setup_context_with_members(
        manager: &Arc<crate::context::supervisor::Supervisor>,
        context_id: &str,
        creator_did: &DID,
        additional_members: &[&DID],
    ) {
        use scp_protocol::context::ContextParams;
        use scp_protocol::context::membership::KeyPackage;
        use scp_protocol::context::params::{ContextMode, GovernanceModel};
        use scp_protocol::context::roles::Capability;

        let params = ContextParams {
            mode: ContextMode::Encrypted,
            governance: GovernanceModel::SingleAdmin,
            // Include role:assign capability so the admin can add members.
            ceiling: vec![
                Capability::new("messages:read"),
                Capability::new("messages:write"),
                Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        // Create the context. This registers it in the manager.
        let handle = manager
            .create_context(context_id.to_owned(), params, creator_did.clone(), None)
            .await
            .expect("failed to create test context");

        // Add additional members via join_context.
        for member_did in additional_members {
            let kp = KeyPackage::mock((*member_did).clone());
            manager
                .join_context(&handle, kp, None, None)
                .await
                .expect("failed to join test member");
        }
    }

    /// Seeds the MLS group for an identity-scoped recovery pseudo-context
    /// directly in the supervisor's crypto provider.
    ///
    /// PSK rotation (spec §9.12 step 6) seals its recovery notification
    /// against a synthetic `identity-private-state` context that is never
    /// registered as a per-context actor and never flows through
    /// `create_context`. The real `MlsCryptoProvider` that backs
    /// [`test_context_manager`] still requires an existing MLS group for
    /// that id before [`MlsCryptoProvider::seal`] will succeed, so tests
    /// exercising `rotate_psk` (directly or through `execute_recovery`)
    /// must establish the group up front — exactly as the production
    /// create-context path does for ordinary contexts.
    fn seed_identity_private_state_group(manager: &Arc<crate::context::supervisor::Supervisor>) {
        let context_id_bytes = crate::context::state::context_id_to_bytes("identity-private-state");
        manager
            .crypto_ref()
            .expect("crypto provider attached to test supervisor")
            .create_mls_group(&context_id_bytes)
            .expect("failed to seed identity-private-state MLS group");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_mls_update_succeeds() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let context_id = "ctx-prod-1";

        setup_context(&manager, context_id, &alice).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let result = backend.mls_update(context_id, &key_rotation).await;
        assert!(result.is_ok(), "mls_update should succeed: {result:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_mls_update_unknown_context_fails() {
        let manager = test_context_manager();
        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let alice = did("did:dht:alice");
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let result = backend
            .mls_update("nonexistent-context", &key_rotation)
            .await;
        assert!(result.is_err(), "mls_update on unknown context should fail");
        assert_eq!(result.unwrap_err().step, 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_revoke_ucans_succeeds() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let context_id = "ctx-prod-2";

        setup_context(&manager, context_id, &alice).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let result = backend.revoke_ucans(context_id, &key_rotation).await;
        assert!(result.is_ok(), "revoke_ucans should succeed: {result:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_rotate_key_packages_succeeds() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let context_id = "ctx-prod-3";

        setup_context(&manager, context_id, &alice).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let result = backend.rotate_key_packages(context_id, &key_rotation).await;
        assert!(
            result.is_ok(),
            "rotate_key_packages should succeed: {result:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_notify_contacts_succeeds() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let bob = did("did:dht:bob");
        let carol = did("did:dht:carol");

        // Set up a shared context where alice, bob, and carol are all members.
        // recovery_notify_contact searches for shared contexts between the
        // recovering DID and each contact.
        setup_context_with_members(&manager, "ctx-shared", &alice, &[&bob, &carol]).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let contacts = HashSet::from([bob, carol]);

        let result = backend
            .notify_contacts(&alice, CompromiseTier::Agent, &key_rotation, &contacts)
            .await;
        assert!(result, "notify_contacts should succeed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_notify_contacts_empty_set() {
        let manager = test_context_manager();
        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let alice = did("did:dht:alice");
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let contacts = HashSet::new();

        // Empty contact set — notification is vacuously true.
        // Note: notify_contacts with empty set is not called by the orchestrator
        // (it checks `contact_dids.is_empty()` first) but the backend should
        // handle it gracefully.
        let result = backend
            .notify_contacts(&alice, CompromiseTier::Agent, &key_rotation, &contacts)
            .await;
        assert!(result, "notify_contacts with empty set should succeed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_rotate_psk_succeeds() {
        let manager = test_context_manager();
        seed_identity_private_state_group(&manager);
        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());

        let params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };

        let result = backend.rotate_psk(&params).await;
        assert!(result, "rotate_psk should succeed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_rotate_psk_excludes_compromised_device() {
        let manager = test_context_manager();
        seed_identity_private_state_group(&manager);
        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());

        let params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]],
            compromised_device_pubkey: Some(vec![2u8; 32]),
        };

        let result = backend.rotate_psk(&params).await;
        assert!(
            result,
            "rotate_psk should succeed with compromised device excluded"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_rotate_psk_fails_no_eligible_devices() {
        let manager = test_context_manager();
        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());

        // All devices compromised.
        let params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: Some(vec![1u8; 32]),
        };

        let result = backend.rotate_psk(&params).await;
        assert!(!result, "rotate_psk should fail with no eligible devices");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_full_recovery_agent_tier() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let bob = did("did:dht:bob");
        let context_id = "ctx-full-recovery";

        // Set up a context with alice and bob as members so contact
        // notification can find a shared context.
        setup_context_with_members(&manager, context_id, &alice, &[&bob]).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![context_id.to_owned()]);
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let contacts = HashSet::from([bob]);

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                &key_rotation,
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(result.tier, CompromiseTier::Agent);
        assert_eq!(result.completed_contexts, vec![context_id]);
        assert!(result.failed_contexts.is_empty());
        assert!(result.key_rotation_completed);
        assert!(result.contacts_notified);
        assert!(result.private_state_reencrypted);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_full_recovery_active_signing_tier() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let bob = did("did:dht:bob");
        let context_id = "ctx-active-recovery";

        // Set up a context with alice and bob as members so contact
        // notification can find a shared context.
        setup_context_with_members(&manager, context_id, &alice, &[&bob]).await;
        // ActiveSigning recovery rotates the PSK, which seals against the
        // synthetic identity-private-state context — seed its MLS group.
        seed_identity_private_state_group(&manager);

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![context_id.to_owned()]);
        let key_rotation = active_key_rotation_outcome(&alice, 2000);
        let contacts = HashSet::from([bob]);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                &key_rotation,
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(result.tier, CompromiseTier::ActiveSigning);
        assert_eq!(result.completed_contexts, vec![context_id]);
        assert!(result.contacts_notified);
        assert!(result.private_state_reencrypted);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_full_recovery_identity_key_tier() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let bob = did("did:dht:bob");
        let carol = did("did:dht:carol");
        let context_id = "ctx-identity-recovery";

        // Set up a context with alice, bob, and carol as members so
        // contact notification can find shared contexts.
        setup_context_with_members(&manager, context_id, &alice, &[&bob, &carol]).await;
        // IdentityKey recovery rotates the PSK, which seals against the
        // synthetic identity-private-state context — seed its MLS group.
        seed_identity_private_state_group(&manager);

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![context_id.to_owned()]);
        let key_rotation = identity_key_rotation_outcome(&alice, did("did:dht:alice-new"), 3000);
        let contacts = HashSet::from([bob, carol]);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: None,
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::IdentityKey,
                &key_rotation,
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(result.tier, CompromiseTier::IdentityKey);
        assert_eq!(result.new_did, Some(did("did:dht:alice-new")));
        assert_eq!(result.completed_contexts, vec![context_id]);
        assert!(result.key_rotation_completed);
        assert!(result.contacts_notified);
        assert!(result.private_state_reencrypted);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_multi_context_with_failure_isolation() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");

        // Create two contexts. The second will exist but both should work.
        setup_context(&manager, "ctx-ok-1", &alice).await;
        setup_context(&manager, "ctx-ok-2", &alice).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let orch = CompromiseRecoveryOrchestrator::new(
            alice.clone(),
            vec![
                "ctx-ok-1".to_owned(),
                "ctx-ok-2".to_owned(),
                "ctx-nonexistent".to_owned(), // This should fail.
            ],
        );
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let contacts = HashSet::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                &key_rotation,
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        // Two contexts should succeed, one should fail.
        assert_eq!(result.completed_contexts.len(), 2);
        assert_eq!(result.failed_contexts.len(), 1);
        assert_eq!(result.failed_contexts[0].0, "ctx-nonexistent");
        assert_eq!(result.failed_contexts[0].1.step, 2);
    }

    // -----------------------------------------------------------------------
    // wrap_psk_for_device unit tests (RFC 9180, §3.7.2)
    //
    // These verify the PRODUCTION wrap path (`wrap_psk_for_device`, called by
    // `rotate_psk`). The device-side open counterpart is exercised here by
    // calling `scp_protocol::crypto::hpke::open` directly against the wrapped
    // wire (`enc(32) || ct(48)`), reconstructing the §3.7.2 `info` via the
    // shared `build_psk_hpke_info` helper that the production wrap also uses.
    // Opening through `hpke::open` keeps every negative ciphertext-level: a
    // real AEAD verification failure, not a builder-string comparison.
    // -----------------------------------------------------------------------

    /// Device-side open of a wrapped PSK, mirroring what a device that receives
    /// a `PskRotated` / `DeviceWrappedPsk` entry does: split `enc(32) || ct(48)`,
    /// rebuild the §3.7.2 `info`, and HPKE-open with the device X25519 secret.
    ///
    /// Returns `None` on wrong wire length, invalid `enc`, or any HPKE/AEAD
    /// failure (wrong device key, wrong `did`, tampered ciphertext) — exactly
    /// the failure surface the negatives below assert against.
    fn open_wrapped_psk(wrapped: &[u8], device_sk: &[u8; 32], did: &str) -> Option<[u8; 32]> {
        if wrapped.len() != super::WRAPPED_PSK_LEN {
            return None;
        }
        let enc: [u8; 32] = wrapped[..32].try_into().ok()?;
        let ct = &wrapped[32..];

        // Reconstruct the §3.7.2 info via the SAME helper the production wrap
        // uses, so the test cannot drift from the wrap's info construction.
        let info = super::build_psk_hpke_info(did, super::PSK_PURPOSE_ROTATE);
        let plaintext = zeroize::Zeroizing::new(
            scp_protocol::crypto::hpke::open(device_sk, &enc, &info, &[], ct).ok()?,
        );
        plaintext.as_slice().try_into().ok()
    }

    #[test]
    fn psk_wrapping_is_80_bytes_with_fresh_enc() {
        use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

        let device_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let device_public = X25519Pub::from(&device_secret);
        let psk = [0xABu8; 32];
        let did = "did:dht:zPskTest";

        let wrapped1 =
            super::wrap_psk_for_device(&psk, device_public.as_bytes(), did).expect("wrap 1 failed");
        let wrapped2 =
            super::wrap_psk_for_device(&psk, device_public.as_bytes(), did).expect("wrap 2 failed");

        // Wire layout: enc(32) || ct(48) = 80 bytes. No external nonce.
        assert_eq!(wrapped1.len(), 80);
        assert_eq!(wrapped2.len(), 80);

        // Each wrap uses a fresh ephemeral keypair → the encapsulated key
        // (`enc`, bytes 0..32) differs every time, even for the same PSK and
        // device. This is what makes each HPKE context single-use.
        assert_ne!(
            &wrapped1[..32],
            &wrapped2[..32],
            "enc must be fresh per wrap"
        );
    }

    #[test]
    fn psk_wrapping_roundtrip() {
        use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

        let device_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let device_public = X25519Pub::from(&device_secret);
        let psk = [0x42u8; 32];
        let did = "did:dht:zPskTest";

        // Production wrap → device-side open via hpke::open must recover the PSK.
        let wrapped =
            super::wrap_psk_for_device(&psk, device_public.as_bytes(), did).expect("wrap failed");

        let recovered =
            open_wrapped_psk(&wrapped, &device_secret.to_bytes(), did).expect("open failed");
        assert_eq!(recovered, psk, "roundtrip mismatch");
    }

    #[test]
    fn psk_opening_rejects_wrong_did() {
        use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

        let device_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let device_public = X25519Pub::from(&device_secret);
        let psk = [0x42u8; 32];

        let wrapped = super::wrap_psk_for_device(&psk, device_public.as_bytes(), "did:dht:zAlice")
            .expect("wrap failed");

        // A different DID changes the HPKE info → AEAD open fails.
        assert!(
            open_wrapped_psk(&wrapped, &device_secret.to_bytes(), "did:dht:zBob").is_none(),
            "wrong DID must fail to open"
        );
    }

    #[test]
    fn psk_opening_rejects_wrong_device_and_tamper() {
        use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

        let device_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let device_public = X25519Pub::from(&device_secret);
        let wrong_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let psk = [0x42u8; 32];
        let did = "did:dht:zPskTest";

        let wrapped =
            super::wrap_psk_for_device(&psk, device_public.as_bytes(), did).expect("wrap failed");

        // Wrong device key.
        assert!(
            open_wrapped_psk(&wrapped, &wrong_secret.to_bytes(), did).is_none(),
            "wrong device key must fail"
        );

        // Tampered ciphertext.
        let mut tampered = wrapped.clone();
        tampered[40] ^= 0x01;
        assert!(
            open_wrapped_psk(&tampered, &device_secret.to_bytes(), did).is_none(),
            "tampered ciphertext must fail"
        );

        // Wrong length.
        assert!(
            open_wrapped_psk(&wrapped[..79], &device_secret.to_bytes(), did).is_none(),
            "wrong length must fail"
        );
    }
}
