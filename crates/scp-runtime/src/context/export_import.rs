//! Context export/import with `MessagePack` serialization and Merkle verification.
//!
//! Provides [`ContextExport`] for serializing context state (snapshot, event log,
//! opaque MLS blob) into a portable, versioned format using `MessagePack` with
//! [`StoredValue<T>`](crate::store::StoredValue) envelopes (spec §17.5).
//!
//! Import verifies Merkle chain integrity of the event log entries before
//! restoring context state, ensuring tamper detection.
//!
//! See GitHub issue #363.

use scp_primitives::Clock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::manager::ContextSnapshot;
use crate::store::StoredValue;
use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current version of the context export format.
///
/// Incremented when the export format changes in a backward-incompatible way.
/// Import rejects exports with `version > CURRENT_EXPORT_VERSION`.
///
/// # Version history
///
/// - `1`: unsigned export (event-log Merkle chain only). **Rejected on import**
///   — the embedded snapshot was not integrity-protected, so a tampered export
///   could forge membership/roles/params. Distinguished from a signature
///   failure by a dedicated `version` error.
/// - `2`: signed export. The embedded snapshot is covered by
///   `snapshot_signature` (Ed25519 over [`ContextExport::canonical_snapshot_hash`],
///   domain `SCP-CONTEXT-SNAPSHOT-V1:` per spec §23.16.4), produced by the
///   exporter's custody key and verified on import against the exporter DID's
///   resolved verification-method key (`#active`/`#agent`, ADR-039).
pub const CURRENT_EXPORT_VERSION: u32 = 2;

/// Domain separator for the signed `ContextExport` snapshot hash (spec §23.16.4,
/// §9.18.2). Shared with [`super::super::sync::days_offline`].
pub const CONTEXT_SNAPSHOT_DOMAIN_SEPARATOR: &str = "SCP-CONTEXT-SNAPSHOT-V1:";

// ---------------------------------------------------------------------------
// ContextExport
// ---------------------------------------------------------------------------

/// Portable representation of a context's full state.
///
/// Serialized as `MessagePack` with a [`StoredValue<T>`] version envelope per
/// spec §17.5. Contains the context snapshot (membership, roles, governance,
/// TTL, broadcast state), serialized event log entries, and an opaque MLS
/// state blob (empty until MLS integration lands via #333).
///
/// # Merkle Verification
///
/// On import, the Merkle chain of `event_log_data` is verified: each entry's
/// `prev_hash` must match the preceding entry's `hash`, and each entry's
/// `hash` must be correctly computed. The Merkle root (hash of the last entry)
/// is stored in `merkle_root` at export time and compared on import.
///
/// # Privacy
///
/// The `scope` field controls what data is included:
/// - [`ExportScope::Full`]: all data, including membership details and
///   governance configuration. Intended for backup/migration by context admins.
/// - [`ExportScope::Public`]: only structural metadata visible to pre-join
///   observers (spec §5.7). Strips member list, governance details, and
///   event log entries. Intended for sharing context summaries.
///
/// See GitHub issue #363.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextExport {
    /// The context snapshot (membership, roles, governance, TTL, broadcast).
    pub snapshot: ContextSnapshot,
    /// Serialized event log entries (MessagePack-encoded `Vec<EventLogEntry>`).
    /// Empty for [`ExportScope::Public`] exports.
    #[serde(with = "serde_bytes")]
    pub event_log_data: Vec<u8>,
    /// Opaque MLS group state. Empty until #333 (MLS integration) lands.
    #[serde(with = "serde_bytes")]
    pub mls_state: Vec<u8>,
    /// Export format version. Import rejects versions above
    /// [`CURRENT_EXPORT_VERSION`].
    pub version: u32,
    /// Unix timestamp (seconds) when the export was created.
    pub exported_at: u64,
    /// DID of the identity that performed the export.
    pub exporter_did: DID,
    /// Merkle root hash of the event log at export time.
    /// All zeros if the event log is empty or not included.
    pub merkle_root: [u8; 32],
    /// The scope of data included in this export.
    pub scope: ExportScope,
    /// Ed25519 signature over [`ContextExport::canonical_snapshot_hash`],
    /// produced by the exporter's custody key (spec §23.16.4).
    ///
    /// Binds the embedded [`ContextSnapshot`] (membership, roles, params, tool
    /// set) together with the event-log Merkle root, exporter DID, and export
    /// version, so a tampered export is rejected on import. Verified against the
    /// exporter DID's resolved `#active`/`#agent` verification-method key.
    ///
    /// For [`ExportScope::Public`] exports the signature is computed over the
    /// stripped snapshot (after [`strip_snapshot_for_public`]); a verifier must
    /// recompute the hash over the bytes it actually received.
    #[serde(with = "serde_bytes")]
    pub snapshot_signature: [u8; 64],
}

/// Controls what data is included in a [`ContextExport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportScope {
    /// Full export: all context state including membership, governance,
    /// and event log. Intended for backup/migration by context admins.
    Full,
    /// Public export: only structural metadata visible to pre-join observers
    /// (spec §5.7). Strips sensitive data. Intended for sharing context
    /// summaries.
    Public,
}

// ---------------------------------------------------------------------------
// Canonical snapshot hash (spec §23.16.4)
// ---------------------------------------------------------------------------

impl ContextExport {
    /// Computes the canonical hash signed by the exporter and verified on
    /// import (spec §23.16.4).
    ///
    /// Domain separator `SCP-CONTEXT-SNAPSHOT-V1:`. The hash binds the embedded
    /// snapshot's integrity-relevant state together with the export envelope:
    ///
    /// `members_hash || role_definitions_hash || params_hash || tool_names_hash
    ///  || merkle_root || BE32(len(exporter_did)) || exporter_did || version`
    ///
    /// Composite fields are first reduced to a deterministic 32-byte digest
    /// (key-ordered, length-prefixed) following the §23.16.4 recipe, then folded
    /// into the canonical hash as fixed-32 fields. Because the hash is computed
    /// over the *current* contents of `self.snapshot`, a `Public` export (whose
    /// snapshot has already been stripped) is signed and verified over the
    /// stripped bytes — the verifier sees exactly what was transmitted.
    ///
    /// # Errors
    ///
    /// Returns [`scp_protocol::crypto::canonical::CanonicalError`] if a
    /// variable-length field exceeds `u32::MAX` bytes (unreachable in practice).
    pub fn canonical_snapshot_hash(
        &self,
    ) -> Result<[u8; 32], scp_protocol::crypto::canonical::CanonicalError> {
        let members_hash = self.hash_members();
        let role_defs_hash = self.hash_role_definitions();
        let params_hash = self.hash_params();
        let tool_names_hash = self.hash_tool_names();

        let exporter_did = self.exporter_did.as_ref().as_bytes();

        let fields = [
            CanonicalField::Fixed32(&members_hash),
            CanonicalField::Fixed32(&role_defs_hash),
            CanonicalField::Fixed32(&params_hash),
            CanonicalField::Fixed32(&tool_names_hash),
            CanonicalField::Fixed32(&self.merkle_root),
            CanonicalField::VarBytes(exporter_did),
            CanonicalField::U32(self.version),
        ];

        canonical_hash(CONTEXT_SNAPSHOT_DOMAIN_SEPARATOR, &fields)
    }

    /// Deterministic hash of the snapshot membership roster (§23.16.4 recipe).
    ///
    /// Members are emitted in DID key order: for each `(did, info)`,
    /// `BE32(len(did)) || did || BE32(len(role_name)) || role_name
    ///  || sequence_number (8-byte BE u64)`.
    fn hash_members(&self) -> [u8; 32] {
        // BTreeMap gives deterministic key ordering regardless of the source
        // HashMap's iteration order.
        let ordered: std::collections::BTreeMap<
            &str,
            &scp_protocol::context::membership::MemberInfo,
        > = self
            .snapshot
            .membership
            .members()
            .map(|info| (info.did.as_ref(), info))
            .collect();

        let mut hasher = Sha256::new();
        for (did, info) in ordered {
            let did_len = u32::try_from(did.len()).unwrap_or(u32::MAX);
            hasher.update(did_len.to_be_bytes());
            hasher.update(did.as_bytes());
            let role_len = u32::try_from(info.role_name.len()).unwrap_or(u32::MAX);
            hasher.update(role_len.to_be_bytes());
            hasher.update(info.role_name.as_bytes());
            hasher.update(info.sequence_number.to_be_bytes());
        }
        hasher.finalize().into()
    }

    /// Deterministic hash of the snapshot role definitions (§23.16.4 recipe).
    ///
    /// Roles are emitted in role-name key order. Each role's capabilities are
    /// reduced to their UCAN capability-name strings, sorted, then emitted:
    /// `BE32(len(role)) || role || BE32(count) || [BE32(len(cap)) || cap ...]`.
    fn hash_role_definitions(&self) -> [u8; 32] {
        let ordered: std::collections::BTreeMap<&str, Vec<String>> = self
            .snapshot
            .role_state
            .role_definitions
            .iter()
            .map(|(name, def)| {
                let mut caps: Vec<String> = def
                    .capabilities
                    .iter()
                    .map(scp_protocol::context::roles::Capability::ucan_capability_name)
                    .collect();
                caps.sort();
                (name.as_str(), caps)
            })
            .collect();

        let mut hasher = Sha256::new();
        for (role, caps) in ordered {
            let role_len = u32::try_from(role.len()).unwrap_or(u32::MAX);
            hasher.update(role_len.to_be_bytes());
            hasher.update(role.as_bytes());
            let count = u32::try_from(caps.len()).unwrap_or(u32::MAX);
            hasher.update(count.to_be_bytes());
            for cap in &caps {
                let cap_len = u32::try_from(cap.len()).unwrap_or(u32::MAX);
                hasher.update(cap_len.to_be_bytes());
                hasher.update(cap.as_bytes());
            }
        }
        hasher.finalize().into()
    }

    /// SHA-256 over the canonical (RFC 8785 JCS) encoding of the snapshot's
    /// context parameters (§23.16.4 `params_hash`).
    ///
    /// Uses JSON canonicalization (the project-wide canonical hashing format)
    /// so the digest is stable across implementations. Falls back to a fixed
    /// sentinel only if canonicalization fails, which cannot occur for a
    /// well-formed `ContextParams`.
    fn hash_params(&self) -> [u8; 32] {
        let canonical =
            scp_protocol::jcs::to_vec(&self.snapshot.context_params).unwrap_or_default();
        Sha256::digest(&canonical).into()
    }

    /// Deterministic hash of the registered tool-name set (§23.16.4 recipe).
    ///
    /// Tool identifiers are gathered from both the immutable
    /// `context_params.tools` and the dynamically `registered_tools`, then
    /// deduplicated and sorted for order-independence:
    /// `BE32(count) || [BE32(len(name)) || name ...]`.
    fn hash_tool_names(&self) -> [u8; 32] {
        let mut names: Vec<&str> = self
            .snapshot
            .context_params
            .tools
            .iter()
            .map(|t| t.tool_id.as_str())
            .chain(
                self.snapshot
                    .registered_tools
                    .iter()
                    .map(|t| t.tool_id.as_str()),
            )
            .collect();
        names.sort_unstable();
        names.dedup();

        let mut hasher = Sha256::new();
        let count = u32::try_from(names.len()).unwrap_or(u32::MAX);
        hasher.update(count.to_be_bytes());
        for name in names {
            let name_len = u32::try_from(name.len()).unwrap_or(u32::MAX);
            hasher.update(name_len.to_be_bytes());
            hasher.update(name.as_bytes());
        }
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Serialization (MessagePack + StoredValue envelope)
// ---------------------------------------------------------------------------

/// Serializes a [`ContextExport`] into `MessagePack` bytes wrapped in a
/// [`StoredValue<T>`] version envelope per spec §17.5.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] if serialization fails.
pub fn serialize_export(export: &ContextExport) -> Result<Vec<u8>, ContextError> {
    let envelope = StoredValue {
        version: 1u16,
        data: export,
    };
    rmp_serde::to_vec_named(&envelope)
        .map_err(|e| ContextError::EventLogFailed(format!("export serialization failed: {e}")))
}

/// Deserializes a [`ContextExport`] from `MessagePack` bytes wrapped in a
/// [`StoredValue<T>`] version envelope per spec §17.5.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] if the stored version is
/// incompatible or deserialization fails.
pub fn deserialize_export(bytes: &[u8]) -> Result<ContextExport, ContextError> {
    let envelope: StoredValue<ContextExport> = rmp_serde::from_slice(bytes)
        .map_err(|e| ContextError::EventLogFailed(format!("export deserialization failed: {e}")))?;
    if envelope.version > 1 {
        return Err(ContextError::EventLogFailed(format!(
            "incompatible StoredValue version: stored={}, current=1",
            envelope.version
        )));
    }
    Ok(envelope.data)
}

// ---------------------------------------------------------------------------
// Merkle verification
// ---------------------------------------------------------------------------

/// Recomputes the Merkle chain hash for a set of serialized event log entries
/// and returns the root hash (the hash of the last entry).
///
/// Returns all zeros for empty data.
///
/// # Pruning tolerance
///
/// The first entry's `prev_hash` linkage is **not** validated. If the log was
/// pruned, `entries[0].prev_hash` references a discarded predecessor that
/// cannot be checked. A non-genesis `prev_hash` on the first entry is therefore
/// accepted — the log is treated as a pruned suffix. Hash-chain verification
/// begins at the link between the first and second entries; each subsequent
/// entry's `prev_hash` must match its predecessor's `hash`. Self-hash
/// correctness is still verified for every entry, including the first.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] if deserialization fails or
/// the Merkle chain is broken (`prev_hash` mismatch or hash mismatch).
pub fn verify_merkle_chain(event_log_data: &[u8]) -> Result<[u8; 32], ContextError> {
    use super::providers::event_log::EventLogEntry;

    if event_log_data.is_empty() {
        return Ok([0u8; 32]);
    }

    let entries: Vec<EventLogEntry> = rmp_serde::from_slice(event_log_data).map_err(|e| {
        ContextError::EventLogFailed(format!(
            "failed to deserialize event log entries for verification: {e}"
        ))
    })?;

    if entries.is_empty() {
        return Ok([0u8; 32]);
    }

    for (i, entry) in entries.iter().enumerate() {
        // Skip prev_hash linkage check for the first entry: if the log was
        // pruned, entries[0].prev_hash references a discarded predecessor and
        // cannot be validated. This matches the logic in
        // `providers::event_log::verify_chain_integrity`.
        if i > 0 && !bool::from(entry.prev_hash.ct_eq(&entries[i - 1].hash)) {
            return Err(ContextError::EventLogFailed(format!(
                "Merkle chain broken at entry {i}: prev_hash mismatch"
            )));
        }

        // Verify self-hash correctness.
        let expected_hash = compute_entry_hash(
            &entry.event,
            &entry.actor_did,
            entry.timestamp,
            &entry.prev_hash,
            entry.payload.as_ref(),
        );
        if !bool::from(entry.hash.ct_eq(&expected_hash)) {
            return Err(ContextError::EventLogFailed(format!(
                "Merkle chain broken at entry {i}: hash mismatch"
            )));
        }
    }

    Ok(entries.last().map_or([0u8; 32], |e| e.hash))
}

/// Computes the SHA-256 hash for an event log entry.
///
/// Hash input: `"SCP-EXPORT-ENTRY:" || len(event) || event || len(actor_did)
///   || actor_did || timestamp || prev_hash [|| len(payload_json) || payload_json]`
///
/// Uses big-endian u32 length prefixes before variable-length fields to
/// prevent length-extension ambiguity.
///
/// This must be identical to
/// [`providers::event_log::compute_entry_hash`](super::providers::event_log)
/// to ensure verification produces the same hashes.
fn compute_entry_hash(
    event: &str,
    actor_did: &str,
    timestamp: u64,
    prev_hash: &[u8; 32],
    payload: Option<&serde_json::Value>,
) -> [u8; 32] {
    // Event names and DID strings are always well under u32::MAX bytes.
    let event_len = u32::try_from(event.len()).unwrap_or(u32::MAX);
    let actor_len = u32::try_from(actor_did.len()).unwrap_or(u32::MAX);
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-EXPORT-ENTRY:");
    hasher.update(event_len.to_be_bytes());
    hasher.update(event.as_bytes());
    hasher.update(actor_len.to_be_bytes());
    hasher.update(actor_did.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(prev_hash);
    // Payload is included in the hash when present.
    // Absent payloads contribute no bytes, preserving backward compat.
    if let Some(val) = payload {
        let json_bytes = serde_json::to_vec(val).unwrap_or_default();
        let payload_len = u32::try_from(json_bytes.len()).unwrap_or(u32::MAX);
        hasher.update(payload_len.to_be_bytes());
        hasher.update(&json_bytes);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Validates a [`ContextExport`] for import readiness, including snapshot
/// signature verification (spec §23.16.4).
///
/// Checks, in order:
/// 1. Export version is **exactly** supported. Versions above
///    [`CURRENT_EXPORT_VERSION`] are rejected as unsupported; the pre-signing
///    version (`1`) is rejected with a distinct *version* error because such
///    exports carry no integrity-protected snapshot and MUST NOT be trusted.
/// 2. Snapshot signature: the exporter's Ed25519 signature over
///    [`ContextExport::canonical_snapshot_hash`] must verify (`verify_strict`)
///    against `verifying_key` (the exporter DID's resolved
///    `#active`/`#agent` key). Failure yields the distinct
///    [`ContextError::SnapshotSignatureInvalid`].
/// 3. Merkle chain integrity of event log entries.
/// 4. Merkle root matches the stored root hash.
///
/// The signature is checked before the Merkle chain so that an export with a
/// forged snapshot is rejected with the signature error regardless of whether
/// its event log happens to be internally consistent.
///
/// # Errors
///
/// - [`ContextError::EventLogFailed`] — unsupported/legacy version, broken
///   Merkle chain, or Merkle root mismatch.
/// - [`ContextError::SnapshotSignatureInvalid`] — the snapshot signature does
///   not authenticate the embedded snapshot under `verifying_key`.
pub fn validate_export_for_import(
    export: &ContextExport,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ContextError> {
    // 1. Version check. Reject anything that is not the current signed format.
    // Legacy v1 exports (unsigned) and future versions are both rejected here
    // — distinct from a signature failure so callers can tell "too old / too
    // new" apart from "signature forged".
    if export.version != CURRENT_EXPORT_VERSION {
        return Err(ContextError::EventLogFailed(format!(
            "unsupported export version: {}, required: {CURRENT_EXPORT_VERSION} \
             (versions below {CURRENT_EXPORT_VERSION} predate snapshot signing and \
             are rejected as unverifiable)",
            export.version
        )));
    }

    // 2. Snapshot signature verification (§23.16.4). Recompute the canonical
    // hash over the received bytes and verify against the exporter's key.
    let hash =
        export
            .canonical_snapshot_hash()
            .map_err(|e| ContextError::SnapshotSignatureInvalid {
                reason: format!("canonical snapshot hash construction failed: {e}"),
            })?;
    let signature = ed25519_dalek::Signature::from_bytes(&export.snapshot_signature);
    verifying_key
        .verify_strict(&hash, &signature)
        .map_err(|e| ContextError::SnapshotSignatureInvalid {
            reason: format!(
                "exporter signature over snapshot did not verify (exporter_did={}): {e}",
                export.exporter_did
            ),
        })?;

    // 3. Merkle chain verification.
    let computed_root = verify_merkle_chain(&export.event_log_data)?;

    // 4. Root hash comparison (constant-time to avoid timing side-channels).
    if !bool::from(computed_root.ct_eq(&export.merkle_root)) {
        return Err(ContextError::EventLogFailed(
            "Merkle root mismatch: computed root does not match exported root — \
             event log data may have been tampered with"
                .to_owned(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public metadata stripping for ExportScope::Public
// ---------------------------------------------------------------------------

/// Strips sensitive data from a [`ContextSnapshot`] for a public export.
///
/// Retains only structural fields visible to pre-join observers (spec §5.7):
/// `context_id`, state, `context_params`, and empty/default values for
/// membership, `role_state`, and governance fields.
fn strip_snapshot_for_public(snapshot: &ContextSnapshot) -> ContextSnapshot {
    use scp_protocol::context::membership::MembershipState;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    use std::collections::{HashMap, HashSet};

    // Build a minimal role state with only the default ceiling.
    // Use the snapshot's context_id and an empty creator DID.
    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(
        &snapshot.context_id,
        "",
        ceiling,
        Vec::new(),
        &scp_primitives::SystemClock,
    )
    .unwrap_or_else(|_| snapshot.role_state.clone());

    ContextSnapshot {
        context_id: snapshot.context_id.clone(),
        state: snapshot.state.clone(),
        context_params: snapshot.context_params.clone(),
        membership: MembershipState::new(),
        role_state,
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: snapshot.ttl_remaining_secs,
        registered_tools: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
        economic_policy: snapshot.economic_policy.clone(),
        budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
        approved_proposals: HashMap::new(),
        // H10: monotonic seq counter is local-instance state with no
        // meaning to a public observer — always 0 in public scope.
        next_proposal_seq: 0,
        governance_freeze: None,
        pending_ceiling_modification: None,
        pending_economic_policy_change: None,
        mls_epoch: 0,
        // Epoch coordination records are stripped in public scope —
        // they are auditable but internal governance state.
        epoch_coordination_records: Vec::new(),
        // Grace entries are not exported in public scope — they are
        // runtime state that is only meaningful to the local node.
        grace_entries: Vec::new(),
        // Reconnection flag is not exported — only meaningful to the local node.
        needs_reconnect: false,
        mls_crypto_state: Vec::new(),
        migration_state: None,
        // Access keys are sensitive material — not exported in public scope.
        access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
        // Consequence rules ARE part of the public opt-in contract — prospective
        // members need to see what behavioral consequences exist before joining.
        consequence_rules: snapshot.consequence_rules.clone(),
        participation_cache: HashMap::new(),
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: HashMap::new(),
        proposal_timestamps: HashMap::new(),
        // Per-DID anti-spam pricing (§19.7) is part of the public opt-in
        // contract — joiners must see the cost before joining. Hard rate
        // limit config is also public; the per-sender bucket state is local.
        message_pricing: snapshot.message_pricing.clone(),
        hard_rate_limit_config: snapshot.hard_rate_limit_config.clone(),
        hard_rate_limit_state: HashMap::new(),
        // Nonce tracker state is strictly local — it has no meaning
        // to a joiner and could leak activity patterns. Always empty
        // in public scope.
        spending_nonce_tracker_state: HashMap::new(),
        // PR #1606 C6: pending commits and the fail-close marker are
        // strictly local node state. They reference the local MLS group
        // and have no meaning to a public observer. Always empty in
        // public scope.
        pending_commits: std::collections::VecDeque::new(),
        commit_fault: None,
        // Checkpoint counters are local runtime state — no meaning to a
        // public observer. Always zero in public scope.
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        // Generation counter is local runtime state — no meaning to a
        // public observer. Always zero in public scope.
        generation: 0,
        // §9.10.4: pseudonym state is local-instance routing state —
        // no meaning to a public observer. Always empty/None in public scope.
        local_pseudonym: None,
        pseudonym_registry: HashMap::new(),
    }
}

/// Creates a signed [`ContextExport`] from a snapshot and event log data.
///
/// For [`ExportScope::Full`], includes all data. For [`ExportScope::Public`],
/// strips sensitive data from the snapshot and omits event log entries.
///
/// The export's [`ContextExport::canonical_snapshot_hash`] is computed over the
/// **final** export contents (after public stripping, with the resolved Merkle
/// root and `version`) and passed to `sign`, which must return an Ed25519
/// signature produced by the exporter's custody key (spec §23.16.4). Signing
/// happens at the FFI boundary because the runtime holds no custody key — see
/// the module-level architecture note.
///
/// # Errors
///
/// Returns [`ContextError`] if Merkle root computation fails, if canonical hash
/// construction fails, or if `sign` returns an error.
pub fn create_export<F, E>(
    snapshot: ContextSnapshot,
    event_log_data: Vec<u8>,
    mls_state: Vec<u8>,
    exporter_did: DID,
    scope: ExportScope,
    clock: &dyn Clock,
    sign: F,
) -> Result<ContextExport, ContextError>
where
    F: FnOnce(&[u8; 32]) -> Result<[u8; 64], E>,
    E: std::fmt::Display,
{
    let exported_at = clock.now_secs();

    let (final_snapshot, event_log_data, mls_state, merkle_root) = match scope {
        ExportScope::Full => {
            let merkle_root = verify_merkle_chain(&event_log_data)?;
            (snapshot, event_log_data, mls_state, merkle_root)
        }
        ExportScope::Public => {
            let stripped = strip_snapshot_for_public(&snapshot);
            (stripped, Vec::new(), Vec::new(), [0u8; 32])
        }
    };

    // Build the export with a placeholder signature so the canonical hash can
    // be computed over the exact bytes a verifier will recompute. The signature
    // field itself is NOT part of the hash (see `canonical_snapshot_hash`).
    let mut export = ContextExport {
        snapshot: final_snapshot,
        event_log_data,
        mls_state,
        version: CURRENT_EXPORT_VERSION,
        exported_at,
        exporter_did,
        merkle_root,
        scope,
        snapshot_signature: [0u8; 64],
    };

    let hash = export.canonical_snapshot_hash().map_err(|e| {
        ContextError::EventLogFailed(format!("export snapshot hash construction failed: {e}"))
    })?;

    export.snapshot_signature = sign(&hash).map_err(|e| {
        ContextError::EventLogFailed(format!("export snapshot signing failed: {e}"))
    })?;

    Ok(export)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::builder::ContextEventLogProvider;
    use crate::context::providers::event_log::MerkleEventLogProvider;
    use scp_protocol::context::ContextState;
    use scp_protocol::context::membership::MembershipState;
    use scp_protocol::context::params::ContextParams;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    use std::collections::{HashMap, HashSet};

    /// Deterministic test signing key (seed of all 7s).
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Signing closure that signs the canonical hash with [`test_signing_key`].
    // Result is mandated by the `create_export` sign-closure contract
    // (`FnOnce(&[u8; 32]) -> Result<[u8; 64], E>`); the test signer is
    // infallible.
    #[allow(clippy::unnecessary_wraps)]
    fn sign_with_test_key(hash: &[u8; 32]) -> Result<[u8; 64], std::convert::Infallible> {
        use ed25519_dalek::Signer;
        Ok(test_signing_key().sign(hash).to_bytes())
    }

    /// Verifying key paired with [`test_signing_key`].
    fn test_verifying_key() -> ed25519_dalek::VerifyingKey {
        test_signing_key().verifying_key()
    }

    /// Helper to build a test snapshot.
    fn test_snapshot(context_id: &str) -> ContextSnapshot {
        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            context_id,
            "did:key:test-creator",
            ceiling,
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap();

        ContextSnapshot {
            context_id: context_id.to_owned(),
            state: ContextState::Active,
            context_params: ContextParams::default(),
            membership: MembershipState::new(),
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            read_exclusion_list: HashSet::new(),
            approved_proposals: HashMap::new(),
            next_proposal_seq: 0,
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            mls_crypto_state: Vec::new(),
            migration_state: None,
            access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
            consequence_rules: Vec::new(),
            participation_cache: std::collections::HashMap::new(),
            velocity_tracker: None,
            velocity_tracker_state: None,
            cooldown_until: std::collections::HashMap::new(),
            proposal_timestamps: std::collections::HashMap::new(),
            message_pricing: None,
            hard_rate_limit_config: None,
            hard_rate_limit_state: std::collections::HashMap::new(),
            spending_nonce_tracker_state: std::collections::HashMap::new(),
            pending_commits: std::collections::VecDeque::new(),
            commit_fault: None,
            checkpoint_events_since: 0,
            checkpoint_last_time_secs: 0,
            generation: 0,
            local_pseudonym: None,
            pseudonym_registry: HashMap::new(),
        }
    }

    /// Helper to create event log entries via the provider.
    fn create_event_log_data(context_id_bytes: &[u8; 32], event_names: &[&str]) -> Vec<u8> {
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(context_id_bytes).unwrap();
        for name in event_names {
            provider
                .append_event(context_id_bytes, name, "", None)
                .unwrap();
        }
        provider.export_event_log_entries(context_id_bytes).unwrap()
    }

    // -------------------------------------------------------------------
    // Roundtrip serialization tests
    // -------------------------------------------------------------------

    #[test]
    fn roundtrip_export_empty_events() {
        let snapshot = test_snapshot("ctx-roundtrip-1");
        let export = create_export(
            snapshot,
            Vec::new(),
            Vec::new(),
            DID::from("did:key:exporter-1"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        let bytes = serialize_export(&export).unwrap();
        let decoded = deserialize_export(&bytes).unwrap();

        assert_eq!(decoded.snapshot.context_id, "ctx-roundtrip-1");
        assert_eq!(decoded.version, CURRENT_EXPORT_VERSION);
        assert_eq!(decoded.exporter_did.as_ref(), "did:key:exporter-1");
        assert_eq!(decoded.merkle_root, [0u8; 32]);
        assert!(decoded.event_log_data.is_empty());
        assert!(decoded.mls_state.is_empty());
    }

    #[test]
    fn roundtrip_export_with_events() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-roundtrip-2");
        let event_log_data = create_event_log_data(
            &ctx_id_bytes,
            &["ContextCreated", "MemberJoined", "MessageSent"],
        );

        let snapshot = test_snapshot("ctx-roundtrip-2");
        let export = create_export(
            snapshot,
            event_log_data,
            vec![0xDE, 0xAD],
            DID::from("did:key:exporter-2"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        assert_ne!(export.merkle_root, [0u8; 32]);

        let bytes = serialize_export(&export).unwrap();
        let decoded = deserialize_export(&bytes).unwrap();

        assert_eq!(decoded.snapshot.context_id, "ctx-roundtrip-2");
        assert_eq!(decoded.merkle_root, export.merkle_root);
        assert_eq!(decoded.mls_state, vec![0xDE, 0xAD]);
        assert_eq!(decoded.version, CURRENT_EXPORT_VERSION);
        assert!(!decoded.event_log_data.is_empty());
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-roundtrip-3");
        let event_log_data = create_event_log_data(&ctx_id_bytes, &["E1", "E2", "E3", "E4", "E5"]);

        let mut snapshot = test_snapshot("ctx-roundtrip-3");
        snapshot.ttl_remaining_secs = Some(3600);
        snapshot.threshold_value = 42;

        let export = create_export(
            snapshot,
            event_log_data,
            vec![1, 2, 3],
            DID::from("did:key:exporter-3"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        let bytes = serialize_export(&export).unwrap();
        let decoded = deserialize_export(&bytes).unwrap();

        assert_eq!(decoded.snapshot.ttl_remaining_secs, Some(3600));
        assert_eq!(decoded.snapshot.threshold_value, 42);
        assert_eq!(decoded.scope, ExportScope::Full);
        assert_eq!(decoded.exporter_did.as_ref(), "did:key:exporter-3");
    }

    // -------------------------------------------------------------------
    // Merkle verification tests
    // -------------------------------------------------------------------

    #[test]
    fn verify_merkle_chain_empty_data() {
        let root = verify_merkle_chain(&[]).unwrap();
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn verify_merkle_chain_valid_entries() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-merkle-1");
        let data = create_event_log_data(
            &ctx_id_bytes,
            &["ContextCreated", "MemberJoined", "MessageSent"],
        );

        let root = verify_merkle_chain(&data).unwrap();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn verify_merkle_chain_detects_tampered_hash() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-merkle-2");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event1", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event2", "", None)
            .unwrap();

        let mut entries = provider.entries(&ctx_id_bytes).unwrap();
        // Tamper with the first entry's hash.
        entries[0].hash = [0xFF; 32];

        let tampered_data = rmp_serde::to_vec_named(&entries).unwrap();
        let result = verify_merkle_chain(&tampered_data);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("hash mismatch") || err_msg.contains("prev_hash mismatch"));
    }

    #[test]
    fn verify_merkle_chain_detects_removed_entry() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-merkle-3");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event1", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event2", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event3", "", None)
            .unwrap();

        let mut entries = provider.entries(&ctx_id_bytes).unwrap();
        // Remove the middle entry.
        entries.remove(1);

        let tampered_data = rmp_serde::to_vec_named(&entries).unwrap();
        let result = verify_merkle_chain(&tampered_data);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // Import validation tests
    // -------------------------------------------------------------------

    #[test]
    fn validate_export_succeeds_for_valid_export() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-validate-1");
        let event_log_data =
            create_event_log_data(&ctx_id_bytes, &["ContextCreated", "MemberJoined"]);

        let snapshot = test_snapshot("ctx-validate-1");
        let export = create_export(
            snapshot,
            event_log_data,
            Vec::new(),
            DID::from("did:key:validator-1"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        validate_export_for_import(&export, &test_verifying_key()).unwrap();
    }

    #[test]
    fn validate_export_rejects_future_version() {
        let snapshot = test_snapshot("ctx-validate-2");
        let export = ContextExport {
            snapshot,
            event_log_data: Vec::new(),
            mls_state: Vec::new(),
            version: 99,
            exported_at: 1_000_000,
            exporter_did: DID::from("did:key:validator-2"),
            merkle_root: [0u8; 32],
            scope: ExportScope::Full,
            snapshot_signature: [0u8; 64],
        };

        let result = validate_export_for_import(&export, &test_verifying_key());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unsupported export version"));
    }

    #[test]
    fn validate_export_rejects_merkle_root_mismatch() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-validate-3");
        let event_log_data =
            create_event_log_data(&ctx_id_bytes, &["ContextCreated", "MemberJoined"]);

        let snapshot = test_snapshot("ctx-validate-3");
        let mut export = create_export(
            snapshot,
            event_log_data,
            Vec::new(),
            DID::from("did:key:validator-3"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // Tamper with the Merkle root, then re-sign so the snapshot signature
        // is valid for the tampered contents — this isolates the Merkle root
        // comparison (step 4) from the signature check (step 2).
        export.merkle_root = [0xAB; 32];
        export.snapshot_signature =
            sign_with_test_key(&export.canonical_snapshot_hash().unwrap()).unwrap();

        let result = validate_export_for_import(&export, &test_verifying_key());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Merkle root mismatch"));
    }

    #[test]
    fn validate_export_rejects_tampered_event_log() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-validate-4");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event1", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event2", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event3", "", None)
            .unwrap();

        let _original_data = provider.export_event_log_entries(&ctx_id_bytes).unwrap();
        let merkle_root = provider.merkle_root(&ctx_id_bytes).unwrap();

        // Tamper: remove one event from the entries.
        let mut entries = provider.entries(&ctx_id_bytes).unwrap();
        entries.remove(1);
        let tampered_data = rmp_serde::to_vec_named(&entries).unwrap();

        let snapshot = test_snapshot("ctx-validate-4");
        let export = ContextExport {
            snapshot,
            event_log_data: tampered_data,
            mls_state: Vec::new(),
            version: CURRENT_EXPORT_VERSION,
            exported_at: 1_000_000,
            exporter_did: DID::from("did:key:validator-4"),
            merkle_root,
            scope: ExportScope::Full,
            // Sign over the tampered contents so the signature check (step 2)
            // passes and validation reaches the Merkle chain check (step 3).
            snapshot_signature: [0u8; 64],
        };
        let signed = {
            let mut e = export;
            e.snapshot_signature =
                sign_with_test_key(&e.canonical_snapshot_hash().unwrap()).unwrap();
            e
        };

        let result = validate_export_for_import(&signed, &test_verifying_key());
        assert!(result.is_err());
        // The failure is the Merkle chain / root mismatch, NOT the signature.
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("Merkle") || err_msg.contains("chain"),
            "expected Merkle failure, got: {err_msg}"
        );
    }

    // -------------------------------------------------------------------
    // Export scope tests
    // -------------------------------------------------------------------

    #[test]
    fn public_export_strips_sensitive_data() {
        let snapshot = test_snapshot("ctx-public-1");
        let export = create_export(
            snapshot,
            Vec::new(),
            vec![1, 2, 3],
            DID::from("did:key:public-1"),
            ExportScope::Public,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        assert_eq!(export.scope, ExportScope::Public);
        assert!(export.event_log_data.is_empty());
        assert!(export.mls_state.is_empty());
        assert_eq!(export.merkle_root, [0u8; 32]);
        assert_eq!(export.snapshot.context_id, "ctx-public-1");
        // Membership should be empty.
        assert_eq!(export.snapshot.membership.count(), 0);
    }

    #[test]
    fn full_export_includes_all_data() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-full-1");
        let event_log_data = create_event_log_data(&ctx_id_bytes, &["ContextCreated"]);

        let snapshot = test_snapshot("ctx-full-1");
        let export = create_export(
            snapshot,
            event_log_data,
            vec![0xFF],
            DID::from("did:key:full-1"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        assert_eq!(export.scope, ExportScope::Full);
        assert!(!export.event_log_data.is_empty());
        assert_eq!(export.mls_state, vec![0xFF]);
        assert_ne!(export.merkle_root, [0u8; 32]);
    }

    // -------------------------------------------------------------------
    // Integration: export -> serialize -> deserialize -> validate -> import
    // -------------------------------------------------------------------

    #[test]
    fn full_export_import_pipeline() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-pipeline-1");
        let event_log_data = create_event_log_data(
            &ctx_id_bytes,
            &[
                "ContextCreated",
                "MemberJoined",
                "RoleAssigned",
                "MessageSent",
                "ToolInvoked",
            ],
        );

        let snapshot = test_snapshot("ctx-pipeline-1");
        let export = create_export(
            snapshot,
            event_log_data,
            Vec::new(),
            DID::from("did:key:pipeline-1"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // Serialize to bytes.
        let bytes = serialize_export(&export).unwrap();
        assert!(!bytes.is_empty());

        // Deserialize back.
        let decoded = deserialize_export(&bytes).unwrap();

        // Validate for import (Merkle verification).
        validate_export_for_import(&decoded, &test_verifying_key()).unwrap();

        // All fields should match.
        assert_eq!(decoded.snapshot.context_id, "ctx-pipeline-1");
        assert_eq!(decoded.version, CURRENT_EXPORT_VERSION);
        assert_eq!(decoded.merkle_root, export.merkle_root);
    }

    #[test]
    fn current_version_import_succeeds_legacy_and_future_versions_fail() {
        let snapshot = test_snapshot("ctx-version-test");
        let export_current = create_export(
            snapshot,
            Vec::new(),
            Vec::new(),
            DID::from("did:key:version-test"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();
        assert_eq!(export_current.version, CURRENT_EXPORT_VERSION);
        validate_export_for_import(&export_current, &test_verifying_key()).unwrap();

        // Legacy v1 exports (unsigned) are rejected with a DISTINCT version
        // error — never reaching the signature check — because they carry no
        // integrity-protected snapshot.
        let mut export_v1 = export_current.clone();
        export_v1.version = 1;
        let v1_err = validate_export_for_import(&export_v1, &test_verifying_key())
            .expect_err("v1 export must be rejected");
        let v1_msg = format!("{v1_err}");
        assert!(
            v1_msg.contains("unsupported export version"),
            "v1 must fail at version gate, got: {v1_msg}"
        );
        assert!(
            !matches!(v1_err, ContextError::SnapshotSignatureInvalid { .. }),
            "v1 rejection must be a version error, not a signature error"
        );

        // Future versions are likewise rejected at the version gate.
        let mut export_v99 = export_current;
        export_v99.version = 99;
        let v99_err = validate_export_for_import(&export_v99, &test_verifying_key())
            .expect_err("v99 export must be rejected");
        assert!(format!("{v99_err}").contains("unsupported export version"));
    }

    // -------------------------------------------------------------------
    // Event log provider round-trip
    // -------------------------------------------------------------------

    #[test]
    fn event_log_export_import_roundtrip() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-el-roundtrip");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event1", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event2", "", None)
            .unwrap();
        provider
            .append_event(&ctx_id_bytes, "Event3", "", None)
            .unwrap();

        let original_entries = provider.entries(&ctx_id_bytes).unwrap();
        let original_root = provider.merkle_root(&ctx_id_bytes).unwrap();

        // Export the event log.
        let data = provider.export_event_log_entries(&ctx_id_bytes).unwrap();

        // Import into a fresh provider.
        let new_provider = MerkleEventLogProvider::new();
        new_provider
            .import_event_log_entries(&ctx_id_bytes, &data)
            .unwrap();

        let imported_entries = new_provider.entries(&ctx_id_bytes).unwrap();
        let imported_root = new_provider.merkle_root(&ctx_id_bytes).unwrap();

        assert_eq!(imported_entries.len(), original_entries.len());
        assert_eq!(imported_root, original_root);

        for (orig, imported) in original_entries.iter().zip(imported_entries.iter()) {
            assert_eq!(orig.event, imported.event);
            assert_eq!(orig.timestamp, imported.timestamp);
            assert_eq!(orig.prev_hash, imported.prev_hash);
            assert_eq!(orig.hash, imported.hash);
        }

        // The imported log should verify.
        assert!(new_provider.verify_chain(&ctx_id_bytes));
    }

    // -------------------------------------------------------------------
    // Pruned event log round-trip (#705)
    // -------------------------------------------------------------------

    #[test]
    fn pruned_event_log_export_import_roundtrip() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-prune-roundtrip");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        for i in 0..10 {
            provider
                .append_event(&ctx_id_bytes, &format!("Event{i}"), "", None)
                .unwrap();
        }

        // Prune, keeping only the last 3 entries.
        let removed = provider.prune_event_log(&ctx_id_bytes, 3).unwrap();
        assert_eq!(removed, 7);

        let entries = provider.entries(&ctx_id_bytes).unwrap();
        assert_eq!(entries.len(), 3);
        // First remaining entry's prev_hash is NOT the genesis sentinel.
        assert_ne!(entries[0].prev_hash, [0u8; 32]);

        // Export the pruned event log.
        let data = provider.export_event_log_entries(&ctx_id_bytes).unwrap();
        let merkle_root = provider.merkle_root(&ctx_id_bytes).unwrap();

        // verify_merkle_chain must accept the pruned log.
        let computed_root = verify_merkle_chain(&data).unwrap();
        assert_eq!(computed_root, merkle_root);

        // Full export/import pipeline with pruned data.
        let snapshot = test_snapshot("ctx-prune-roundtrip");
        let export = create_export(
            snapshot,
            data.clone(),
            Vec::new(),
            DID::from("did:key:prune-test"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        let bytes = serialize_export(&export).unwrap();
        let decoded = deserialize_export(&bytes).unwrap();
        validate_export_for_import(&decoded, &test_verifying_key()).unwrap();

        // Import into a fresh provider and verify chain integrity.
        let new_provider = MerkleEventLogProvider::new();
        new_provider
            .import_event_log_entries(&ctx_id_bytes, &data)
            .unwrap();

        let imported_entries = new_provider.entries(&ctx_id_bytes).unwrap();
        assert_eq!(imported_entries.len(), 3);
        assert_eq!(imported_entries[0].event, "Event7");
        assert!(new_provider.verify_chain(&ctx_id_bytes));

        // Appending after import should chain correctly.
        new_provider
            .append_event(&ctx_id_bytes, "Event10", "", None)
            .unwrap();
        let final_entries = new_provider.entries(&ctx_id_bytes).unwrap();
        assert_eq!(final_entries.len(), 4);
        assert_eq!(final_entries[3].prev_hash, final_entries[2].hash);
        assert!(new_provider.verify_chain(&ctx_id_bytes));
    }
}
