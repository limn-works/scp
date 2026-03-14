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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::ContextError;
use super::manager::ContextSnapshot;
use crate::store::StoredValue;
use scp_identity::DID;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current version of the context export format.
///
/// Incremented when the export format changes in a backward-incompatible way.
/// Import rejects exports with `version > CURRENT_EXPORT_VERSION`.
pub const CURRENT_EXPORT_VERSION: u32 = 1;

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
        let expected_hash = compute_entry_hash(&entry.event, entry.timestamp, &entry.prev_hash);
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
/// Hash input: `"SCP-EXPORT-ENTRY-V1:" || event_bytes || timestamp_be_bytes || prev_hash`
///
/// Uses big-endian for the timestamp to match codebase convention, and a
/// domain separator to prevent cross-protocol hash confusion.
///
/// This must be identical to
/// [`providers::event_log::compute_entry_hash`](super::providers::event_log)
/// to ensure verification produces the same hashes.
fn compute_entry_hash(event: &str, timestamp: u64, prev_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-EXPORT-ENTRY-V1:");
    hasher.update(event.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(prev_hash);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Validates a [`ContextExport`] for import readiness.
///
/// Checks:
/// 1. Export version is supported (`<= CURRENT_EXPORT_VERSION`).
/// 2. Merkle chain integrity of event log entries.
/// 3. Merkle root matches the stored root hash.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] with a descriptive message
/// if any validation check fails.
pub fn validate_export_for_import(export: &ContextExport) -> Result<(), ContextError> {
    // 1. Version check.
    if export.version > CURRENT_EXPORT_VERSION {
        return Err(ContextError::EventLogFailed(format!(
            "unsupported export version: {}, maximum supported: {CURRENT_EXPORT_VERSION}",
            export.version
        )));
    }

    // 2. Merkle chain verification.
    let computed_root = verify_merkle_chain(&export.event_log_data)?;

    // 3. Root hash comparison (constant-time to avoid timing side-channels).
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
    use super::membership::MembershipState;
    use super::roles::{ContextRoleState, default_ceiling};
    use std::collections::{HashMap, HashSet};

    // Build a minimal role state with only the default ceiling.
    // Use the snapshot's context_id and an empty creator DID.
    let ceiling = default_ceiling();
    let role_state = ContextRoleState::new(&snapshot.context_id, "", ceiling, Vec::new())
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
        write_revoked_members: HashSet::new(),
        read_revoked_members: HashSet::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
        economic_policy: snapshot.economic_policy.clone(),
        budget_tracker: crate::economy::budget::MemberBudgetTracker::new(),
        approved_proposals: HashMap::new(),
        governance_freeze: None,
        pending_ceiling_modification: None,
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
    }
}

/// Creates a [`ContextExport`] from a snapshot and event log data.
///
/// For [`ExportScope::Full`], includes all data. For [`ExportScope::Public`],
/// strips sensitive data from the snapshot and omits event log entries.
///
/// # Errors
///
/// Returns [`ContextError`] if Merkle root computation fails.
pub fn create_export(
    snapshot: ContextSnapshot,
    event_log_data: Vec<u8>,
    mls_state: Vec<u8>,
    exporter_did: DID,
    scope: ExportScope,
) -> Result<ContextExport, ContextError> {
    let exported_at = crate::time::now_secs().map_err(|e| {
        ContextError::EventLogFailed(format!("failed to get current timestamp: {e}"))
    })?;

    match scope {
        ExportScope::Full => {
            let merkle_root = verify_merkle_chain(&event_log_data)?;
            Ok(ContextExport {
                snapshot,
                event_log_data,
                mls_state,
                version: CURRENT_EXPORT_VERSION,
                exported_at,
                exporter_did,
                merkle_root,
                scope,
            })
        }
        ExportScope::Public => {
            let stripped = strip_snapshot_for_public(&snapshot);
            Ok(ContextExport {
                snapshot: stripped,
                event_log_data: Vec::new(),
                mls_state: Vec::new(),
                version: CURRENT_EXPORT_VERSION,
                exported_at,
                exporter_did,
                merkle_root: [0u8; 32],
                scope,
            })
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
    use crate::context::ContextState;
    use crate::context::builder::ContextEventLogProvider;
    use crate::context::membership::MembershipState;
    use crate::context::params::ContextParams;
    use crate::context::providers::event_log::MerkleEventLogProvider;
    use crate::context::roles::{ContextRoleState, default_ceiling};
    use std::collections::{HashMap, HashSet};

    /// Helper to build a test snapshot.
    fn test_snapshot(context_id: &str) -> ContextSnapshot {
        let ceiling = default_ceiling();
        let role_state =
            ContextRoleState::new(context_id, "did:key:test-creator", ceiling, vec![]).unwrap();

        ContextSnapshot {
            context_id: context_id.to_owned(),
            state: ContextState::Active,
            context_params: ContextParams::default(),
            membership: MembershipState::new(),
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: crate::economy::budget::MemberBudgetTracker::new(),
            read_revoked_members: HashSet::new(),
            read_exclusion_list: HashSet::new(),
            approved_proposals: HashMap::new(),
            governance_freeze: None,
            pending_ceiling_modification: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: false,
            mls_crypto_state: Vec::new(),
        }
    }

    /// Helper to create event log entries via the provider.
    fn create_event_log_data(context_id_bytes: &[u8; 32], event_names: &[&str]) -> Vec<u8> {
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(context_id_bytes).unwrap();
        for name in event_names {
            provider.append_event(context_id_bytes, name).unwrap();
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
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-roundtrip-2");
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
        )
        .unwrap();

        assert_ne!(export.merkle_root, [0u8; 32]);

        let bytes = serialize_export(&export).unwrap();
        let decoded = deserialize_export(&bytes).unwrap();

        assert_eq!(decoded.snapshot.context_id, "ctx-roundtrip-2");
        assert_eq!(decoded.merkle_root, export.merkle_root);
        assert_eq!(decoded.mls_state, vec![0xDE, 0xAD]);
        assert_eq!(decoded.version, 1);
        assert!(!decoded.event_log_data.is_empty());
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-roundtrip-3");
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
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-merkle-1");
        let data = create_event_log_data(
            &ctx_id_bytes,
            &["ContextCreated", "MemberJoined", "MessageSent"],
        );

        let root = verify_merkle_chain(&data).unwrap();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn verify_merkle_chain_detects_tampered_hash() {
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-merkle-2");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        provider.append_event(&ctx_id_bytes, "Event1").unwrap();
        provider.append_event(&ctx_id_bytes, "Event2").unwrap();

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
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-merkle-3");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        provider.append_event(&ctx_id_bytes, "Event1").unwrap();
        provider.append_event(&ctx_id_bytes, "Event2").unwrap();
        provider.append_event(&ctx_id_bytes, "Event3").unwrap();

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
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-validate-1");
        let event_log_data =
            create_event_log_data(&ctx_id_bytes, &["ContextCreated", "MemberJoined"]);

        let snapshot = test_snapshot("ctx-validate-1");
        let export = create_export(
            snapshot,
            event_log_data,
            Vec::new(),
            DID::from("did:key:validator-1"),
            ExportScope::Full,
        )
        .unwrap();

        validate_export_for_import(&export).unwrap();
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
        };

        let result = validate_export_for_import(&export);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unsupported export version"));
    }

    #[test]
    fn validate_export_rejects_merkle_root_mismatch() {
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-validate-3");
        let event_log_data =
            create_event_log_data(&ctx_id_bytes, &["ContextCreated", "MemberJoined"]);

        let snapshot = test_snapshot("ctx-validate-3");
        let mut export = create_export(
            snapshot,
            event_log_data,
            Vec::new(),
            DID::from("did:key:validator-3"),
            ExportScope::Full,
        )
        .unwrap();

        // Tamper with the Merkle root.
        export.merkle_root = [0xAB; 32];

        let result = validate_export_for_import(&export);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Merkle root mismatch"));
    }

    #[test]
    fn validate_export_rejects_tampered_event_log() {
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-validate-4");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        provider.append_event(&ctx_id_bytes, "Event1").unwrap();
        provider.append_event(&ctx_id_bytes, "Event2").unwrap();
        provider.append_event(&ctx_id_bytes, "Event3").unwrap();

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
        };

        let result = validate_export_for_import(&export);
        assert!(result.is_err());
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
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-full-1");
        let event_log_data = create_event_log_data(&ctx_id_bytes, &["ContextCreated"]);

        let snapshot = test_snapshot("ctx-full-1");
        let export = create_export(
            snapshot,
            event_log_data,
            vec![0xFF],
            DID::from("did:key:full-1"),
            ExportScope::Full,
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
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-pipeline-1");
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
        )
        .unwrap();

        // Serialize to bytes.
        let bytes = serialize_export(&export).unwrap();
        assert!(!bytes.is_empty());

        // Deserialize back.
        let decoded = deserialize_export(&bytes).unwrap();

        // Validate for import (Merkle verification).
        validate_export_for_import(&decoded).unwrap();

        // All fields should match.
        assert_eq!(decoded.snapshot.context_id, "ctx-pipeline-1");
        assert_eq!(decoded.version, CURRENT_EXPORT_VERSION);
        assert_eq!(decoded.merkle_root, export.merkle_root);
    }

    #[test]
    fn export_version_1_import_succeeds_version_99_fails() {
        let snapshot = test_snapshot("ctx-version-test");
        let export_v1 = create_export(
            snapshot.clone(),
            Vec::new(),
            Vec::new(),
            DID::from("did:key:version-test"),
            ExportScope::Full,
        )
        .unwrap();
        assert_eq!(export_v1.version, 1);
        validate_export_for_import(&export_v1).unwrap();

        let export_v99 = ContextExport {
            snapshot,
            event_log_data: Vec::new(),
            mls_state: Vec::new(),
            version: 99,
            exported_at: 1_000_000,
            exporter_did: DID::from("did:key:version-test"),
            merkle_root: [0u8; 32],
            scope: ExportScope::Full,
        };
        let result = validate_export_for_import(&export_v99);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // Event log provider round-trip
    // -------------------------------------------------------------------

    #[test]
    fn event_log_export_import_roundtrip() {
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-el-roundtrip");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        provider.append_event(&ctx_id_bytes, "Event1").unwrap();
        provider.append_event(&ctx_id_bytes, "Event2").unwrap();
        provider.append_event(&ctx_id_bytes, "Event3").unwrap();

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
        let ctx_id_bytes = crate::context::context_id_bytes("ctx-prune-roundtrip");
        let provider = MerkleEventLogProvider::new();
        provider.init_event_log(&ctx_id_bytes).unwrap();
        for i in 0..10 {
            provider
                .append_event(&ctx_id_bytes, &format!("Event{i}"))
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
        )
        .unwrap();

        let bytes = serialize_export(&export).unwrap();
        let decoded = deserialize_export(&bytes).unwrap();
        validate_export_for_import(&decoded).unwrap();

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
        new_provider.append_event(&ctx_id_bytes, "Event10").unwrap();
        let final_entries = new_provider.entries(&ctx_id_bytes).unwrap();
        assert_eq!(final_entries.len(), 4);
        assert_eq!(final_entries[3].prev_hash, final_entries[2].hash);
        assert!(new_provider.verify_chain(&ctx_id_bytes));
    }
}
