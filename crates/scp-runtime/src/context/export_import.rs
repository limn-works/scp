//! Context export/import with `MessagePack` serialization and Merkle verification.
//!
//! Provides [`ContextExport`] for serializing context state (the signed
//! snapshot plus the event log) into a portable, versioned format using
//! `MessagePack` with [`StoredValue<T>`](crate::store::StoredValue) envelopes
//! (spec §17.5).
//!
//! Portable exports currently omit live MLS crypto state: the signed snapshot
//! carries `mls_crypto_state` on the persistence/restore path, but the portable
//! export path leaves it empty. Whether portable export should include MLS
//! crypto state is an open design decision (security tradeoff).
//!
//! Import verifies Merkle chain integrity of the event log entries before
//! restoring context state, ensuring tamper detection.
//!
//! See GitHub issue #363.

use scp_primitives::Clock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::state::ContextSnapshot;
use crate::store::StoredValue;
use scp_identity::DID;
use scp_protocol::context::ContextError;

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
/// - `2`: signed export over an **enumerated subset** of the snapshot
///   (membership / role-definitions / params / tool-names + Merkle root +
///   exporter DID + version), the §23.16.4 sync-delta hash recipe.
///   **Rejected on import** — the subset left the trusted governance,
///   economic, access-key, and ceiling fields that `import_context` restores
///   verbatim *unsigned*, so a tampered v2 export could forge them under a
///   valid signature (ADR-050). Distinguished from a signature failure by the
///   dedicated `version` error.
/// - `3`: signed export over the **full canonical snapshot**. The embedded
///   snapshot is covered by `snapshot_signature` (Ed25519 over
///   [`ContextExport::canonical_snapshot_hash`] =
///   `SHA-256("SCP-CONTEXT-EXPORT-V1:" || JCS(snapshot))`, the RFC 8785
///   canonical-JSON serialization of the *entire* [`ContextSnapshot`], per
///   spec §23.16.8). Produced by the exporter's custody key and verified on
///   import against the snapshot `creator_did`'s resolved verification-method
///   key (`#active`/`#agent`, ADR-039). Signing the whole snapshot is total
///   by construction: every field the importer trusts is in the preimage, so
///   no field is forgeable.
/// - `4`: signed export over the **full canonical snapshot** with the export
///   **scope discriminant** bound into the preimage. The digest is
///   `SHA-256("SCP-CONTEXT-EXPORT-V1:" || [scope.tag_byte()] || JCS(snapshot))`
///   (the single scope byte sits immediately after the domain separator and
///   before the JCS bytes, §23.16.8, ADR-050). v3 left the envelope `scope`
///   field unsigned, so a holder of a validly-signed `Public` export could flip
///   it to `Full`; binding the scope byte makes that tamper fail signature
///   verification by construction. SCP is pre-release with no deployed exports,
///   so v3 is **not** accepted on import — the correct end state ships directly.
///
/// # Relationship to the WASM export version
///
/// This native version line (`MessagePack`-encoded `StoredValue` payload) is
/// **intentionally independent** of the WASM bridge's `WASM_EXPORT_VERSION`
/// (JSON envelope, currently 5). The two serializations are disjoint and
/// mutually non-importable by construction (ADR-034): a WASM export fed to a
/// native bridge is rejected at the version gate, never silently parsed. The
/// two numbers are therefore **not** expected to match and must **not** be
/// "reconciled" — only the signing construction converges, not the bytes.
pub const CURRENT_EXPORT_VERSION: u32 = 4;

/// Maximum accepted serialized byte length of an incoming `ContextExport`
/// envelope, enforced before any deserialization or canonical hashing.
///
/// An imported export is fully attacker-controlled: [`deserialize_export`]
/// runs `rmp_serde::from_slice` over it, and
/// [`validate_export_for_import`] then runs RFC 8785 JCS canonicalization
/// (with per-element re-canonicalization of every set/map-backed field, see
/// `scp_protocol::serde_util::serde_sorted_set`) over the *entire* snapshot
/// to recompute the signed digest — all of this work happens BEFORE the
/// cheap Ed25519 signature check can reject a forgery. Without a length
/// bound, an attacker can submit a small-but-pathological or simply enormous
/// blob and force unbounded allocation plus an `O(n*m*log n)` canonicalization
/// amplifier on bytes that will be rejected anyway. Capping the raw length
/// first makes the parse-and-hash cost bounded and fails closed.
///
/// The value is deliberately generous: a `ContextExport` aggregates the full
/// context snapshot (the snapshot's `mls_crypto_state` field is empty on the
/// portable export path, but may carry the MLS group blob on the
/// persistence/restore path) and the entire serialized event log, so
/// legitimate exports of large, long-lived contexts must fit.
/// 64 MiB is far above any realistic single-context export while still
/// bounding the pre-verification work to a constant. Mirrors the
/// pre-deserialization size-check pattern used for inner envelopes
/// (`scp_protocol::serde_util::MAX_ENVELOPE_SIZE`, see
/// `crate::envelope::outer::ops`).
pub const MAX_CONTEXT_EXPORT_BYTES: usize = 64 * 1024 * 1024;

/// Domain separator for the Tier-2 sync-delta `ContextSnapshot` hash (§23.16.4).
///
/// Registered in spec §9.18.2: prefixed (no separator byte) to the canonical
/// bytes of the sync-delta snapshot before the SHA-256 digest. This is the
/// single source of truth for the literal; [`crate::sync::days_offline`]
/// re-exports this constant (rather than keeping an independent copy).
///
/// NOTE: this separator governs the §23.16.4 *sync-delta* hash ONLY. The
/// §23.16.8 signed-export hash uses its OWN separator
/// [`CONTEXT_EXPORT_DOMAIN_SEPARATOR`] so that an export signature can never be
/// confused with a sync-delta signature — both are Ed25519 under the same
/// creator key, so cross-protocol domain separation is enforced at the
/// preimage prefix rather than relying on the post-domain encodings staying
/// disjoint.
pub const CONTEXT_SNAPSHOT_DOMAIN_SEPARATOR: &str = "SCP-CONTEXT-SNAPSHOT-V1:";

/// Domain separator for the signed `ContextExport` snapshot hash (§23.16.8).
///
/// Registered in spec §9.18.2 and used by [`ContextExport::canonical_snapshot_hash`]:
/// prefixed (no separator byte) to the JCS bytes of the snapshot before the
/// SHA-256 digest. This is the single source of truth for the literal; the WASM
/// reference bridge (`crates/scp-ffi/wasm/src/manager.rs`) uses the same literal.
///
/// This is deliberately DISTINCT from [`CONTEXT_SNAPSHOT_DOMAIN_SEPARATOR`] (the
/// §23.16.4 sync-delta separator). Both the signed-export digest and the
/// sync-delta digest are Ed25519-signed under the same creator key, so they MUST
/// be domain-separated at the hash preimage to prevent cross-protocol signature
/// confusion — an export signature must never verify as a sync-delta signature
/// or vice versa, regardless of how the two post-domain encodings evolve.
pub const CONTEXT_EXPORT_DOMAIN_SEPARATOR: &str = "SCP-CONTEXT-EXPORT-V1:";

// ---------------------------------------------------------------------------
// ContextExport
// ---------------------------------------------------------------------------

/// Portable representation of a context's full state.
///
/// Serialized as `MessagePack` with a [`StoredValue<T>`] version envelope per
/// spec §17.5. Contains the context snapshot (membership, roles, governance,
/// TTL, broadcast state) plus serialized event log entries. The signed
/// `snapshot.mls_crypto_state` group blob is empty on the portable export
/// path; it is populated only on the persistence/restore path. Whether
/// portable export should include MLS crypto state is an open design decision
/// (security tradeoff).
///
/// # Signed vs. unsigned fields (ADR-050)
///
/// The Ed25519 `snapshot_signature` covers the **entire** embedded
/// [`ContextSnapshot`] via `SHA-256(domain || scope-tag-byte || JCS(snapshot))`.
/// Every value the
/// importer restores into authoritative state MUST live inside that signed
/// preimage — there are NO unsigned blobs that the importer reads into state.
/// In particular, MLS crypto state restored on import comes from the **signed**
/// `snapshot.mls_crypto_state` field, not from any envelope blob (the former
/// unsigned `mls_state` envelope field was removed precisely because it was an
/// attacker-controlled surface the importer would have restored verbatim).
///
/// The remaining envelope-level fields are **not** part of the signed preimage,
/// and each is safe because the importer never derives authoritative state from
/// it:
///
/// - `version` — gated by [`validate_export_for_import`] step 1 (must equal
///   [`CURRENT_EXPORT_VERSION`]); a tampered value is rejected, not trusted.
/// - `exporter_did` — cross-checked against the signed
///   `snapshot.role_state.creator_did` (step 2); a mismatch is rejected, and
///   the verifying key is resolved from the signed `creator_did`, never from
///   this field.
/// - `merkle_root` — defense-in-depth only; step 6 requires it to equal the
///   **signed** `snapshot.event_log_merkle_root`, and the authoritative event-
///   log binding (step 5) compares the recomputed root to the signed value.
/// - `scope` — the export-scope discriminant is now bound INTO the signed
///   preimage (via [`ExportScope::tag_byte`], placed immediately after the
///   domain separator and before the JCS bytes), so ANY scope flip changes the
///   recomputed digest and fails `verify_strict` by construction — the importer
///   no longer relies on the older "hollow-context" argument. The importer also
///   does not derive authoritative state from this tag (it restores whatever the
///   signed snapshot actually contains), and [`validate_export_for_import`]
///   additionally REJECTS any export whose `scope` is not [`ExportScope::Full`]
///   (see `import_context`): a non-`Full` (e.g. [`ExportScope::Public`]) snapshot
///   has had member list, governance, and event log stripped, so importing it
///   would silently install a hollow context. That Full-only check is a separate
///   import-orchestration policy, distinct from the signature binding above.
/// - `exported_at` — informational timestamp; the importer reads no state from
///   it.
///
/// # Merkle Verification
///
/// On import, the Merkle chain of `event_log_data` is verified: each entry's
/// `prev_hash` must match the preceding entry's `hash`, and each entry's
/// `hash` must be correctly computed. The recomputed Merkle root is compared
/// (constant-time) against the SIGNED `snapshot.event_log_merkle_root`; the
/// unsigned envelope `merkle_root` is an observability mirror cross-checked for
/// agreement (defense in depth).
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
    /// Export format version. Import rejects versions above
    /// [`CURRENT_EXPORT_VERSION`].
    pub version: u32,
    /// Unix timestamp (seconds) when the export was created.
    ///
    /// **Informational only — NOT load-bearing for replay protection.** This is
    /// an unsigned envelope field; the importer derives no authoritative state
    /// or freshness decision from it. Replay/rollback is guarded by the §23.17
    /// sequence-floor invariants over the **signed** snapshot (e.g. `mls_epoch`
    /// and per-sender monotonic counters), not by this timestamp. A future
    /// reviewer must not mistake `exported_at` for a freshness control.
    pub exported_at: u64,
    /// DID of the identity that performed the export.
    pub exporter_did: DID,
    /// Merkle root hash of the event log at export time.
    /// All zeros if the event log is empty or not included.
    pub merkle_root: [u8; 32],
    /// The scope of data included in this export.
    pub scope: ExportScope,
    /// Ed25519 signature over [`ContextExport::canonical_snapshot_hash`],
    /// produced by the exporter's custody key (spec §23.16.8).
    ///
    /// Covers the **entire** embedded [`ContextSnapshot`] via
    /// `SHA-256("SCP-CONTEXT-EXPORT-V1:" || [scope.tag_byte()] || JCS(snapshot))`,
    /// so every field
    /// the importer restores verbatim (membership, roles, ceiling, governance,
    /// economic policy, access-key store, consequence rules, …) is in the
    /// signed preimage and a tampered export is rejected on import. Verified
    /// against the snapshot `creator_did`'s resolved `#active`/`#agent`
    /// verification-method key (ADR-039).
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

impl ExportScope {
    /// Stable scope discriminant byte folded into the signed snapshot preimage
    /// (§23.16.8, ADR-050).
    ///
    /// The signed digest is
    /// `SHA-256(CONTEXT_EXPORT_DOMAIN_SEPARATOR || [self.tag_byte()] || JCS(snapshot))`
    /// (see [`ContextExport::canonical_snapshot_hash`]). Binding this byte into
    /// the preimage means a tampered envelope scope (e.g. a validly-signed
    /// `Public` export flipped to `Full`) makes the verifier recompute a
    /// different digest than the creator signed, so the signature fails by
    /// construction rather than by the hollow-context argument.
    ///
    /// The byte values are the shared
    /// [`scp_protocol::context::EXPORT_SCOPE_TAG_FULL`] /
    /// [`scp_protocol::context::EXPORT_SCOPE_TAG_PUBLIC`] constants, so the
    /// native runtime and the WASM reference bridge use the identical mapping.
    ///
    /// **MUST NEVER change once shipped:** the byte is part of the signed
    /// preimage; altering it would silently invalidate every previously
    /// produced export signature. New scopes take new, never-reused values.
    #[must_use]
    pub const fn tag_byte(self) -> u8 {
        match self {
            Self::Full => scp_protocol::context::EXPORT_SCOPE_TAG_FULL,
            Self::Public => scp_protocol::context::EXPORT_SCOPE_TAG_PUBLIC,
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical snapshot hash (spec §23.16.8)
// ---------------------------------------------------------------------------

impl ContextExport {
    /// Computes the canonical digest signed by the exporter and verified on
    /// import (spec §23.16.8).
    ///
    /// The digest is
    ///
    /// `SHA-256("SCP-CONTEXT-EXPORT-V1:" || [self.scope.tag_byte()] || JCS(self.snapshot))`
    ///
    /// The single [`ExportScope::tag_byte`] sits immediately after the domain
    /// separator and before the JCS snapshot bytes, binding the export scope
    /// (`Full` = `0x00`, `Public` = `0x01`) into the signed preimage so a
    /// tampered envelope scope fails verification by construction (ADR-050).
    ///
    /// where `JCS(self.snapshot)` is the RFC 8785 (JSON Canonicalization
    /// Scheme) canonical-JSON serialization of the **entire** embedded
    /// [`ContextSnapshot`] — every field, not a subset (ADR-050). The domain
    /// separator is prefixed to the snapshot bytes with no separator byte.
    /// This is the construction shared with the WASM reference bridge
    /// (`crates/scp-ffi/wasm/src/manager.rs`).
    ///
    /// Signing the whole snapshot is total by construction: every field the
    /// importer restores verbatim — membership, role definitions, ceiling,
    /// per-member and suspended capabilities, threshold set/value, governance
    /// model configuration, economic policy, consequence rules,
    /// read-exclusion list, access-key store, pending ceiling modification,
    /// and tool registrations — is in the signed preimage, so none of them is
    /// forgeable. The earlier v2 enumerated-subset recipe (§23.16.4) left
    /// those fields unsigned; it is no longer used for export.
    ///
    /// # Determinism
    ///
    /// RFC 8785 JCS canonicalizes JSON *object* member order (so every
    /// string-keyed `HashMap` in the snapshot is stable) but NOT *array*
    /// element order. Every set-derived field in the snapshot is therefore
    /// serialized in a deterministic, content-sorted order at the source: the
    /// `ContextSnapshot` fields `executed_proposals`, `read_exclusion_list`,
    /// and `approved_proposals` (hex-keyed so its `[u8; 32]` keys are valid
    /// JSON object keys), plus the `ContextRoleState` fields `members`,
    /// `member_capabilities`, and `suspended_capabilities`, plus
    /// `CapabilityCeiling::capabilities` and `RoleDefinition::capabilities`
    /// (reached via `role_state` and `context_params.roles`). See
    /// [`scp_protocol::serde_util`]. Producer ([`create_export`]) and verifier
    /// ([`validate_export_for_import`]) both call this method, so they always
    /// agree on the digest. Because the digest is computed over the *current*
    /// contents of `self.snapshot`, a `Public` export (whose snapshot has
    /// already been stripped) is signed and verified over the stripped bytes —
    /// the verifier sees exactly what was transmitted.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::SnapshotSignatureInvalid`] if the snapshot
    /// cannot be canonicalized to JCS (e.g. a non-string, non-hex map key).
    /// This cannot occur for a well-formed snapshot.
    pub fn canonical_snapshot_hash(&self) -> Result<[u8; 32], ContextError> {
        let snapshot_json = scp_protocol::jcs::to_vec(&self.snapshot).map_err(|e| {
            ContextError::SnapshotSignatureInvalid {
                reason: format!("snapshot canonical-JSON (JCS) serialization failed: {e}"),
            }
        })?;
        let mut hasher = Sha256::new();
        hasher.update(CONTEXT_EXPORT_DOMAIN_SEPARATOR.as_bytes());
        // Bind the export scope discriminant into the signed preimage
        // (§23.16.8, ADR-050). The single tag byte sits IMMEDIATELY after the
        // domain separator and BEFORE the JCS snapshot bytes. The verifier
        // sources `self.scope` from the received envelope, so flipping the
        // envelope scope (e.g. a validly-signed `Public` export rewritten to
        // `Full`) makes the recomputed digest diverge from the signed one and
        // the signature fails — the scope is no longer an unsigned field.
        hasher.update([self.scope.tag_byte()]);
        hasher.update(&snapshot_json);
        Ok(hasher.finalize().into())
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
    // Defense in depth: bound the attacker-controlled input length BEFORE
    // deserialization or canonical hashing. `import_context` later runs JCS
    // canonicalization over the whole snapshot to recompute the signed digest
    // (an O(n*m*log n) amplifier with per-element re-canonicalization of every
    // set/map field) before the cheap signature check can reject a forgery, so
    // an unbounded blob is a DoS amplifier. Reject oversized inputs up front,
    // failing closed with the same version/validation error class the rest of
    // this path uses (no new SCP code allocated). See [`MAX_CONTEXT_EXPORT_BYTES`].
    if bytes.len() > MAX_CONTEXT_EXPORT_BYTES {
        return Err(ContextError::EventLogFailed(format!(
            "context export too large: {} bytes exceeds maximum of {} bytes",
            bytes.len(),
            MAX_CONTEXT_EXPORT_BYTES
        )));
    }
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
    use scp_event_log::{Event, EventLog};

    if event_log_data.is_empty() {
        return Ok([0u8; 32]);
    }

    let entries: Vec<Event> = rmp_serde::from_slice(event_log_data).map_err(|e| {
        ContextError::EventLogFailed(format!(
            "failed to deserialize event log for verification: {e}"
        ))
    })?;

    if entries.is_empty() {
        return Ok(scp_event_log::tree::root(&EventLog::new(String::new())));
    }

    // Replay the events through the canonical substrate Merkle tree exactly as
    // exported (preserving each event's own sequence + prev_hash), so the
    // recomputed root is bit-identical to the root the exporter signed. The
    // context id is not authenticated by the chain, so a synthetic id hosts the
    // replay. `append_unsigned_event` validates each leaf's sequence and
    // prev_hash chain link (returning an error on any break), and `tree::root`
    // returns the RFC 6962 root committing to the full leaf sequence. This
    // mirrors `providers::event_log::rebuild_log_from_events`.
    let mut log = EventLog::new(String::new());
    for entry in &entries {
        scp_event_log::tree::append_unsigned_event(&mut log, entry).map_err(|e| {
            ContextError::EventLogFailed(format!(
                "Merkle chain broken at sequence {}: {e}",
                entry.sequence
            ))
        })?;
    }

    Ok(scp_event_log::tree::root(&log))
}

/// Validates a [`ContextExport`] for import readiness, including the
/// full-snapshot signature verification (spec §23.16.8).
///
/// Checks, in order:
/// 1. Export version is **exactly** [`CURRENT_EXPORT_VERSION`]. Versions below
///    it (the unsigned `1`, the enumerated-subset-signed `2`, and the
///    pre-scope-binding full-snapshot `3`) and any future version are rejected
///    with a distinct *version* error
///    ([`ContextError::ExportVersionUnsupported`], `SCP-CTX-2094`), because a
///    non-current export is not verifiable under the current signed
///    construction and MUST NOT be trusted. The version error is distinct from
///    the signature error (`SCP-CTX-2093`) so callers can tell "wrong format"
///    apart from "signature forged" (§17.5, §23.16.8).
/// 2. Signer binding (§23.16.8 step 2): the envelope's `exporter_did` MUST
///    equal the snapshot's `role_state.creator_did`. An export whose declared
///    exporter is not the snapshot creator is rejected with
///    [`ContextError::SnapshotSignatureInvalid`]. This binds the signing
///    authority to the creator identity and prevents a non-creator from
///    re-wrapping a snapshot under their own key. Checked before the
///    cryptographic verification so a mis-bound export is rejected regardless
///    of whether its signature happens to verify.
/// 3. Snapshot signature: the Ed25519 signature over
///    [`ContextExport::canonical_snapshot_hash`] =
///    `SHA-256(domain || scope-tag-byte || JCS(snapshot))` must verify
///    (`verify_strict`) against
///    `verifying_key` — the snapshot `creator_did`'s resolved
///    `#active`/`#agent` key (resolved by the caller, never from an
///    unauthenticated envelope field). Failure yields the distinct
///    [`ContextError::SnapshotSignatureInvalid`].
/// 4. Merkle chain integrity of event log entries.
/// 5. The recomputed event-log root matches the SIGNED
///    `snapshot.event_log_merkle_root` (the authoritative binding). A mismatch
///    yields the distinct `"signed snapshot root mismatch"` error.
/// 6. Defense in depth: the unsigned envelope `merkle_root` agrees with the
///    signed snapshot root. A mismatch yields the distinct
///    `"envelope merkle_root mismatch"` error (separate from step 5 so a test
///    can drive each independently).
///
/// Verification happens entirely before any caller reads a field of the
/// snapshot into authoritative state (the `lifecycle_helpers::import_context`
/// free function — reached via
/// [`Supervisor::import_context`](crate::context::supervisor::Supervisor::import_context) —
/// calls this first), preserving verify-before-restore (ADR-050). The
/// signature is checked before the Merkle chain so that an export with a
/// forged snapshot is rejected with the signature error regardless of whether
/// its event log happens to be internally consistent.
///
/// # Errors
///
/// - [`ContextError::EventLogFailed`] — unsupported/sub-current version,
///   broken Merkle chain, signed-snapshot root mismatch (step 5), or envelope
///   root mismatch (step 6).
/// - [`ContextError::SnapshotSignatureInvalid`] — `exporter_did` does not
///   match the snapshot `creator_did`, the snapshot could not be
///   canonicalized, or the signature does not authenticate the embedded
///   snapshot under `verifying_key`.
pub fn validate_export_for_import(
    export: &ContextExport,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ContextError> {
    // 1. Version check. Reject anything that is not the current signed format.
    // Pre-3 exports (unsigned v1, enumerated-subset-signed v2) and future
    // versions are all rejected here — distinct from a signature failure so
    // callers can tell "wrong format" apart from "signature forged".
    if export.version != CURRENT_EXPORT_VERSION {
        return Err(ContextError::ExportVersionUnsupported {
            reason: format!(
                "unsupported export version: {}, required: {CURRENT_EXPORT_VERSION} \
                 (versions below {CURRENT_EXPORT_VERSION} predate the current \
                 scope-bound full-snapshot signature and are rejected as \
                 unverifiable; this is a version error, distinct from a \
                 signature-verification failure)",
                export.version
            ),
        });
    }

    // 2. Signer binding (§23.16.8 step 2): exporter_did == creator_did. The
    // signing authority is bound to the snapshot creator; a non-creator
    // re-wrapping the snapshot under their own key is rejected here, before
    // the signature is checked.
    let creator_did = export.snapshot.role_state.creator_did.as_str();
    if export.exporter_did.as_ref() != creator_did {
        return Err(ContextError::SnapshotSignatureInvalid {
            reason: format!(
                "exporter_did ({}) does not match snapshot creator_did ({creator_did}); \
                 only the context creator may sign an export",
                export.exporter_did
            ),
        });
    }

    // 3. Snapshot signature verification (§23.16.8). Recompute the canonical
    // digest SHA-256(domain || scope-tag-byte || JCS(snapshot)) over the
    // received bytes and verify against the creator's resolved key.
    let hash = export.canonical_snapshot_hash()?;
    let signature = ed25519_dalek::Signature::from_bytes(&export.snapshot_signature);
    verifying_key
        .verify_strict(&hash, &signature)
        .map_err(|e| ContextError::SnapshotSignatureInvalid {
            reason: format!(
                "creator signature over snapshot did not verify (creator_did={creator_did}): {e}"
            ),
        })?;

    // 4. Merkle chain verification.
    let computed_root = verify_merkle_chain(&export.event_log_data)?;

    // 5. Root hash comparison against the SIGNED snapshot field
    //    (constant-time to avoid timing side-channels).
    //
    //    The authoritative root is `snapshot.event_log_merkle_root`, which is
    //    inside the signed preimage verified in step 3. Comparing the
    //    recomputed root to THIS value (not the unsigned envelope
    //    `export.merkle_root`) binds the event log to the creator's signature:
    //    an attacker holding a valid signed snapshot cannot substitute a
    //    different internally-consistent event log, because its recomputed
    //    root would not match the signed value. See §23.16.4 / §23.16.8.
    //
    //    Security scope: the signed root is the event-log hash-CHAIN HEAD, not
    //    a Merkle-tree commitment over all entries. `verify_merkle_chain` is
    //    pruning-tolerant (it does not validate entry[0].prev_hash), so a
    //    contiguous SUFFIX of the log (oldest entries dropped) verifies against
    //    the signed head. The signature thus attests that no entry was
    //    added/modified/reordered/forged and that the head is authentic, but
    //    NOT full-history completeness.
    //
    //    This is not audit-only: the imported pre-import entries are consumed by
    //    post-import enforcement — `event_log_entries_for_consequences` reads
    //    them as "Source 1" to drive consequence/participation/standing on the
    //    first live action. A front-truncated but valid-head log can thus lower
    //    consequence counts and suppress an auto-suspend/demote/ban for rules
    //    whose `window` exceeds the dropped entries' age (inert under the
    //    default 1-5 minute matrix windows, where the droppable entries are
    //    already out-of-window). A true cold-start for enforcement (imported
    //    history audit-only) is a planned hardening; until then front-truncation
    //    is not authoritative-state-neutral.
    if !bool::from(computed_root.ct_eq(&export.snapshot.event_log_merkle_root)) {
        return Err(ContextError::EventLogFailed(
            "signed snapshot root mismatch: recomputed event-log root does not \
             match the signed snapshot.event_log_merkle_root — event log data \
             may have been tampered with or substituted"
                .to_owned(),
        ));
    }

    // 6. Defense in depth: the unsigned envelope `merkle_root` must agree with
    //    the signed snapshot root. A mismatch indicates envelope tampering
    //    (the producer always sets them equal in `create_export`); reject it
    //    distinctly rather than silently trusting the signed value alone.
    if !bool::from(
        export
            .merkle_root
            .ct_eq(&export.snapshot.event_log_merkle_root),
    ) {
        return Err(ContextError::EventLogFailed(
            "envelope merkle_root mismatch: unsigned envelope merkle_root does \
             not match the signed snapshot root — export envelope may have been \
             tampered with"
                .to_owned(),
        ));
    }

    Ok(())
}

/// §9.10.4 misuse-resistance: verify the importer is a member of the exported
/// snapshot before its per-context pseudonym is derived.
///
/// Encrypted app-data routes to each member's per-member pseudonym routing ID.
/// If the importer is not in the snapshot's membership, the pseudonym it derives
/// addresses a routing ID no peer expects — leaving the importer silently
/// unaddressable rather than failing visibly. Reject loudly with the structural
/// import-rejection code (`SCP-CTX-2092`) instead. The snapshot creator is
/// itself a member, so a creator re-homing its own context passes this check.
///
/// Call AFTER [`validate_export_for_import`] (so the snapshot membership is
/// cryptographically authenticated) and BEFORE deriving the importer pseudonym.
///
/// # Errors
///
/// Returns [`ContextError::ImportRejected`] (canonical code `SCP-CTX-2092`) when
/// `importer_did` is not present in the snapshot's membership.
pub fn ensure_importer_is_member(
    snapshot: &ContextSnapshot,
    importer_did: &str,
) -> Result<(), ContextError> {
    if snapshot.membership.contains(importer_did) {
        Ok(())
    } else {
        Err(ContextError::ImportRejected {
            reason: format!(
                "importer '{importer_did}' is not a member of the exported context; \
                 only a member can re-home it and derive a routable pseudonym (§9.10.4)"
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// Public metadata stripping for ExportScope::Public
// ---------------------------------------------------------------------------

/// Strips sensitive data from a [`ContextSnapshot`] for a public export.
///
/// Retains only structural fields visible to pre-join observers (spec §5.7):
/// `context_id`, state, `context_params`, and empty/default values for
/// membership, `role_state`, and governance fields.
fn strip_snapshot_for_public(snapshot: &ContextSnapshot) -> Result<ContextSnapshot, ContextError> {
    use scp_protocol::context::membership::MembershipState;
    use scp_protocol::context::roles::{ContextRoleState, default_ceiling};
    use std::collections::{HashMap, HashSet};

    // Build a minimal role state with only the default ceiling.
    //
    // The real `creator_did` is RETAINED (not blanked): it is public
    // information — the root UCAN issuer, visible in the context's DID
    // document and role tokens — and the signed-export contract binds the
    // signer to `role_state.creator_did` (§23.16.8 step 2,
    // `exporter_did == creator_did`). Blanking it would break that binding for
    // public-scope exports and prevent the verifier from resolving the
    // signing key.
    let ceiling = default_ceiling();
    // Fail closed: if a minimal public role state cannot be constructed, return
    // the error rather than cloning the FULL role state (member_capabilities,
    // suspended, assignments) into a "public" export and leaking sensitive
    // membership/governance data to pre-join observers.
    let role_state = ContextRoleState::new(
        &snapshot.context_id,
        snapshot.role_state.creator_did.as_str(),
        ceiling,
        Vec::new(),
        &scp_primitives::SystemClock,
    )
    .map_err(|e| {
        ContextError::MembershipFailed(format!(
            "failed to build minimal public role state for export: {e}"
        ))
    })?;

    Ok(ContextSnapshot {
        context_id: snapshot.context_id.clone(),
        state: snapshot.state.clone(),
        context_params: snapshot.context_params.clone(),
        membership: MembershipState::new(),
        role_state,
        event_log_merkle_root: [0u8; 32],
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
        // Revoked spending-UCAN CIDs are internal governance state with no
        // meaning to a public observer (and could leak activity). Always empty
        // in public scope, like the nonce tracker.
        revoked_spending_ucan_cids: HashSet::new(),
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
        // §9.10.4: pseudonym state is local-instance routing state with no
        // meaning to a public observer. Redact to the no-pseudonym
        // `Broadcast` placeholder — it carries no routing secret. (Public
        // snapshots are never imported back into a live encrypted context, so
        // the routing axis is irrelevant here.)
        routing: crate::context::actor::state::ContextRouting::Broadcast,
        // ADR-049 §9: staged saga evidence is local-instance cross-context
        // coordination state with no authority on any other node. A foreign
        // saga must never drive a public importer's Commit/Abort, so it is
        // ALWAYS dropped from the public export.
        saga_pending: HashMap::new(),
        xctx_committed_outputs: HashMap::new(),
        xctx_committed_invocations: std::collections::HashSet::new(),
        // Caller-side reservation reversal records are local-instance economy
        // state with no authority on any other node — ALWAYS dropped from the
        // public export.
        xctx_caller_reservations: HashMap::new(),
        // B's freshness/replay cache has no authority on a foreign node and a
        // fresh node starts its own replay window — dropped from the export.
        xctx_nonce_dedup: HashMap::new(),
    })
}

/// Creates a signed [`ContextExport`] from a snapshot and event log data.
///
/// For [`ExportScope::Full`], includes all data. For [`ExportScope::Public`],
/// strips sensitive data from the snapshot and omits event log entries.
///
/// The export's [`ContextExport::canonical_snapshot_hash`] =
/// `SHA-256(domain || scope-tag-byte || JCS(snapshot))` is computed over the
/// **final** snapshot
/// (after public stripping) and passed to `sign`, which must return an Ed25519
/// signature produced by the exporter's custody key (spec §23.16.8). The
/// exporter MUST be the snapshot `creator_did` (the verifier enforces
/// `exporter_did == creator_did`). Signing happens at the FFI boundary because
/// the runtime holds no custody key — see the module-level architecture note.
///
/// # Errors
///
/// Returns [`ContextError`] if Merkle root computation fails, if canonical hash
/// construction fails, or if `sign` returns an error.
///
/// Crate-internal: the only producer is `Supervisor::export_context` (the
/// authoritative path FFI bridges reach through `Supervisor`). It is not part
/// of the FFI surface, so it carries no cross-layer export obligation.
pub(crate) fn create_export<F, E>(
    snapshot: ContextSnapshot,
    event_log_data: Vec<u8>,
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

    let (mut final_snapshot, event_log_data, merkle_root) = match scope {
        ExportScope::Full => {
            let merkle_root = verify_merkle_chain(&event_log_data)?;
            (snapshot, event_log_data, merkle_root)
        }
        ExportScope::Public => {
            let stripped = strip_snapshot_for_public(&snapshot)?;
            (stripped, Vec::new(), [0u8; 32])
        }
    };

    // Bind the event-log Merkle root INTO the signed snapshot (§23.16.4,
    // §23.16.8). The signature covers `JCS(snapshot)`, so writing the root
    // here puts it inside the signed preimage. Without this, the root lived
    // only on the (unsigned, attacker-controlled) `ContextExport` envelope,
    // letting a holder of a valid signed snapshot substitute a different
    // internally-consistent event log and have it accepted on import. The
    // importer recomputes the root over the received `event_log_data` and
    // compares it to this SIGNED value. Always `[0u8; 32]` for `Public`
    // (no event log included), matching `verify_merkle_chain(&[])`.
    final_snapshot.event_log_merkle_root = merkle_root;

    // Build the export with a placeholder signature so the canonical hash can
    // be computed over the exact bytes a verifier will recompute. The signature
    // field itself is NOT part of the hash (see `canonical_snapshot_hash`).
    let mut export = ContextExport {
        snapshot: final_snapshot,
        event_log_data,
        version: CURRENT_EXPORT_VERSION,
        exported_at,
        exporter_did,
        merkle_root,
        scope,
        snapshot_signature: [0u8; 64],
    };

    // SHA-256(domain || scope-tag-byte || JCS(snapshot)) over the final snapshot
    // bytes; the signature field is [0u8; 64] here and is NOT part of the hash (it lives
    // on the envelope, not the snapshot).
    let hash = export.canonical_snapshot_hash()?;

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

    /// The creator DID embedded in every [`test_snapshot`]. §23.16.8 requires
    /// `exporter_did == role_state.creator_did`, so exports built in these
    /// tests use this DID as the exporter unless a mismatch is being tested.
    const TEST_CREATOR_DID: &str = "did:key:test-creator";

    /// Helper to build a test snapshot.
    fn test_snapshot(context_id: &str) -> ContextSnapshot {
        let ceiling = default_ceiling();
        let role_state = ContextRoleState::new(
            context_id,
            TEST_CREATOR_DID,
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
            event_log_merkle_root: [0u8; 32],
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
            revoked_spending_ucan_cids: std::collections::HashSet::new(),
            pending_commits: std::collections::VecDeque::new(),
            commit_fault: None,
            checkpoint_events_since: 0,
            checkpoint_last_time_secs: 0,
            generation: 0,
            routing: crate::context::actor::state::ContextRouting::Broadcast,
            saga_pending: HashMap::new(),
            xctx_committed_outputs: HashMap::new(),
            xctx_committed_invocations: std::collections::HashSet::new(),
            // Caller-side reservation reversal records are local-instance
            // economy state — dropped from the export (no foreign authority).
            xctx_caller_reservations: HashMap::new(),
            // B's freshness/replay cache has no authority on a foreign node and
            // a fresh node starts its own replay window — dropped from export.
            xctx_nonce_dedup: HashMap::new(),
        }
    }

    #[test]
    fn ensure_importer_is_member_accepts_members_rejects_non_members() {
        use scp_identity::DID;

        let mut snapshot = test_snapshot("member-check-ctx");
        // A real snapshot carries the creator in its membership; mirror that, plus
        // a second ordinary member.
        snapshot.membership.add_member(
            DID(TEST_CREATOR_DID.to_owned()),
            "admin".to_owned(),
            vec![],
        );
        snapshot.membership.add_member(
            DID("did:key:alice".to_owned()),
            "member".to_owned(),
            vec![],
        );

        // An ordinary member is accepted.
        ensure_importer_is_member(&snapshot, "did:key:alice").expect("a member must be accepted");
        // The creator re-homing its own context is accepted (creator is a member).
        ensure_importer_is_member(&snapshot, TEST_CREATOR_DID)
            .expect("the creator (a member) must be accepted");

        // A non-member is rejected with the structural import-rejection error,
        // naming the offending DID — never a silent dead-pseudonym derivation.
        match ensure_importer_is_member(&snapshot, "did:key:mallory") {
            Err(ContextError::ImportRejected { reason }) => {
                assert!(reason.contains("not a member"), "reason: {reason}");
                assert!(reason.contains("did:key:mallory"), "reason: {reason}");
            }
            other => panic!("non-member import must be rejected, got {other:?}"),
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
    // Import size-cap (DoS hardening) tests
    // -------------------------------------------------------------------

    #[test]
    fn oversized_export_rejected_before_deserialization_and_hashing() {
        // A blob one byte over the cap must be rejected by the length guard
        // at the START of `deserialize_export`, BEFORE `rmp_serde::from_slice`
        // and before any canonical-snapshot hashing in the import path. The
        // bytes are not even valid MessagePack envelope content, so reaching
        // the deserializer would surface a different error; the cap path must
        // win first and fail closed.
        let oversized = vec![0u8; MAX_CONTEXT_EXPORT_BYTES + 1];
        let err = deserialize_export(&oversized).unwrap_err();
        match err {
            ContextError::EventLogFailed(msg) => {
                assert!(
                    msg.contains("too large"),
                    "expected size-cap rejection, got: {msg}"
                );
            }
            other => panic!("expected EventLogFailed size-cap error, got: {other:?}"),
        }
    }

    #[test]
    fn export_at_size_cap_boundary_passes_length_guard() {
        // A blob exactly AT the cap must pass the length guard (the guard
        // rejects strictly greater than the cap). It then fails in the
        // deserializer because the all-zero bytes are not a valid envelope —
        // proving the guard is `>`, not `>=`, and does not reject legitimate
        // maximum-size exports. We assert the error is NOT the size-cap error.
        let at_cap = vec![0u8; MAX_CONTEXT_EXPORT_BYTES];
        let err = deserialize_export(&at_cap).unwrap_err();
        match err {
            ContextError::EventLogFailed(msg) => {
                assert!(
                    !msg.contains("too large"),
                    "blob at the cap must pass the length guard, not trip it: {msg}"
                );
            }
            other => panic!("expected deserialization EventLogFailed, got: {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // §9.10.4 degraded-snapshot routing default (FIX 6b)
    // -------------------------------------------------------------------

    /// A `ContextSnapshot` persisted WITHOUT a `routing` field (pre-routing-
    /// field snapshots, or `strip_snapshot_for_public` redactions) deserializes
    /// with `routing == ContextRouting::Broadcast` via `default_context_routing`
    /// and `#[serde(default)]`. This is the placeholder the restore path then
    /// reconciles against the reconstructed mode (fail-closed for an encrypted
    /// context, fine for a broadcast one).
    #[test]
    fn snapshot_without_routing_field_defaults_to_broadcast() {
        let snapshot = test_snapshot("ctx-degraded-routing");
        // Round-trip through JSON and DELETE the `routing` key to simulate a
        // snapshot persisted before the field existed.
        let mut value = serde_json::to_value(&snapshot).expect("serialize snapshot");
        let obj = value.as_object_mut().expect("snapshot serializes as a map");
        assert!(
            obj.remove("routing").is_some(),
            "routing field present pre-strip"
        );

        let restored: ContextSnapshot =
            serde_json::from_value(value).expect("deserialize snapshot with routing omitted");
        assert!(
            restored.routing.is_broadcast(),
            "a snapshot missing the routing field must default to Broadcast (degraded placeholder)"
        );
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
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        let bytes = serialize_export(&export).unwrap();
        let decoded = deserialize_export(&bytes).unwrap();

        assert_eq!(decoded.snapshot.context_id, "ctx-roundtrip-1");
        assert_eq!(decoded.version, CURRENT_EXPORT_VERSION);
        assert_eq!(decoded.exporter_did.as_ref(), TEST_CREATOR_DID);
        assert_eq!(decoded.merkle_root, [0u8; 32]);
        assert!(decoded.event_log_data.is_empty());
        // MLS group state, when present, rides inside the signed snapshot
        // (`mls_crypto_state`), not on the envelope. The portable export path
        // currently leaves it empty (populated only on persistence/restore).
        assert!(decoded.snapshot.mls_crypto_state.is_empty());
    }

    #[test]
    fn roundtrip_export_with_events() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-roundtrip-2");
        let event_log_data = create_event_log_data(
            &ctx_id_bytes,
            &["ContextCreated", "MemberJoined", "MessageSent"],
        );

        let mut snapshot = test_snapshot("ctx-roundtrip-2");
        // MLS group state rides inside the SIGNED snapshot, not the envelope.
        // Populate it so the round-trip exercises the signed-blob path.
        snapshot.mls_crypto_state = vec![0xDE, 0xAD];
        let export = create_export(
            snapshot,
            event_log_data,
            DID::from(TEST_CREATOR_DID),
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
        assert_eq!(decoded.snapshot.mls_crypto_state, vec![0xDE, 0xAD]);
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
            DID::from(TEST_CREATOR_DID),
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
        assert_eq!(decoded.exporter_did.as_ref(), TEST_CREATOR_DID);
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
            DID::from(TEST_CREATOR_DID),
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
            version: 99,
            exported_at: 1_000_000,
            exporter_did: DID::from(TEST_CREATOR_DID),
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
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // Tamper with the UNSIGNED envelope Merkle root. Re-signing does not
        // help the attacker: the signed snapshot's `event_log_merkle_root`
        // still holds the true root, so the envelope/signed-snapshot agreement
        // check (step 6) rejects the mismatch. This isolates the root
        // comparison from the signature check (step 3).
        export.merkle_root = [0xAB; 32];
        export.snapshot_signature =
            sign_with_test_key(&export.canonical_snapshot_hash().unwrap()).unwrap();

        let result = validate_export_for_import(&export, &test_verifying_key());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        // Only the unsigned envelope root was tampered; the recomputed root
        // still matches the signed snapshot root (step 5 passes), so step 6
        // (envelope-vs-signed agreement) is the rejecting check.
        assert!(
            err_msg.contains("envelope merkle_root mismatch"),
            "expected step-6 envelope-root mismatch, got: {err_msg}"
        );
    }

    #[test]
    fn validate_export_rejects_substituted_event_log() {
        // The signature-coverage attack the signed merkle-root binding closes:
        // an attacker holds a VALID signed snapshot but swaps in a DIFFERENT,
        // internally-consistent event log (and matching envelope merkle_root).
        // Because the true root is bound into the SIGNED snapshot, the
        // recomputed root over the substituted log no longer matches the
        // signed value and the import is rejected — even though the substitute
        // log is itself a valid Merkle chain and the envelope merkle_root
        // matches it.
        let ctx_id = "ctx-validate-substitute";
        let ctx_id_bytes = scp_protocol::context::context_id_bytes(ctx_id);

        // Legitimate export over the real event log.
        let real_log = create_event_log_data(&ctx_id_bytes, &["ContextCreated", "MemberJoined"]);
        let export = create_export(
            test_snapshot(ctx_id),
            real_log,
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // Build a DIFFERENT but internally-consistent event log and its root.
        let substitute_log = create_event_log_data(&ctx_id_bytes, &["ContextCreated", "Evicted"]);
        let substitute_root = verify_merkle_chain(&substitute_log).unwrap();
        assert_ne!(
            substitute_root, export.snapshot.event_log_merkle_root,
            "substitute log must have a different root for the test to be meaningful"
        );

        // Attacker swaps the event log AND the envelope root to match it, but
        // CANNOT touch the signed snapshot field without invalidating the
        // creator signature.
        let mut attacked = export;
        attacked.event_log_data = substitute_log;
        attacked.merkle_root = substitute_root;

        let result = validate_export_for_import(&attacked, &test_verifying_key());
        assert!(result.is_err(), "substituted event log must be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        // The substitute log's root matches the (also-substituted) envelope
        // root, so step 6 would pass; the rejecting check is step 5, comparing
        // the recomputed root against the SIGNED snapshot root.
        assert!(
            err_msg.contains("signed snapshot root mismatch"),
            "expected step-5 signed-root mismatch, got: {err_msg}"
        );
    }

    /// Isolates step 5 (recomputed-root vs SIGNED `snapshot.event_log_merkle_root`)
    /// from step 6 (recomputed-root vs unsigned envelope `merkle_root`).
    ///
    /// Unlike [`validate_export_rejects_substituted_event_log`], which also
    /// rewrites the envelope `merkle_root`, this test mutates ONLY
    /// `event_log_data` and LEAVES the envelope `merkle_root` at its signed
    /// value. With the envelope root untouched, step 6's envelope-vs-signed
    /// comparison can never fire (both still equal the signed root); the ONLY
    /// check that can reject is step 5, comparing the recomputed root over the
    /// substituted log against the signed snapshot root. This is the test that
    /// would pass (false-negative) if step 5 were removed — a mutation check.
    #[test]
    fn validate_export_step5_rejects_event_log_with_envelope_root_untouched() {
        let ctx_id = "ctx-validate-step5-only";
        let ctx_id_bytes = scp_protocol::context::context_id_bytes(ctx_id);

        let real_log = create_event_log_data(&ctx_id_bytes, &["ContextCreated", "MemberJoined"]);
        let export = create_export(
            test_snapshot(ctx_id),
            real_log,
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // A different but internally-consistent event log.
        let substitute_log = create_event_log_data(&ctx_id_bytes, &["ContextCreated", "Evicted"]);
        let substitute_root = verify_merkle_chain(&substitute_log).unwrap();
        assert_ne!(
            substitute_root, export.snapshot.event_log_merkle_root,
            "substitute log must have a different root for the test to be meaningful"
        );

        // Swap ONLY the event log. The envelope `merkle_root` stays at the
        // signed value (it was set equal to the signed snapshot root by
        // `create_export`), so step 6 cannot fire — step 5 must catch this.
        let mut attacked = export;
        attacked.event_log_data = substitute_log;
        // Precondition: envelope root still equals the signed snapshot root.
        assert_eq!(
            attacked.merkle_root, attacked.snapshot.event_log_merkle_root,
            "envelope merkle_root must remain at the signed value for this to isolate step 5"
        );

        let result = validate_export_for_import(&attacked, &test_verifying_key());
        assert!(
            result.is_err(),
            "step 5 must reject the substituted event log"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("signed snapshot root mismatch"),
            "expected the step-5 message, got: {err_msg}"
        );
        // And NOT the step-6 message — proving step 5 is what fired.
        assert!(
            !err_msg.contains("envelope merkle_root mismatch"),
            "step 6 must not be the rejecting check here, got: {err_msg}"
        );
    }

    /// Regression guard for the signed/unsigned binding contract (ADR-050):
    /// mutating a genuinely-UNSIGNED envelope field on a validly-signed export
    /// must NOT change the validation outcome. `exported_at` is envelope-level
    /// and NOT in the signed preimage, so tampering it cannot forge acceptance
    /// OR cause spurious rejection. (The `scope` field is NO LONGER unsigned —
    /// it is bound into the signed preimage via [`ExportScope::tag_byte`], so a
    /// scope flip now fails verification; that is covered by the dedicated
    /// `tampered_scope_rejected_with_signature_error` test, not here.) This pins
    /// "no genuinely-unsigned envelope field affects authoritative state" — if a
    /// future change started deriving trusted state from `exported_at`, this
    /// test (or a sibling step) would need to fail it.
    #[test]
    fn mutating_unsigned_envelope_fields_does_not_change_validation() {
        let ctx_id = "ctx-unsigned-envelope-inert";
        let ctx_id_bytes = scp_protocol::context::context_id_bytes(ctx_id);
        let event_log_data = create_event_log_data(&ctx_id_bytes, &["ContextCreated"]);

        let export = create_export(
            test_snapshot(ctx_id),
            event_log_data,
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // Baseline: the untouched export validates.
        validate_export_for_import(&export, &test_verifying_key())
            .expect("baseline signed export must validate");

        // Mutate ONLY a genuinely-unsigned envelope field (not the signature,
        // not the snapshot, not the event log, not the cross-checked envelope
        // root, and NOT `scope` — `scope` is now in the signed preimage).
        let mut tampered = export.clone();
        tampered.exported_at = export.exported_at.wrapping_add(86_400);

        // Validation outcome is unchanged — the mutation is provably ignored.
        validate_export_for_import(&tampered, &test_verifying_key()).expect(
            "mutating the unsigned envelope field `exported_at` must NOT change \
             the validation outcome — it is not in the signed preimage and the \
             importer derives no authoritative state from it",
        );
    }

    /// Guards the `#[serde(with = "...")]` deterministic-set/map serialization
    /// of [`ContextSnapshot`] (`serde_sorted_set`, `serde_sorted_set_map`,
    /// `serde_hex_keyed_map_32`). The signed export digest is
    /// `SHA-256(domain || scope-tag-byte || JCS(snapshot))`; JCS fixes JSON
    /// *object* key order
    /// but NOT *array* element order, so any `HashSet`/`HashMap` snapshot field
    /// MUST be canonicalized at the source or the digest becomes
    /// non-deterministic across insertion orders / hasher seeds — silently
    /// breaking export signatures.
    ///
    /// This builds the same logical snapshot twice with set/map fields
    /// populated in OPPOSITE insertion orders (and distinct `HashMap`/`HashSet`
    /// instances) and asserts the canonical hash is BYTE-IDENTICAL. A future
    /// field-adder who forgets `#[serde(with = ...)]` on a new set/map snapshot
    /// field will fail this test.
    #[test]
    fn canonical_snapshot_hash_is_order_independent_for_sets_and_maps() {
        use scp_protocol::context::governance::{
            GovernanceAction, GovernanceProposal, ProposalId, ProposalStatus,
        };

        // Rebuilds a `HashSet` from its elements inserted in reverse order,
        // forcing a different iteration order while preserving identical
        // content.
        fn reinsert_reversed_set<T, S>(set: &mut HashSet<T, S>)
        where
            T: Eq + std::hash::Hash,
            S: std::hash::BuildHasher + Default,
        {
            let mut items: Vec<T> = std::mem::take(set).into_iter().collect();
            items.reverse();
            *set = items.into_iter().collect();
        }

        // Rebuilds a `HashMap` from its entries inserted in reverse order,
        // forcing a different iteration order while preserving identical
        // content.
        fn reinsert_reversed_map<K, V, S>(map: &mut HashMap<K, V, S>)
        where
            K: Eq + std::hash::Hash,
            S: std::hash::BuildHasher + Default,
        {
            let mut items: Vec<(K, V)> = std::mem::take(map).into_iter().collect();
            items.reverse();
            *map = items.into_iter().collect();
        }

        let prop_x: ProposalId = [0x11; 32];
        let prop_y: ProposalId = [0xEE; 32];
        let make_proposal = |id: ProposalId| GovernanceProposal {
            proposal_id: id,
            context_id: "ctx-determinism".to_owned(),
            proposer_did: DID::from("did:key:determinism-proposer"),
            action: GovernanceAction::RemoveMember {
                did: DID::from("did:key:determinism-target"),
                reason: None,
            },
            status: ProposalStatus::Approved,
            created_at: 0,
            voting_deadline: u64::MAX,
            approvals: vec![],
            rejections: vec![],
            created_at_epoch: Some(0),
        };

        // ONE base snapshot — production signs a single snapshot value, so the
        // guard compares that exact value against a structurally-identical copy
        // whose collection fields have been rebuilt in a different iteration
        // order. (Two independent `test_snapshot` constructions would differ on
        // genuinely per-build data and would not isolate ordering.)
        let mut base = test_snapshot("ctx-determinism");
        // executed_proposals: HashSet<ProposalId> (serde_sorted_set)
        base.executed_proposals.insert(prop_x);
        base.executed_proposals.insert(prop_y);
        // read_exclusion_list: HashSet<DID> (serde_sorted_set)
        base.read_exclusion_list
            .insert(DID::from("did:key:zzz-exclusion-a"));
        base.read_exclusion_list
            .insert(DID::from("did:key:aaa-exclusion-b"));
        // approved_proposals: HashMap<ProposalId, _> (serde_hex_keyed_map_32) —
        // extends coverage beyond the sibling set-only determinism test.
        base.approved_proposals
            .insert(prop_x, (make_proposal(prop_x), 1u64, 100u64));
        base.approved_proposals
            .insert(prop_y, (make_proposal(prop_y), 2u64, 200u64));

        // Structurally-identical copy with every set/map rebuilt in reverse
        // iteration order.
        let mut shuffled = base.clone();
        reinsert_reversed_set(&mut shuffled.executed_proposals);
        reinsert_reversed_set(&mut shuffled.read_exclusion_list);
        reinsert_reversed_map(&mut shuffled.approved_proposals);

        let hash_of = |snap: ContextSnapshot| -> [u8; 32] {
            let export = ContextExport {
                snapshot: snap,
                event_log_data: Vec::new(),
                version: CURRENT_EXPORT_VERSION,
                exported_at: 1_000_000,
                exporter_did: DID::from(TEST_CREATOR_DID),
                merkle_root: [0u8; 32],
                scope: ExportScope::Full,
                snapshot_signature: [0u8; 64],
            };
            export.canonical_snapshot_hash().unwrap()
        };

        assert_eq!(
            hash_of(base),
            hash_of(shuffled),
            "canonical snapshot hash must be byte-identical regardless of \
             set/map insertion order — a snapshot field is missing its \
             deterministic #[serde(with = ...)] canonicalizer"
        );
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
            version: CURRENT_EXPORT_VERSION,
            exported_at: 1_000_000,
            exporter_did: DID::from(TEST_CREATOR_DID),
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
        let mut snapshot = test_snapshot("ctx-public-1");
        // Sensitive MLS group state must NOT survive a public-scope export.
        snapshot.mls_crypto_state = vec![1, 2, 3];
        let export = create_export(
            snapshot,
            Vec::new(),
            DID::from(TEST_CREATOR_DID),
            ExportScope::Public,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        assert_eq!(export.scope, ExportScope::Public);
        assert!(export.event_log_data.is_empty());
        // Public scope strips the signed MLS group blob.
        assert!(export.snapshot.mls_crypto_state.is_empty());
        assert_eq!(export.merkle_root, [0u8; 32]);
        assert_eq!(export.snapshot.context_id, "ctx-public-1");
        // Membership should be empty.
        assert_eq!(export.snapshot.membership.count(), 0);
    }

    #[test]
    fn full_export_includes_all_data() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-full-1");
        let event_log_data = create_event_log_data(&ctx_id_bytes, &["ContextCreated"]);

        let mut snapshot = test_snapshot("ctx-full-1");
        // MLS group state rides inside the signed snapshot; full scope keeps it.
        snapshot.mls_crypto_state = vec![0xFF];
        let export = create_export(
            snapshot,
            event_log_data,
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        assert_eq!(export.scope, ExportScope::Full);
        assert!(!export.event_log_data.is_empty());
        assert_eq!(export.snapshot.mls_crypto_state, vec![0xFF]);
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
            DID::from(TEST_CREATOR_DID),
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
            DID::from(TEST_CREATOR_DID),
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
            v1_msg.contains("SCP-CTX-2094"),
            "v1 version-gate rejection must carry the dedicated version code, got: {v1_msg}"
        );
        assert!(
            matches!(v1_err, ContextError::ExportVersionUnsupported { .. }),
            "v1 rejection must be the dedicated version-gate variant, not a \
             signature/event-log error, got: {v1_err:?}"
        );

        // The pre-scope-binding full-snapshot format (v3) is also rejected at
        // the version gate — its signature does not cover the scope discriminant.
        let mut export_v3 = export_v1;
        export_v3.version = 3;
        let v3_err = validate_export_for_import(&export_v3, &test_verifying_key())
            .expect_err("v3 export must be rejected");
        assert!(
            matches!(v3_err, ContextError::ExportVersionUnsupported { .. }),
            "v3 rejection must be the dedicated version-gate variant, got: {v3_err:?}"
        );

        // Future versions are likewise rejected at the version gate.
        let mut export_v99 = export_current;
        export_v99.version = 99;
        let v99_err = validate_export_for_import(&export_v99, &test_verifying_key())
            .expect_err("v99 export must be rejected");
        assert!(format!("{v99_err}").contains("unsupported export version"));
        assert!(matches!(
            v99_err,
            ContextError::ExportVersionUnsupported { .. }
        ));
    }

    // -------------------------------------------------------------------
    // Snapshot signature tampering (spec §23.16.8)
    // -------------------------------------------------------------------

    /// Core security property: mutating the embedded snapshot's membership
    /// after signing causes import to be rejected with the *signature* error,
    /// distinct from the Merkle-chain error. This is the gap the signature
    /// closes — `validate_export_for_import` previously verified only the
    /// event-log Merkle chain, leaving membership/roles/params forgeable.
    #[test]
    fn tampered_membership_rejected_with_signature_error() {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes("ctx-tamper-membership");
        let event_log_data = create_event_log_data(&ctx_id_bytes, &["ContextCreated"]);

        let mut snapshot = test_snapshot("ctx-tamper-membership");
        // Legitimate membership at export time: a single member.
        snapshot.membership.add_member(
            DID::from("did:key:legit-member"),
            "member".to_owned(),
            Vec::new(),
        );

        let mut export = create_export(
            snapshot,
            event_log_data,
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // A valid export imports cleanly.
        validate_export_for_import(&export, &test_verifying_key()).unwrap();

        // Attacker forges an extra admin member into the signed snapshot
        // WITHOUT re-signing (they have no exporter key).
        export.snapshot.membership.add_member(
            DID::from("did:key:forged-admin"),
            "admin".to_owned(),
            Vec::new(),
        );

        let err = validate_export_for_import(&export, &test_verifying_key())
            .expect_err("tampered membership must be rejected");
        assert!(
            matches!(err, ContextError::SnapshotSignatureInvalid { .. }),
            "tampered membership must fail with SnapshotSignatureInvalid, got: {err:?}"
        );
        // The failure is NOT a root-mismatch error — the event log is untouched.
        let msg = format!("{err}");
        assert!(!msg.contains("signed snapshot root mismatch"));
        assert!(!msg.contains("envelope merkle_root mismatch"));
    }

    /// §23.16.8 / ADR-050 scope-binding: flipping the envelope `scope` on a
    /// validly-signed export MUST fail signature verification, because the scope
    /// discriminant ([`ExportScope::tag_byte`]) is bound into the signed
    /// preimage. An attacker holding a legitimately-signed export cannot rewrite
    /// `Full` -> `Public` (or `Public` -> `Full`) and have it still verify: the
    /// verifier recomputes `SHA-256(domain || [scope.tag_byte()] || JCS(...))`
    /// from the *received* envelope scope, which no longer matches the digest
    /// the creator signed. Tests both flip directions.
    #[test]
    fn tampered_scope_rejected_with_signature_error() {
        for original in [ExportScope::Full, ExportScope::Public] {
            let ctx_id = "ctx-tamper-scope";
            let ctx_id_bytes = scp_protocol::context::context_id_bytes(ctx_id);
            // Public exports carry no event log; Full does. Build the log
            // unconditionally — create_export discards it for Public scope.
            let event_log_data = create_event_log_data(&ctx_id_bytes, &["ContextCreated"]);

            let mut export = create_export(
                test_snapshot(ctx_id),
                event_log_data,
                DID::from(TEST_CREATOR_DID),
                original,
                &scp_primitives::SystemClock,
                sign_with_test_key,
            )
            .unwrap();

            // Baseline: the untouched export validates under its real scope.
            validate_export_for_import(&export, &test_verifying_key())
                .expect("baseline signed export must validate before scope tamper");

            // Flip ONLY the envelope scope discriminant — no re-signing (the
            // attacker has no exporter key). The snapshot bytes are untouched.
            let flipped = match original {
                ExportScope::Full => ExportScope::Public,
                ExportScope::Public => ExportScope::Full,
            };
            export.scope = flipped;
            assert_ne!(
                original.tag_byte(),
                flipped.tag_byte(),
                "flip must change the bound discriminant byte"
            );

            let err = validate_export_for_import(&export, &test_verifying_key())
                .expect_err("flipping the signed-bound scope discriminant must be rejected");
            assert!(
                matches!(err, ContextError::SnapshotSignatureInvalid { .. }),
                "scope flip ({original:?} -> {flipped:?}) must fail with \
                 SnapshotSignatureInvalid, got: {err:?}"
            );
            // It is a SIGNATURE failure, not a version error or a root mismatch.
            let msg = format!("{err}");
            assert!(
                msg.contains("SCP-CTX-2093"),
                "expected the signature-failure code, got: {msg}"
            );
            assert!(!msg.contains("unsupported export"));
            assert!(!msg.contains("signed snapshot root mismatch"));
        }
    }

    /// Round-trip: a signed export survives serialize -> deserialize ->
    /// validate with the embedded snapshot signature intact, for both Full and
    /// Public scope.
    #[test]
    fn signed_export_round_trips_full_and_public() {
        for scope in [ExportScope::Full, ExportScope::Public] {
            let mut snapshot = test_snapshot("ctx-signed-roundtrip");
            snapshot.membership.add_member(
                DID::from("did:key:rt-member"),
                "member".to_owned(),
                Vec::new(),
            );
            let export = create_export(
                snapshot,
                Vec::new(),
                DID::from(TEST_CREATOR_DID),
                scope,
                &scp_primitives::SystemClock,
                sign_with_test_key,
            )
            .unwrap();

            let bytes = serialize_export(&export).unwrap();
            let decoded = deserialize_export(&bytes).unwrap();
            assert_eq!(decoded.snapshot_signature, export.snapshot_signature);
            validate_export_for_import(&decoded, &test_verifying_key()).unwrap();
        }
    }

    /// A signature that does not match the verifying key (wrong signer) is
    /// rejected.
    #[test]
    fn wrong_signer_rejected() {
        let snapshot = test_snapshot("ctx-wrong-signer");
        let export = create_export(
            snapshot,
            Vec::new(),
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // Verify with a DIFFERENT key than the one that signed.
        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let err = validate_export_for_import(&export, &wrong_key)
            .expect_err("wrong signer must be rejected");
        assert!(matches!(err, ContextError::SnapshotSignatureInvalid { .. }));
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
            DID::from(TEST_CREATOR_DID),
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

    // -------------------------------------------------------------------
    // Full-snapshot signing construction (spec §23.16.8, ADR-050)
    // -------------------------------------------------------------------

    /// Tampering `read_exclusion_list` — a field that the OLD §23.16.4 subset
    /// hash did NOT sign — is now rejected with the signature error. This is
    /// the core gap ADR-050 closes: the full-JCS digest covers every field.
    #[test]
    fn tampered_read_exclusion_list_rejected() {
        let mut snapshot = test_snapshot("ctx-tamper-readexcl");
        snapshot
            .read_exclusion_list
            .insert(DID::from("did:key:excluded-1"));

        let mut export = create_export(
            snapshot,
            Vec::new(),
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // Valid export imports cleanly.
        validate_export_for_import(&export, &test_verifying_key()).unwrap();

        // Attacker injects another exclusion WITHOUT re-signing.
        export
            .snapshot
            .read_exclusion_list
            .insert(DID::from("did:key:forged-exclusion"));

        let err = validate_export_for_import(&export, &test_verifying_key())
            .expect_err("tampered read_exclusion_list must be rejected");
        assert!(
            matches!(err, ContextError::SnapshotSignatureInvalid { .. }),
            "must fail with SnapshotSignatureInvalid, got: {err:?}"
        );
        let msg = format!("{err}");
        assert!(!msg.contains("signed snapshot root mismatch"));
        assert!(!msg.contains("envelope merkle_root mismatch"));
    }

    /// Tampering a role's capability ceiling — also unsigned under the old
    /// subset recipe — is rejected. A forged ceiling expansion (privilege
    /// escalation) no longer survives a valid signature.
    #[test]
    fn tampered_role_ceiling_rejected() {
        use scp_protocol::context::roles::Capability;

        let snapshot = test_snapshot("ctx-tamper-ceiling");
        let mut export = create_export(
            snapshot,
            Vec::new(),
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        validate_export_for_import(&export, &test_verifying_key()).unwrap();

        // Attacker raises the ceiling by injecting a capability that is NOT in
        // the default ceiling (so the insertion genuinely changes the set)
        // into the signed snapshot without re-signing.
        assert!(
            !export
                .snapshot
                .role_state
                .ceiling
                .capabilities
                .contains(&Capability::MediaVoice),
            "precondition: MediaVoice must not already be in the default ceiling"
        );
        export
            .snapshot
            .role_state
            .ceiling
            .capabilities
            .insert(Capability::MediaVoice);

        let err = validate_export_for_import(&export, &test_verifying_key())
            .expect_err("tampered role ceiling must be rejected");
        assert!(
            matches!(err, ContextError::SnapshotSignatureInvalid { .. }),
            "must fail with SnapshotSignatureInvalid, got: {err:?}"
        );
    }

    /// The signed digest is INDEPENDENT of the iteration order of the
    /// snapshot's `HashSet`/`HashMap` fields. This is the structural guard
    /// against a future set/map field leaking into the digest unsorted.
    ///
    /// The signed digest MUST be a pure function of the snapshot *value*,
    /// independent of the iteration order of any `HashSet`/`HashMap` it
    /// contains. We take ONE snapshot value (so its random-nonce role tokens
    /// are fixed) and build a structurally-identical copy whose set-backed
    /// fields have been cleared and re-inserted in reverse order — forcing a
    /// different `HashSet` iteration order while preserving identical content.
    /// The two canonical digests MUST be byte-identical. If a future set/map
    /// field is added without a deterministic serializer, the reversed
    /// iteration order will diverge here and fail this test.
    #[test]
    fn digest_is_deterministic_across_set_insertion_order() {
        use scp_protocol::context::roles::Capability;
        use std::collections::HashSet;

        // Rebuilds a set from its elements inserted in reverse order, forcing a
        // different `HashSet` iteration order while preserving identical
        // content.
        fn reinsert_reversed<T, S>(set: &mut HashSet<T, S>)
        where
            T: Eq + std::hash::Hash,
            S: std::hash::BuildHasher + Default,
        {
            let mut items: Vec<T> = std::mem::take(set).into_iter().collect();
            items.reverse();
            *set = items.into_iter().collect();
        }

        // Base snapshot with every non-deterministic collection populated.
        let mut base = test_snapshot("ctx-determinism");
        for d in ["did:key:e1", "did:key:e2", "did:key:e3"] {
            base.read_exclusion_list.insert(DID::from(d));
        }
        for p in [[1u8; 32], [2u8; 32], [9u8; 32]] {
            base.executed_proposals.insert(p);
        }
        // MediaVoice / MediaVideo are NOT in default_ceiling, so these are
        // genuine additions exercising the ceiling set serializer.
        base.role_state
            .ceiling
            .capabilities
            .insert(Capability::MediaVoice);
        base.role_state
            .ceiling
            .capabilities
            .insert(Capability::MediaVideo);
        base.role_state.members.insert("did:key:m-a".to_owned());
        base.role_state.members.insert("did:key:m-b".to_owned());

        // Structurally-identical copy whose set fields are rebuilt in reverse
        // iteration order.
        let mut shuffled = base.clone();
        reinsert_reversed(&mut shuffled.read_exclusion_list);
        reinsert_reversed(&mut shuffled.executed_proposals);
        reinsert_reversed(&mut shuffled.role_state.ceiling.capabilities);
        reinsert_reversed(&mut shuffled.role_state.members);

        let sign = sign_with_test_key;
        let a = create_export(
            base,
            Vec::new(),
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign,
        )
        .unwrap();
        let b = create_export(
            shuffled,
            Vec::new(),
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign,
        )
        .unwrap();

        // Same canonical digest regardless of set iteration order.
        assert_eq!(
            a.canonical_snapshot_hash().unwrap(),
            b.canonical_snapshot_hash().unwrap(),
            "canonical digest must be independent of set iteration order"
        );
        // And therefore the same signature.
        assert_eq!(a.snapshot_signature, b.snapshot_signature);
    }

    /// §23.16.8 step 2: an export whose `exporter_did` is not the snapshot
    /// `creator_did` is rejected — even when the signature itself would verify
    /// — because the signing authority must be bound to the creator.
    #[test]
    fn exporter_not_creator_rejected() {
        let snapshot = test_snapshot("ctx-exporter-mismatch");
        // Build with a NON-creator exporter; signature is still produced by the
        // test key, so this isolates the binding check from the crypto check.
        let export = create_export(
            snapshot,
            Vec::new(),
            DID::from("did:key:not-the-creator"),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        let err = validate_export_for_import(&export, &test_verifying_key())
            .expect_err("exporter != creator must be rejected");
        assert!(
            matches!(err, ContextError::SnapshotSignatureInvalid { .. }),
            "must fail with SnapshotSignatureInvalid, got: {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("does not match snapshot creator_did"),
            "expected creator-binding message, got: {msg}"
        );
    }

    /// §23.16.8 step 2 (post-sign tamper): an attacker who takes a
    /// validly-signed export and rewrites the envelope `exporter_did` to a
    /// different DID — without re-signing (they lack the creator key) — is
    /// rejected with [`ContextError::SnapshotSignatureInvalid`]. This locks the
    /// signer-binding step against envelope tampering, distinct from the
    /// build-time non-creator case (`exporter_not_creator_rejected`).
    #[test]
    fn tampered_exporter_did_rejected_with_signature_error() {
        let snapshot = test_snapshot("ctx-exporter-tamper");
        let mut export = create_export(
            snapshot,
            Vec::new(),
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // Baseline: the untouched, creator-signed export validates.
        validate_export_for_import(&export, &test_verifying_key())
            .expect("baseline creator-signed export must validate");

        // Attacker rewrites the unsigned envelope `exporter_did` away from the
        // snapshot `creator_did` without re-signing.
        export.exporter_did = DID::from("did:key:attacker-rewrap");

        let err = validate_export_for_import(&export, &test_verifying_key())
            .expect_err("exporter_did tampered away from creator_did must be rejected");
        assert!(
            matches!(err, ContextError::SnapshotSignatureInvalid { .. }),
            "tampered exporter_did must fail with SnapshotSignatureInvalid, got: {err:?}"
        );
        assert!(
            format!("{err}").contains("does not match snapshot creator_did"),
            "expected creator-binding message, got: {err}"
        );
    }

    /// Structural pin (ADR-050 "no unsigned restored field"): destructure the
    /// full [`ContextExport`] envelope with NO `..` rest pattern. If a future
    /// change adds a field to the envelope, this test stops compiling — forcing
    /// an explicit decision about whether the new field must live inside the
    /// signed snapshot preimage (and be cross-checked) rather than being
    /// silently carried unsigned. Every field named here is either gated,
    /// cross-checked against a signed value, or inert (see the `ContextExport`
    /// doc comment and `validate_export_for_import`).
    #[test]
    fn context_export_envelope_fields_are_pinned() {
        let export = create_export(
            test_snapshot("ctx-envelope-pin"),
            Vec::new(),
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // Exhaustive destructure — adding a field forces this to break.
        let ContextExport {
            snapshot,
            event_log_data,
            version,
            exported_at,
            exporter_did,
            merkle_root,
            scope,
            snapshot_signature,
        } = &export;

        // Touch each binding so none is dead and the intent is explicit.
        assert_eq!(snapshot.context_id, "ctx-envelope-pin");
        assert!(event_log_data.is_empty());
        assert_eq!(*version, CURRENT_EXPORT_VERSION);
        let _ = exported_at;
        assert_eq!(exporter_did.as_ref(), TEST_CREATOR_DID);
        assert_eq!(*merkle_root, [0u8; 32]);
        assert_eq!(*scope, ExportScope::Full);
        assert_eq!(snapshot_signature.len(), 64);
    }

    /// A `ContextSnapshot` carrying every non-deterministic collection
    /// (the two `HashSet`s, the `[u8; 32]`-keyed `approved_proposals` map, and
    /// nested role-state capability sets) round-trips through `MessagePack`
    /// persistence unchanged, proving the deterministic serializers do not
    /// break the persistence path (serialize -> deserialize is value-stable).
    #[test]
    fn snapshot_persistence_roundtrip_with_populated_sets() {
        use scp_protocol::context::roles::Capability;

        let mut snapshot = test_snapshot("ctx-persist-roundtrip");
        snapshot
            .read_exclusion_list
            .insert(DID::from("did:key:rx-1"));
        snapshot
            .read_exclusion_list
            .insert(DID::from("did:key:rx-2"));
        snapshot.executed_proposals.insert([7u8; 32]);
        snapshot.executed_proposals.insert([8u8; 32]);
        snapshot
            .role_state
            .ceiling
            .capabilities
            .insert(Capability::MemberInvite);
        snapshot.role_state.members.insert("did:key:m1".to_owned());
        snapshot.role_state.members.insert("did:key:m2".to_owned());
        // Cross-context anti-replay nonce-dedup cache (Class-S, FIX 4): an
        // accepted-nonce entry must round-trip so the replay window survives a
        // restart (BLACK-624-01).
        snapshot
            .xctx_nonce_dedup
            .insert([0xABu8; 16], 1_700_000_123);
        snapshot
            .xctx_nonce_dedup
            .insert([0xCDu8; 16], 1_700_000_456);

        // MessagePack persistence round-trip (the path used by
        // ContextPersistence::persist_context / load).
        let bytes = rmp_serde::to_vec_named(&snapshot).unwrap();
        let decoded: ContextSnapshot = rmp_serde::from_slice(&bytes).unwrap();

        assert_eq!(
            decoded.read_exclusion_list.len(),
            snapshot.read_exclusion_list.len()
        );
        assert!(decoded.read_exclusion_list.contains("did:key:rx-1"));
        assert!(decoded.read_exclusion_list.contains("did:key:rx-2"));
        assert_eq!(
            decoded.executed_proposals.len(),
            snapshot.executed_proposals.len()
        );
        assert!(decoded.executed_proposals.contains(&[7u8; 32]));
        assert!(decoded.role_state.members.contains("did:key:m1"));
        assert!(
            decoded
                .role_state
                .ceiling
                .capabilities
                .contains(&Capability::MemberInvite)
        );
        // The nonce-dedup cache survives the persistence round-trip value-stable.
        assert_eq!(decoded.xctx_nonce_dedup.len(), 2);
        assert_eq!(
            decoded.xctx_nonce_dedup.get(&[0xABu8; 16]).copied(),
            Some(1_700_000_123)
        );
        assert_eq!(
            decoded.xctx_nonce_dedup.get(&[0xCDu8; 16]).copied(),
            Some(1_700_000_456)
        );
    }

    /// A caller-side durable reservation reversal record (spec §6.2.4; Class S)
    /// round-trips through `MessagePack` persistence value-stable, so a
    /// `PreparingB`-window crash restores exactly the budget / hard-rate-limit /
    /// velocity-timestamp / external-escrow facts the recovery abort needs to
    /// reverse the caller deduction and void the escrow. Mirrors the
    /// `xctx_nonce_dedup` round-trip above for the other Class-S saga field.
    #[test]
    fn caller_reservation_record_persistence_roundtrips_value_stable() {
        use crate::context::supervisor::saga_journal::SagaId;
        use crate::context::supervisor::saga_prepared_state::CallerReservationRecord;
        use crate::economy::adapter::PaymentAuthorization;

        let mut snapshot = test_snapshot("ctx-caller-reservation-roundtrip");
        let caller = DID::from("did:key:caller-roundtrip");

        // A record carrying a budget delta, a hard-rate-limit refund flag, a
        // velocity timestamp, and a populated external escrow authorization —
        // every reversal-relevant field set so the round-trip exercises them all.
        let record = CallerReservationRecord {
            actor_did: caller.clone(),
            deducted_cost: Some(scp_protocol::economy::types::Amount(42)),
            needs_hard_rate_limit_refund: true,
            recorded_at_secs: 1_700_000_999,
            escrow_authorization: Some(PaymentAuthorization {
                auth_id: [9u8; 32],
                payer: caller,
                payee: DID::from("did:key:payee-roundtrip"),
                amount: scp_protocol::economy::types::Amount(42),
                currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
                adapter_id: "roundtrip-adapter".to_owned(),
                created_at: 1_000_000,
                expires_at: 2_000_000,
                adapter_state: vec![1, 2, 3, 4],
            }),
        };
        let saga = SagaId("saga-roundtrip".to_owned());
        snapshot
            .xctx_caller_reservations
            .insert(saga.clone(), record.clone());

        // MessagePack persistence round-trip (the path used by
        // ContextPersistence::persist_context / load).
        let bytes = rmp_serde::to_vec_named(&snapshot).unwrap();
        let decoded: ContextSnapshot = rmp_serde::from_slice(&bytes).unwrap();

        assert_eq!(decoded.xctx_caller_reservations.len(), 1);
        let decoded_record = decoded
            .xctx_caller_reservations
            .get(&saga)
            .expect("the caller-reservation record survives the round-trip");
        // Value-stable: the whole record (including the nested escrow auth)
        // is byte-for-byte equal via the derived `PartialEq`.
        assert_eq!(decoded_record, &record);
    }

    /// Caller-side reservation records are LOCAL-node economy state with no
    /// authority on a foreign node, so `strip_snapshot_for_public` MUST drop
    /// them — a public observer / importer must never be handed the means to
    /// drive a local economy reversal (caller economy is local, exactly like
    /// `xctx_committed_invocations` and `xctx_nonce_dedup`). A same-node FULL
    /// snapshot, by contrast, RETAINS them so a crash-recovery abort can reverse
    /// from the record. Asserts both halves of the asymmetry.
    #[test]
    fn caller_reservation_records_retained_full_dropped_public() {
        use crate::context::supervisor::saga_journal::SagaId;
        use crate::context::supervisor::saga_prepared_state::CallerReservationRecord;

        let mut snapshot = test_snapshot("ctx-caller-reservation-strip");
        let caller = DID::from("did:key:caller-strip");
        let saga = SagaId("saga-strip".to_owned());
        snapshot.xctx_caller_reservations.insert(
            saga.clone(),
            CallerReservationRecord {
                actor_did: caller,
                deducted_cost: Some(scp_protocol::economy::types::Amount(7)),
                needs_hard_rate_limit_refund: true,
                recorded_at_secs: 1_700_000_111,
                escrow_authorization: None,
            },
        );

        // FULL same-node snapshot retains the record (crash-recovery reversal
        // depends on it).
        assert!(
            snapshot.xctx_caller_reservations.contains_key(&saga),
            "the full snapshot must retain the caller-reservation record"
        );

        // PUBLIC strip drops it (no foreign authority over local economy).
        let stripped =
            strip_snapshot_for_public(&snapshot).expect("public strip builds a minimal role state");
        assert!(
            stripped.xctx_caller_reservations.is_empty(),
            "public strip MUST drop caller-reservation records (local economy has no foreign authority)"
        );
    }

    /// The signed-export digest (§23.16.8) uses its OWN domain separator,
    /// `"SCP-CONTEXT-EXPORT-V1:"`, which is DISTINCT from the §23.16.4
    /// sync-delta separator `"SCP-CONTEXT-SNAPSHOT-V1:"`. Both digests are
    /// Ed25519-signed under the same creator key, so the preimage prefixes
    /// MUST differ to make an export signature unforgeable as a sync-delta
    /// signature (and vice versa) regardless of how the two post-domain
    /// encodings evolve. This is a cross-protocol domain-separation invariant.
    #[test]
    fn export_digest_uses_distinct_export_domain_separator() {
        // The two separators are not equal and neither is a prefix of the other.
        assert_ne!(
            CONTEXT_EXPORT_DOMAIN_SEPARATOR, CONTEXT_SNAPSHOT_DOMAIN_SEPARATOR,
            "export and sync-delta separators must be distinct"
        );
        assert!(!CONTEXT_EXPORT_DOMAIN_SEPARATOR.starts_with(CONTEXT_SNAPSHOT_DOMAIN_SEPARATOR));
        assert!(!CONTEXT_SNAPSHOT_DOMAIN_SEPARATOR.starts_with(CONTEXT_EXPORT_DOMAIN_SEPARATOR));
        assert_eq!(CONTEXT_EXPORT_DOMAIN_SEPARATOR, "SCP-CONTEXT-EXPORT-V1:");

        let snapshot = test_snapshot("ctx-export-domain-sep");
        let export = create_export(
            snapshot,
            Vec::new(),
            DID::from(TEST_CREATOR_DID),
            ExportScope::Full,
            &scp_primitives::SystemClock,
            sign_with_test_key,
        )
        .unwrap();

        // The export digest the code actually produces.
        let actual = export.canonical_snapshot_hash().unwrap();

        // Recompute over the same JCS bytes with the EXPORT separator and the
        // scope tag byte (§23.16.8, ADR-050) — must match.
        let snapshot_json = scp_protocol::jcs::to_vec(&export.snapshot).unwrap();
        let with_export_domain = {
            let mut hasher = Sha256::new();
            hasher.update(CONTEXT_EXPORT_DOMAIN_SEPARATOR.as_bytes());
            hasher.update([export.scope.tag_byte()]);
            hasher.update(&snapshot_json);
            let d: [u8; 32] = hasher.finalize().into();
            d
        };
        assert_eq!(
            actual, with_export_domain,
            "canonical_snapshot_hash must use the export domain separator"
        );

        // Recompute with the SYNC-DELTA separator — must NOT match. Proves the
        // export digest is domain-separated from the sync-delta construction.
        let with_sync_domain = {
            let mut hasher = Sha256::new();
            hasher.update(CONTEXT_SNAPSHOT_DOMAIN_SEPARATOR.as_bytes());
            hasher.update([export.scope.tag_byte()]);
            hasher.update(&snapshot_json);
            let d: [u8; 32] = hasher.finalize().into();
            d
        };
        assert_ne!(
            actual, with_sync_domain,
            "export digest must differ from a digest computed with the sync-delta separator"
        );
    }
}
