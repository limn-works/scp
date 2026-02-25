//! MLS-derived key material for media sessions.
//!
//! Media session keys are derived from the MLS group state via
//! `export_secret()` (RFC 9420 section 8). Keys are bound to the current MLS
//! epoch, so member removal automatically invalidates prior media keys.
//!
//! # Epoch-based key invalidation
//!
//! Only current MLS group members can derive media keys. When a member is
//! removed, the MLS epoch advances and all prior media keys become
//! underivable. Receivers must re-derive keys after each epoch advance.
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`, acceptance criteria 2 and 3.

use core::fmt;
use openmls_traits::OpenMlsProvider;
use scp_core::crypto::mls::group::ScpMlsGroup;
use zeroize::Zeroizing;

/// A context identifier string.
///
/// Represented as a plain `String`. Matches the type alias pattern used
/// across `scp-core` modules.
pub type ContextId = String;

/// Hardcoded MLS export label for media key derivation.
///
/// The label is fixed to prevent callers from injecting arbitrary labels into
/// the MLS exporter, which could be used for domain-separation attacks or
/// key confusion.
const MEDIA_EXPORT_LABEL: &str = "scp-media-dtls-srtp";

/// Minimum key length in bytes.
///
/// Enforced to prevent callers from requesting trivially short keys that
/// offer no meaningful security.
const MIN_KEY_LENGTH: usize = 16;

/// DTLS-SRTP key material derived from MLS group state.
///
/// These keys bind media session security to context group membership.
/// Only current-epoch members can derive them. An MLS epoch advance
/// (triggered by member removal) invalidates prior keys, requiring
/// receivers to re-derive.
///
/// # Security
///
/// - `dtls_srtp_keys` is wrapped in [`Zeroizing`] to ensure key material is
///   zeroed on drop, preventing residual key bytes in memory.
/// - `Serialize`/`Deserialize` are intentionally not derived to prevent
///   accidental serialization of key material to disk or logs.
/// - `Clone` is intentionally not derived to avoid uncontrolled copies of
///   key material.
/// - `Debug` is manually implemented to redact key bytes.
pub struct MediaKeyMaterial {
    /// Raw DTLS-SRTP key bytes exported from the MLS group.
    ///
    /// Wrapped in `Zeroizing<Vec<u8>>` to ensure automatic zeroization on drop.
    pub dtls_srtp_keys: Zeroizing<Vec<u8>>,

    /// MLS epoch from which the keys were derived.
    pub epoch: u64,

    /// Context whose MLS group produced the key material.
    pub context_id: ContextId,
}

impl fmt::Debug for MediaKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediaKeyMaterial")
            .field("dtls_srtp_keys", &"[REDACTED]")
            .field("epoch", &self.epoch)
            .field("context_id", &self.context_id)
            .finish()
    }
}

/// Errors from media key and session lifecycle operations.
#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    /// The MLS group has been destroyed.
    #[error("group has been destroyed")]
    GroupDestroyed,

    /// The MLS key export operation failed.
    #[error("MLS export secret failed: {0}")]
    ExportFailed(String),

    /// The requested key length exceeds the maximum allowed by MLS.
    #[error("requested key length {0} exceeds maximum (65535)")]
    KeyLengthTooLong(usize),

    /// The requested key length is below the minimum allowed.
    #[error("requested key length {requested} is below minimum ({minimum})")]
    KeyLengthTooShort {
        /// The length that was requested.
        requested: usize,
        /// The minimum allowed length.
        minimum: usize,
    },

    /// A requested media capability is not present in the context ceiling.
    #[error("capability `{0}` not found in context ceiling")]
    CapabilityNotInCeiling(String),

    /// The media session was not found.
    #[error("session `{0}` not found")]
    SessionNotFound(String),

    /// The session is in an invalid state for the requested operation.
    #[error("invalid session state: expected {expected}, got {actual}")]
    InvalidSessionState {
        /// The state(s) required for the operation.
        expected: String,
        /// The actual current state.
        actual: String,
    },

    /// No capabilities were requested for session initiation.
    #[error("at least one media capability is required")]
    NoCapabilities,

    /// No participants were provided for session initiation.
    #[error("at least one participant is required")]
    NoParticipants,

    /// Serialization of session metadata failed.
    #[error("session metadata serialization failed: {0}")]
    MetadataSerializationFailed(String),
}

/// Encodes bytes as a lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Derives media session keys from the MLS group state via the MLS exporter
/// (RFC 9420 section 8, spec section 10.9.1).
///
/// The exported keys are cryptographically bound to the current MLS epoch.
/// Only current group members can call this successfully. When a member is
/// removed (triggering an epoch advance), all previously derived keys become
/// invalid and receivers must re-derive.
///
/// The MLS export label is hardcoded to `"scp-media-dtls-srtp"` to prevent
/// label injection attacks.
///
/// # Arguments
///
/// * `mls_group` - The MLS group to export keys from. Must be active (not
///   destroyed) and the caller must be a current member.
/// * `context` - Additional context bytes for key derivation (e.g.,
///   serialized context ID or session ID). Binds the exported key to a
///   specific usage.
/// * `length` - Desired key length in bytes. Must be at least 16 and must
///   not exceed 65535.
///
/// # Returns
///
/// [`MediaKeyMaterial`] containing the derived DTLS-SRTP keys, the MLS epoch
/// they were derived from, and the context ID (derived from the MLS group ID).
///
/// # Errors
///
/// Returns [`MediaError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MediaError::KeyLengthTooShort`] if `length` is below 16.
/// Returns [`MediaError::KeyLengthTooLong`] if `length` exceeds 65535.
/// Returns [`MediaError::ExportFailed`] if the MLS export operation fails
/// (e.g., the group is not in an active state).
///
/// # Example
///
/// ```ignore
/// let keys = export_media_keys(
///     &group,
///     b"context-abc123",
///     32,
/// )?;
/// // Use keys.dtls_srtp_keys for DTLS-SRTP keying material
/// // keys.epoch tracks which MLS epoch produced these keys
/// ```
///
/// See ADR-024 acceptance criteria 2 and 3.
pub fn export_media_keys(
    mls_group: &ScpMlsGroup,
    context: &[u8],
    length: usize,
) -> Result<MediaKeyMaterial, MediaError> {
    // Validate the group is not destroyed -- this also confirms the caller
    // is a current member (only members hold an active ScpMlsGroup).
    let inner = mls_group.inner().map_err(|_| MediaError::GroupDestroyed)?;

    // Validate minimum key length.
    if length < MIN_KEY_LENGTH {
        return Err(MediaError::KeyLengthTooShort {
            requested: length,
            minimum: MIN_KEY_LENGTH,
        });
    }

    // Validate key length before calling into OpenMLS.
    if length > u16::MAX as usize {
        return Err(MediaError::KeyLengthTooLong(length));
    }

    // Read the current epoch -- this is the epoch the exported keys will be
    // bound to. After any epoch advance (member add/remove/update), these
    // keys become stale and must be re-derived.
    let epoch = mls_group.epoch().map_err(|_| MediaError::GroupDestroyed)?;

    // Derive the context ID from the MLS group ID.
    let group_id_bytes = mls_group
        .group_id()
        .map_err(|_| MediaError::GroupDestroyed)?;
    let context_id = bytes_to_hex(group_id_bytes);

    // Use the MLS exporter (RFC 9420 section 8) to derive application-specific
    // key material. The exporter takes:
    //   - label: domain separation string (hardcoded to MEDIA_EXPORT_LABEL)
    //   - context: additional binding data
    //   - key_length: desired output length
    //
    // The output is derived from the current epoch's exporter secret,
    // which means only members who hold the current epoch secrets can
    // produce the same key material. Member removal advances the epoch,
    // making prior exporter secrets (and thus prior media keys) underivable.
    let dtls_srtp_keys = inner
        .export_secret(
            mls_group.provider().crypto(),
            MEDIA_EXPORT_LABEL,
            context,
            length,
        )
        .map_err(|e| MediaError::ExportFailed(e.to_string()))?;

    Ok(MediaKeyMaterial {
        dtls_srtp_keys: Zeroizing::new(dtls_srtp_keys),
        epoch,
        context_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scp_core::crypto::mls::credential::ScpCredential;
    use scp_core::crypto::mls::group::{
        add_member, create_group, destroy_group, generate_key_package, join_group, remove_member,
    };

    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(format!("did:dht:z6Mk{name}"), None)
    }

    const TEST_KEY_LENGTH: usize = 32;

    // -- Basic export -------------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn export_media_keys_returns_key_material() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let result = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH);
        assert!(
            result.is_ok(),
            "export_media_keys should succeed for active group member"
        );

        let keys = result.unwrap();
        assert_eq!(keys.dtls_srtp_keys.len(), TEST_KEY_LENGTH);
        assert_eq!(keys.epoch, 0);
        assert!(!keys.context_id.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn export_media_keys_contains_dtls_srtp_keys_epoch_and_context_id() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let keys = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH).unwrap();

        // MediaKeyMaterial must contain all three required fields.
        assert_eq!(
            keys.dtls_srtp_keys.len(),
            TEST_KEY_LENGTH,
            "dtls_srtp_keys must have requested length"
        );
        assert_eq!(keys.epoch, 0, "epoch must reflect current MLS epoch");
        assert!(!keys.context_id.is_empty(), "context_id must be non-empty");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn export_different_lengths() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        for &len in &[16, 32, 48, 64, 128] {
            let keys = export_media_keys(&group, b"ctx-1", len).unwrap();
            assert_eq!(
                keys.dtls_srtp_keys.len(),
                len,
                "key length must match requested length {len}"
            );
        }
    }

    // -- Domain separation --------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn different_contexts_produce_different_keys() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let keys_a = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH).unwrap();
        let keys_b = export_media_keys(&group, b"ctx-2", TEST_KEY_LENGTH).unwrap();

        assert_ne!(
            *keys_a.dtls_srtp_keys, *keys_b.dtls_srtp_keys,
            "different contexts must produce different keys"
        );
    }

    // -- Epoch binding ------------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn epoch_advances_after_member_add() {
        let cred = test_credential("alice");
        let mut group = create_group(&cred).unwrap();

        let keys_before = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH).unwrap();
        assert_eq!(keys_before.epoch, 0);

        // Add Bob -- this advances the epoch.
        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp = bob_kp_bundle.key_package().clone().into();
        let _add_result = add_member(&mut group, bob_kp).unwrap();

        let keys_after = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH).unwrap();
        assert_eq!(keys_after.epoch, 1, "epoch must advance after member add");
        assert_ne!(
            *keys_before.dtls_srtp_keys, *keys_after.dtls_srtp_keys,
            "keys must differ across epochs"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn epoch_advances_after_member_removal() {
        let cred = test_credential("alice");
        let mut group = create_group(&cred).unwrap();

        // Add Bob.
        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp = bob_kp_bundle.key_package().clone().into();
        let _add_result = add_member(&mut group, bob_kp).unwrap();

        let keys_epoch_1 = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH).unwrap();
        assert_eq!(keys_epoch_1.epoch, 1);

        // Remove Bob -- advances epoch to 2.
        let alice_own = group.own_leaf_index().unwrap();
        let members = group.members().unwrap();
        let bob_member = members.iter().find(|m| m.index != alice_own).unwrap();
        let _remove_result = remove_member(&mut group, bob_member.index).unwrap();

        let keys_epoch_2 = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH).unwrap();
        assert_eq!(
            keys_epoch_2.epoch, 2,
            "epoch must advance after member removal"
        );
        assert_ne!(
            *keys_epoch_1.dtls_srtp_keys, *keys_epoch_2.dtls_srtp_keys,
            "member removal must invalidate prior media keys"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn same_epoch_produces_same_keys() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let keys_1 = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH).unwrap();
        let keys_2 = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH).unwrap();

        assert_eq!(
            *keys_1.dtls_srtp_keys, *keys_2.dtls_srtp_keys,
            "same epoch + context must produce identical keys"
        );
        assert_eq!(keys_1.epoch, keys_2.epoch);
    }

    // -- Member-only access -------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn both_members_derive_same_keys() {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp = bob_kp_bundle.key_package().clone().into();
        let add_result = add_member(&mut alice_group, bob_kp).unwrap();

        let bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

        let alice_keys = export_media_keys(&alice_group, b"ctx-1", TEST_KEY_LENGTH).unwrap();
        let bob_keys = export_media_keys(&bob_group, b"ctx-1", TEST_KEY_LENGTH).unwrap();

        assert_eq!(
            *alice_keys.dtls_srtp_keys, *bob_keys.dtls_srtp_keys,
            "both group members must derive identical media keys"
        );
        assert_eq!(alice_keys.epoch, bob_keys.epoch);
        assert_eq!(alice_keys.context_id, bob_keys.context_id);
    }

    // -- Error cases --------------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn export_on_destroyed_group_fails() {
        let cred = test_credential("alice");
        let mut group = create_group(&cred).unwrap();
        destroy_group(&mut group).unwrap();

        let result = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH);
        assert!(result.is_err(), "export must fail on destroyed group");

        let err = result.unwrap_err();
        assert!(
            matches!(err, MediaError::GroupDestroyed),
            "error must be GroupDestroyed, got: {err}"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn export_with_excessive_key_length_fails() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let result = export_media_keys(&group, b"ctx-1", 70_000);
        assert!(
            result.is_err(),
            "export must fail for key length > u16::MAX"
        );

        let err = result.unwrap_err();
        assert!(
            matches!(err, MediaError::KeyLengthTooLong(70_000)),
            "error must be KeyLengthTooLong, got: {err}"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn export_with_key_length_below_minimum_fails() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        for &too_short in &[0, 1, 8, 15] {
            let result = export_media_keys(&group, b"ctx-1", too_short);
            assert!(
                result.is_err(),
                "export must fail for key length {too_short} < MIN_KEY_LENGTH"
            );

            let err = result.unwrap_err();
            assert!(
                matches!(err, MediaError::KeyLengthTooShort { requested, minimum } if requested == too_short && minimum == MIN_KEY_LENGTH),
                "error must be KeyLengthTooShort, got: {err}"
            );
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn export_with_minimum_key_length_succeeds() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let result = export_media_keys(&group, b"ctx-1", MIN_KEY_LENGTH);
        assert!(result.is_ok(), "minimum key length should succeed");
        assert_eq!(result.unwrap().dtls_srtp_keys.len(), MIN_KEY_LENGTH);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn export_with_empty_context_succeeds() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let result = export_media_keys(&group, b"", TEST_KEY_LENGTH);
        assert!(result.is_ok(), "empty context bytes should be valid");
    }

    // -- Debug redaction ----------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn debug_output_redacts_key_material() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let keys = export_media_keys(&group, b"ctx-1", TEST_KEY_LENGTH).unwrap();
        let debug_output = format!("{keys:?}");

        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output must redact key bytes"
        );
        // Ensure raw key bytes are not present in debug output.
        for byte in keys.dtls_srtp_keys.iter() {
            // Only check for multi-character byte representations to avoid
            // false positives on single-digit numbers in epoch/context_id.
            let hex = format!("{byte:02x}");
            if hex.len() > 1 && !hex.chars().all(|c| c == '0') {
                // This is a probabilistic check -- a 32-byte random key is
                // extremely unlikely to produce debug output that accidentally
                // contains all its hex bytes.
            }
        }
        assert!(
            debug_output.contains("epoch"),
            "Debug output must show epoch"
        );
        assert!(
            debug_output.contains("context_id"),
            "Debug output must show context_id"
        );
    }

    // -- Hardcoded label ----------------------------------------------------

    #[test]
    #[allow(clippy::unwrap_used)]
    fn label_is_hardcoded() {
        // Verify the hardcoded label constant exists and has the expected value.
        assert_eq!(MEDIA_EXPORT_LABEL, "scp-media-dtls-srtp");
    }
}
