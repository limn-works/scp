//! Versioned storage envelope and key conventions shared across the storage
//! layer (spec sections 17.3 and 17.5).
//!
//! Every value persisted to a [`Storage`](crate::traits::Storage) backend by an
//! SCP component is wrapped in a [`StoredValue`] version envelope and addressed
//! by a sanitized key following the spec §17.3 key convention. Both the envelope
//! format and the key convention are defined **here**, in the platform/storage
//! layer, so that every crate which writes to the same storage slot produces
//! byte-identical output and reads each other's writes.
//!
//! This is the single source of truth for:
//!
//! - [`StoredValue`] — the `{ version, data }` envelope (spec §17.5).
//! - [`CURRENT_STORE_VERSION`] — the current envelope schema version.
//! - [`to_stored_value_bytes`] / [`from_stored_value_bytes`] — the canonical
//!   named-`MessagePack` serialization of the envelope.
//! - [`sanitize_key_component`] — path-traversal rejection for key components.
//! - [`identity_document_key`] — the `identity/{did}/document` key convention
//!   (spec §17.3).
//!
//! # Why the platform layer
//!
//! Both `scp-runtime` (via `ProtocolRepository`) and `scp-identity` (via the
//! standalone `Identity::create` construction path) persist an identity's DID
//! document under the **same** spec §17.3 storage slot `identity/{did}/document`.
//! `scp-identity` sits below `scp-runtime` in the dependency graph and cannot
//! import it; both, however, depend on `scp-platform`. Lifting the envelope and
//! key convention here lets both call the same helper, eliminating the
//! format-divergence class of bug (one path writing bare JSON while the other
//! writes a `MessagePack` envelope — mutually undeserializable).

use serde::{Serialize, de::DeserializeOwned};

/// Errors produced when (de)serializing a [`StoredValue`] envelope or building a
/// storage key.
#[derive(Debug, thiserror::Error)]
pub enum StoreValueError {
    /// Serialization of a value into the envelope failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// Deserialization of a stored envelope failed.
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),

    /// The stored value was written by a newer SCP version and cannot be read.
    #[error("incompatible version: stored={stored}, current={current}")]
    IncompatibleVersion {
        /// The version found in the stored data.
        stored: u16,
        /// The maximum version this build can read.
        current: u16,
    },

    /// A key component contained path-traversal characters.
    #[error("invalid key component: contains forbidden characters: {0:?}")]
    InvalidKeyComponent(String),
}

/// Version envelope for all values persisted to SCP storage.
///
/// Every value written to a [`Storage`](crate::traits::Storage) backend is
/// wrapped in `StoredValue`. On read, `version` is checked before deserializing
/// `data`. This enables lazy on-read migration (spec section 17.10) without
/// requiring schema-level versioning in the storage backend.
///
/// See spec section 17.5.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredValue<T> {
    /// Schema version for the contained data type.
    pub version: u16,
    /// The serialized domain value.
    pub data: T,
}

/// Current schema version for all [`StoredValue`] envelopes.
///
/// Incremented when the serialized format of any domain type changes.
/// Migration logic (spec section 17.10) uses this to detect stale data.
///
/// `2` reflects the v1→v2 migration that introduced named-`MessagePack`
/// encoding (see spec section 17.10).
pub const CURRENT_STORE_VERSION: u16 = 2;

/// Serializes a value into a [`StoredValue`] envelope using named `MessagePack`.
///
/// Wraps `value` in a version envelope (spec section 17.5) at
/// [`CURRENT_STORE_VERSION`] and serializes the whole envelope with `rmp-serde`
/// in named (map) format. Named format encodes struct field names, making the
/// format resilient to field additions and reordering.
///
/// This is the canonical write path: any component persisting to SCP storage
/// must produce its bytes through this function (or an equivalent that yields
/// the identical envelope) so that all writers of a given key agree on the
/// on-disk encoding.
///
/// # Errors
///
/// Returns [`StoreValueError::SerializationFailed`] if `rmp-serde` fails.
pub fn to_stored_value_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreValueError> {
    let envelope = StoredValue {
        version: CURRENT_STORE_VERSION,
        data: value,
    };
    rmp_serde::to_vec_named(&envelope)
        .map_err(|e| StoreValueError::SerializationFailed(e.to_string()))
}

/// Deserializes a [`StoredValue`] envelope from `MessagePack` bytes.
///
/// Checks the version field: if the stored version exceeds
/// [`CURRENT_STORE_VERSION`], returns [`StoreValueError::IncompatibleVersion`].
/// Otherwise deserializes and returns the inner data.
///
/// # Errors
///
/// Returns [`StoreValueError::DeserializationFailed`] if `rmp-serde` fails, or
/// [`StoreValueError::IncompatibleVersion`] if the envelope was written by a
/// newer build.
pub fn from_stored_value_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StoreValueError> {
    let envelope: StoredValue<T> = rmp_serde::from_slice(bytes)
        .map_err(|e| StoreValueError::DeserializationFailed(e.to_string()))?;
    if envelope.version > CURRENT_STORE_VERSION {
        return Err(StoreValueError::IncompatibleVersion {
            stored: envelope.version,
            current: CURRENT_STORE_VERSION,
        });
    }
    Ok(envelope.data)
}

/// Validates a storage key component, rejecting path-traversal characters.
///
/// Rejects strings containing `/`, `\`, `..`, or null bytes to prevent storage
/// path-traversal attacks. Every component interpolated into a storage key
/// (DIDs, context ids, tool ids, …) must pass through this gate before being
/// formatted into a key.
///
/// # Errors
///
/// Returns [`StoreValueError::InvalidKeyComponent`] if the input contains
/// forbidden characters (`/`, `\`, `..`, or null bytes).
pub fn sanitize_key_component(s: &str) -> Result<&str, StoreValueError> {
    if s.contains('/') || s.contains('\\') || s.contains("..") || s.contains('\0') {
        return Err(StoreValueError::InvalidKeyComponent(s.to_owned()));
    }
    Ok(s)
}

/// Builds the spec §17.3 storage key for an identity's DID document.
///
/// Format: `identity/{did}/document`, with `did` passed through
/// [`sanitize_key_component`] first. This is the single source of the key
/// convention shared by `ProtocolRepository::store_identity_document` and the
/// standalone `Identity::create` persistence path, guaranteeing both address
/// the identical storage slot.
///
/// # Errors
///
/// Returns [`StoreValueError::InvalidKeyComponent`] if `did` contains
/// path-traversal characters.
pub fn identity_document_key(did: &str) -> Result<String, StoreValueError> {
    let did = sanitize_key_component(did)?;
    Ok(format!("identity/{did}/document"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn stored_value_roundtrip_via_named_msgpack() {
        let bytes = to_stored_value_bytes(&"hello".to_owned()).unwrap();
        let decoded: String = from_stored_value_bytes(&bytes).unwrap();
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn envelope_carries_current_version() {
        let bytes = to_stored_value_bytes(&vec![1u8, 2, 3]).unwrap();
        let envelope: StoredValue<Vec<u8>> = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(envelope.version, CURRENT_STORE_VERSION);
        assert_eq!(envelope.data, vec![1u8, 2, 3]);
    }

    #[test]
    fn from_stored_value_bytes_rejects_future_version() {
        let envelope = StoredValue {
            version: CURRENT_STORE_VERSION + 1,
            data: "future",
        };
        let bytes = rmp_serde::to_vec_named(&envelope).unwrap();
        let result = from_stored_value_bytes::<String>(&bytes);
        assert!(matches!(
            result,
            Err(StoreValueError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn sanitize_rejects_traversal() {
        assert!(sanitize_key_component("../identity/victim").is_err());
        assert!(sanitize_key_component("evil\\path").is_err());
        assert!(sanitize_key_component("foo..bar").is_err());
        assert!(sanitize_key_component("evil\0id").is_err());
    }

    #[test]
    fn sanitize_accepts_well_formed() {
        assert!(sanitize_key_component("did:dht:z6MkTest").is_ok());
        assert!(sanitize_key_component("ctx-123").is_ok());
    }

    #[test]
    fn identity_document_key_follows_convention() {
        assert_eq!(
            identity_document_key("did:dht:z6MkTest").unwrap(),
            "identity/did:dht:z6MkTest/document"
        );
    }

    #[test]
    fn identity_document_key_rejects_traversal_did() {
        assert!(identity_document_key("../context/victim").is_err());
        assert!(identity_document_key("evil\\did").is_err());
        assert!(identity_document_key("a/b").is_err());
        assert!(identity_document_key("nul\0did").is_err());
    }
}
