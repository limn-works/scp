//! Protocol store for SCP client-side persistence.
//!
//! `ProtocolStore<S>` wraps a `Storage` implementation and provides typed
//! domain methods for all protocol state. Storage adapters implement the
//! thin `Storage` trait (six methods); `ProtocolStore` handles all structured
//! domain logic and key conventions.
//!
//! # Key Convention
//!
//! All keys follow `{namespace}/{entity_id}/{sub_key}` with `/` as the
//! hierarchy separator. See spec section 17.3 for the full key convention.
//!
//! # Module Structure
//!
//! Each domain area has its own submodule with the `ProtocolStore` impl
//! methods for that area. This keeps the impl blocks organized and
//! focused.
//!
//! See spec section 17.4 and ADR-006.

pub mod economy;
pub mod ucan;

use scp_platform::traits::Storage;

// ---------------------------------------------------------------------------
// StoreError
// ---------------------------------------------------------------------------

/// Errors produced by `ProtocolStore` operations.
///
/// Wraps platform storage errors and adds protocol-level error variants
/// for serialization/deserialization failures and missing data.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The underlying storage backend returned an error.
    #[error("storage error: {0}")]
    Storage(#[from] scp_platform::PlatformError),

    /// Serialization of a protocol value failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// Deserialization of a stored value failed.
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),
}

// ---------------------------------------------------------------------------
// Key sanitization
// ---------------------------------------------------------------------------

/// Validates that a string is safe to use as a storage key path component.
///
/// Rejects strings containing `/`, `\`, `..`, or null bytes (`\0`) to
/// prevent path traversal attacks when constructing hierarchical storage
/// keys like `"ucan/{context_id}/tokens/{token_id}"`.
///
/// Returns the input string unchanged if valid, or a [`StoreError`] if the
/// string contains forbidden characters.
///
/// # Errors
///
/// Returns [`StoreError::SerializationFailed`] if `s` contains any of the
/// forbidden patterns: `/`, `\`, `..`, or `\0`.
pub fn sanitize_key_component(s: &str) -> Result<&str, StoreError> {
    if s.contains('/') || s.contains('\\') || s.contains("..") || s.contains('\0') {
        return Err(StoreError::SerializationFailed(format!(
            "invalid key component: contains forbidden characters: {s:?}"
        )));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// ProtocolStore
// ---------------------------------------------------------------------------

/// Concrete protocol store wrapping a platform `Storage` implementation.
///
/// Provides typed domain methods for all protocol state. Storage adapters
/// implement the thin `Storage` trait; `ProtocolStore` handles all structured
/// domain logic, key conventions, and serialization.
///
/// The type parameter `S` is the concrete storage backend (e.g.,
/// `InMemoryStorage`, `SqliteStorage`). The `Storage` trait uses RPITIT
/// (return-position `impl Trait` in traits) and is not dyn-compatible,
/// so `ProtocolStore` is generic rather than using `Arc<dyn Storage>`.
///
/// See spec section 17.4.
pub struct ProtocolStore<S: Storage> {
    storage: S,
}

impl<S: Storage> ProtocolStore<S> {
    /// Creates a new `ProtocolStore` wrapping the given storage backend.
    #[must_use]
    pub const fn new(storage: S) -> Self {
        Self { storage }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_accepts_normal_string() {
        assert_eq!(
            sanitize_key_component("ctx-abc-123").unwrap(),
            "ctx-abc-123"
        );
    }

    #[test]
    fn sanitize_accepts_alphanumeric() {
        assert_eq!(sanitize_key_component("abc123").unwrap(), "abc123");
    }

    #[test]
    fn sanitize_accepts_dashes_and_underscores() {
        assert_eq!(
            sanitize_key_component("my-context_id").unwrap(),
            "my-context_id"
        );
    }

    #[test]
    fn sanitize_rejects_forward_slash() {
        let err = sanitize_key_component("../../secrets").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn sanitize_rejects_backslash() {
        let err = sanitize_key_component("..\\secrets").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn sanitize_rejects_dot_dot() {
        let err = sanitize_key_component("..").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn sanitize_rejects_null_byte() {
        let err = sanitize_key_component("ctx\0evil").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn sanitize_rejects_embedded_slash() {
        let err = sanitize_key_component("ctx/evil").unwrap_err();
        assert!(err.to_string().contains("forbidden characters"));
    }

    #[test]
    fn sanitize_accepts_single_dot() {
        // Single dot is fine; only ".." is dangerous.
        assert_eq!(sanitize_key_component(".hidden").unwrap(), ".hidden");
    }
}
