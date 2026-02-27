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
    pub fn new(storage: S) -> Self {
        Self { storage }
    }
}
