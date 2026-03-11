//! Sealed marker trait for storage backends that encrypt data at rest.
//!
//! [`EncryptedStorage`] is a sealed marker trait — only implementable inside
//! `scp-platform`. External crates can see and require the trait, but cannot
//! implement it for their own types. This prevents unencrypted backends from
//! satisfying the bound.
//!
//! Production backends (`SqliteStorage`, `AppleStorage`) implement it directly.
//! Custom backends that don't natively encrypt should be wrapped in
//! [`EncryptingAdapter`](crate::encrypting_adapter::EncryptingAdapter), which
//! adds per-value AES-256-GCM encryption and implements `EncryptedStorage`.
//!
//! # Why sealed?
//!
//! Encryption at rest is a security invariant, not a behavioral contract that
//! external code can meaningfully promise. Sealing the trait ensures the
//! compiler enforces the invariant — only code within `scp-platform` can vouch
//! for a backend's encryption.
//!
//! See issue #695 and spec §17.5.

pub(crate) mod private {
    /// Supertrait seal — prevents external implementations of
    /// [`EncryptedStorage`](super::EncryptedStorage).
    pub trait Sealed {}
}

/// Marker trait for [`Storage`](crate::traits::Storage) backends that encrypt
/// data at rest.
///
/// Sealed — only implementable inside `scp-platform`. External crates can
/// require this bound but cannot implement it. Wrap custom backends in
/// [`EncryptingAdapter`](crate::encrypting_adapter::EncryptingAdapter) to
/// satisfy the bound.
pub trait EncryptedStorage: crate::traits::Storage + private::Sealed {}

// ---------------------------------------------------------------------------
// Blanket impl for Arc<T> — matches the Storage blanket in traits.rs
// ---------------------------------------------------------------------------

impl<T: EncryptedStorage> private::Sealed for std::sync::Arc<T> {}
impl<T: EncryptedStorage> EncryptedStorage for std::sync::Arc<T> {}

// ---------------------------------------------------------------------------
// Implementations for production backends
// ---------------------------------------------------------------------------

#[cfg(feature = "sqlite")]
impl private::Sealed for crate::sqlite::SqliteStorage {}
#[cfg(feature = "sqlite")]
impl EncryptedStorage for crate::sqlite::SqliteStorage {}

#[cfg(feature = "apple")]
impl private::Sealed for crate::apple::storage::AppleStorage {}
#[cfg(feature = "apple")]
impl EncryptedStorage for crate::apple::storage::AppleStorage {}
