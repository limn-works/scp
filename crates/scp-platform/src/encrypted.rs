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
//! # What the marker proves, and what it does not
//!
//! The seal is load-bearing: the argument that a no-op or in-memory backend
//! cannot reach `Node::start` rests on the bound `S: EncryptedStorage` plus the
//! fact that no crate outside `scp-platform` can implement it. That argument
//! holds. The bound proves a narrower property than "the data at rest is
//! confidential", and a reader who takes the bound for that wider claim is
//! wrong in three specific ways.
//!
//! **The marker proves that every implementor runs a cipher over the values it
//! writes.** `SqliteStorage` and `AppleStorage` reject any key that is not
//! [`SQLCIPHER_KEY_LEN`] bytes at their constructors, so neither can reach
//! `SQLCipher`'s no-encryption mode (`PRAGMA key = "x''"`); before that check
//! existed, an empty key produced a plaintext database behind this marker.
//! `EncryptingAdapter` takes its key as `Zeroizing<[u8; 32]>`, so its length is
//! fixed by the type.
//!
//! **The marker does not prove that the caller chose a secret key.**
//! `SqliteStorage::new(dir, &[0u8; 32])` passes the length check and produces a
//! database encrypted under a key an attacker can guess. No trait bound can
//! constrain the entropy of bytes a caller supplies, so key derivation —
//! HKDF-SHA-256 from the `#0` identity key, or Argon2id from a passphrase (spec
//! §17.6) — is a caller obligation that sits above this marker, not inside it.
//!
//! **The marker does not prove that key names are encrypted.**
//! `EncryptingAdapter` encrypts values and passes key strings through to the
//! inner backend unmodified, which spec §17.5 states and relies on: the
//! `ProtocolRepository` key convention is deterministic and not secret. A
//! reader who takes `EncryptedStorage` to mean "an observer of the medium
//! learns nothing" is therefore wrong for that implementor.
//!
//! **The marker does not prove durability.** `EncryptingAdapter<InMemoryStorage>`
//! satisfies the bound and writes nothing to any medium. Durability is a
//! separate axis, governed by SCP-CAPSEL-8011 (spec §17.17.2), and the caller
//! selects it explicitly.
//!
//! See GitHub issue #695 (compile-time encryption enforcement) and spec §17.5
//! (serialization and the `EncryptedStorage` marker).

/// Length in bytes of the raw `SQLCipher` PRAGMA key (spec §17.6).
///
/// Spec §17.6 derives the PRAGMA key as 32 bytes — `HKDF-Expand(prk, info, 32)`
/// in raw-key mode, `argon2id(...)` with `output_len = 32` in passphrase mode —
/// and hex-encodes those 32 bytes into the 64-character `x'…'` literal. Any
/// other length is not a `SQLCipher` key the first-party adapters can produce
/// or accept.
///
/// The zero-length case costs confidentiality rather than compatibility:
/// `PRAGMA key = "x''"` selects `SQLCipher`'s no-encryption mode, so the
/// database opens and stores every value in plaintext while the adapter still
/// satisfies [`EncryptedStorage`]. `SqliteStorage::new` and `AppleStorage::open`
/// both reject a key of any other length with
/// [`PlatformError::InvalidKeyLength`](crate::error::PlatformError::InvalidKeyLength).
pub const SQLCIPHER_KEY_LEN: usize = 32;

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
