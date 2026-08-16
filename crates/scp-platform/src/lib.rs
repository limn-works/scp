#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
//! Platform abstraction layer for SCP.
//!
//! This crate defines the four platform abstraction traits that every SCP
//! component depends on for device-specific capabilities:
//!
//! - [`KeyCustody`] — Cryptographic key management (generation, signing, ECDH,
//!   pseudonym derivation). Production: Secure Enclave (iOS), Android Keystore.
//! - [`DeviceAttestation`] — Device attestation tokens (App Attest, Play Integrity).
//! - [`Push`] — Push notification registration and handling (APNs, FCM).
//! - [`Storage`] — Persistent key-value byte storage (Keychain, encrypted `SQLite`).
//!
//! All traits are `Send + Sync` with async methods, designed for injection
//! through initializers. Production implementations use hardware security;
//! testing implementations (in-memory, see ADR-006) provide identical API
//! surfaces with no external dependencies.
//!
//! # Architecture
//!
//! See ADR-006 ("In-Memory Platform Adapter") in `.docs/adrs/phase-1.md` for
//! the full design rationale. The trait definitions in this crate are the
//! authoritative source for all platform adapter contracts.
//!
//! # Usage
//!
//! Components accept platform traits as generic parameters or trait objects:
//!
//! ```rust,ignore
//! async fn create_identity<K: scp_platform::KeyCustody>(custody: &K) {
//!     let handle = custody.generate_keypair(scp_platform::KeyType::Ed25519).await?;
//!     // ...
//! }
//! ```

#![forbid(unsafe_code)]

#[cfg(target_os = "android")]
pub mod android;
#[cfg(feature = "apple")]
pub mod apple;
// Shared AES-256-GCM sealing for one private-key entry, with the `key_type`
// discriminant bound as AAD (GitHub issue #2299). `FileKeyCustody` (`file`) and
// `SqliteKeyCustody` (`sqlite` + `software_platform`) both seal through it, so
// one implementation decides how the discriminant is bound to the key bytes.
#[cfg(any(
    feature = "file",
    all(feature = "sqlite", feature = "software_platform")
))]
pub(crate) mod custody_aead;
pub mod encrypted;
#[cfg(feature = "encrypting")]
pub mod encrypting_adapter;
pub mod error;
#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "filesystem")]
pub mod filesystem;
// Durability-only in-memory adapters (`InMemoryStorage`, `InMemoryPush`) —
// each gated behind its own durability-only feature (`in-memory-storage` /
// `in-memory-push`), NOT `testing`. These arms lose state but nullify no
// security property (spec §17.17.2 durability-only-vs-nullifier
// classification), so they are shippable and selected explicitly (e.g. via
// `StorageConfig`), never a default or fallback (spec §17.17 selection
// mandatory / never-default / never-fallback). Kept separate from the
// `testing`-gated nullifier doubles so a build can compile the durable dev
// affordance without pulling in `InMemoryKeyCustody`. See ADR-062 §0.
#[cfg(any(feature = "in-memory-storage", feature = "in-memory-push"))]
pub mod in_memory;
// Test-only nullifier doubles (`InMemoryKeyCustody`,
// `InMemoryDeviceAttestation`, `InMemoryPreRotationCustody`) — gated by the
// `testing` feature, NOT by `software_platform`. This ensures production
// mobile builds can enable `software_platform` (for crypto primitives)
// without compiling in insecure in-memory key storage. See GitHub issue #88,
// ADR-006, and the honest-module-structure split in ADR-062 §0.
#[cfg(feature = "testing")]
pub mod testing;
// Shared Argon2id passphrase→key derivation (spec §17.6 / §17.8). Single
// source of the Argon2id parameterization; used by FileKeyCustody (`file`)
// and the SqliteStorage passphrase constructor (`sqlite`).
#[cfg(any(feature = "file", feature = "sqlite"))]
pub mod kdf;
#[cfg(feature = "sqlite")]
pub mod sqlite;
// Versioned storage envelope + spec §17.3 key conventions. The single source of
// the `StoredValue` format and `identity/{did}/document` key convention shared
// by `scp-runtime`'s `ProtocolRepository` and `scp-identity`'s `Identity::create`
// persistence path, so both produce byte-identical storage writes.
pub mod store_value;
#[cfg(feature = "sync")]
pub mod syncable;
pub mod traits;

// Re-export all public types for ergonomic access.
pub use encrypted::EncryptedStorage;
pub use error::PlatformError;
pub use store_value::{
    CURRENT_STORE_VERSION, StoreValueError, StoredValue, from_stored_value_bytes,
    identity_document_key, sanitize_key_component, to_stored_value_bytes,
};
pub use traits::{
    CustodyType, DeviceAttestation, DeviceAttestationToken, KeyCustody, KeyHandle, KeyType,
    PreRotationCustody, PreRotationCustodyError, PreRotationCustodyKind, PreRotationKeyHandle,
    PseudonymKeypair, PublicKey, Push, PushToken, SharedSecret, Signature, Storage, WakeSignal,
};
