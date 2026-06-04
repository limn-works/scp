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

pub mod encrypted;
#[cfg(feature = "encrypting")]
pub mod encrypting_adapter;
pub mod error;
// In-memory platform adapters — gated by the `testing` feature, NOT by
// `software_platform`. This ensures production mobile builds can enable
// `software_platform` (for crypto primitives) without compiling in insecure
// in-memory key storage. See GitHub issue #88 and ADR-006.
#[cfg(feature = "testing")]
pub mod testing;
// `software` is an alias for `testing` that matches the historical path. New
// code should prefer `scp_platform::testing::*`; `software::*` paths remain
// valid for backwards compatibility.
#[cfg(feature = "testing")]
pub use testing as software;
#[cfg(target_os = "android")]
pub mod android;
#[cfg(feature = "apple")]
pub mod apple;
#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "filesystem")]
pub mod filesystem;
// Shared Argon2id passphrase→key derivation (spec §17.6 / §17.8). Single
// source of the Argon2id parameterization; used by FileKeyCustody (`file`)
// and the SqliteStorage passphrase constructor (`sqlite`).
#[cfg(any(feature = "file", feature = "sqlite"))]
pub mod kdf;
// Shared pseudonym secret derivation — used by all KeyCustody backends.
// Gated behind `software_platform` because it depends on ed25519-dalek, hkdf, sha2.
#[cfg(feature = "software_platform")]
pub(crate) mod pseudonym;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "sync")]
pub mod syncable;
pub mod traits;

// Re-export all public types for ergonomic access.
pub use encrypted::EncryptedStorage;
pub use error::PlatformError;
pub use traits::{
    CustodyType, DeviceAttestation, DeviceAttestationToken, KeyCustody, KeyHandle, KeyType,
    PreRotationCustody, PreRotationCustodyError, PreRotationCustodyKind, PreRotationKeyHandle,
    PseudonymKeypair, PublicKey, Push, PushToken, SharedSecret, Signature, Storage, WakeSignal,
};
