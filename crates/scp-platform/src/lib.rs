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
// The Rust-side custody record that fixes a callback key's type and role
// (spec §17.3 `custody/record/{namespace}/{key_id}`; SCP-345).
pub mod custody_record;
pub mod encrypted;
#[cfg(feature = "encrypting")]
pub mod encrypting_adapter;
pub mod error;
#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "filesystem")]
pub mod filesystem;
// The one type in this crate that takes an exclusive advisory file lock; it
// unlocks before it closes the file (spec §17.6, §17.8).
#[cfg(any(feature = "file", feature = "sqlite"))]
pub mod file_lock;
// The one durability-only in-memory adapter, `InMemoryStorage`, gated by the
// `in-memory-storage` feature, NOT `testing`. It loses state on restart but
// nullifies no security property (spec §17.17.2 durability-only-vs-nullifier
// classification), so a shipped build may compile it and select it
// explicitly (e.g. via `StorageConfig`), never as a default or fallback (spec
// §17.17 selection mandatory / never-default / never-fallback). See ADR-062 §0.
#[cfg(feature = "in-memory-storage")]
pub mod in_memory;
// Test-only doubles, gated by the `testing` feature, NOT by
// `software_platform`: the nullifiers `InMemoryKeyCustody`,
// `InMemoryDeviceAttestation`, and `InMemoryPreRotationCustody`, and
// `InMemoryPush`, whose UUID token no push service issued, so it delivers no
// wake. Production mobile builds enable `software_platform` (for crypto
// primitives) and compile none of these doubles. See GitHub issue #88,
// ADR-006, and ADR-062 §0 (amended 2026-10-12).
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
pub mod signer;
pub mod store_value;
#[cfg(feature = "sync")]
pub mod syncable;
pub mod traits;

// Re-export all public types for ergonomic access.
pub use custody_record::{CustodyRecord, CustodyRecordStore};
pub use encrypted::EncryptedStorage;
// The key-event signer contract (09-security-model.md §9.7.4.2 R10), so a
// custody implementor and its callers need no direct scp-kel dependency.
pub use error::{PlatformError, PushFailureKind};
pub use scp_kel::{
    CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, MaybeSend, ProbeSignature,
    SigningChange,
};
pub use signer::CustodySigner;
pub use store_value::{
    CURRENT_STORE_VERSION, StoreValueError, StoredValue, from_stored_value_bytes,
    identity_document_key, sanitize_key_component, to_stored_value_bytes,
};
pub use traits::{
    CustodyType, DeviceAttestation, DeviceAttestationToken, KeyCustody, KeyHandle, KeyRole,
    KeyType, NextSetCustody, NextSetCustodyError, NextSetKeyHandle, PreRotationCustody,
    PreRotationCustodyError, PreRotationCustodyKind, PreRotationKeyHandle, Pseudonym, PublicKey,
    Push, PushToken, SharedSecret, Signature, Storage, WakeSignal, refuse_key_event_mint,
    require_derive_source,
};
