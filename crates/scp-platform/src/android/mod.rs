//! Android platform adapter modules for SCP.
//!
//! This module declares the four Android platform adapter modules. The
//! adapters themselves are Kotlin classes in `bindings/kotlin/scp-kt-android/`.
//! Each Kotlin class implements a Kotlin interface in `Types.kt`, not a trait
//! in [`crate::traits`] (ADR-021, ADR-027). The four Kotlin interfaces follow
//! different Rust declarations:
//!
//! - `DeviceAttestationProvider` restates the `UniFFI` callback interface of
//!   the same name in `crates/scp-ffi/uniffi/src/lib.rs`: `attest(challenge,
//!   deviceId)` and `assertRequest(requestHash)` take and return bytes.
//! - `KeyCustodyProvider` follows the Rust [`crate::traits::KeyCustody`]
//!   trait: its methods take a `KeyHandle` and a `KeyType`, while the `UniFFI`
//!   `KeyCustodyProvider` callback's methods take a `String` key ID and a
//!   `String` key type. Its methods are synchronous, while the methods of both
//!   Rust declarations are `async`.
//! - `PushProvider` follows the Rust [`crate::traits::Push`] trait: its
//!   `register` returns a `String` token and its `handleNotification` takes a
//!   `Map<String, String>` payload and returns a `WakeSignal`, while the
//!   `UniFFI` `PushProvider` callback's `register_push` and
//!   `handle_notification` return bytes.
//! - `StorageProvider` uses the method names of the `UniFFI`
//!   `StorageProvider` callback (`set`, `get`, `listKeys`, `deletePrefix`),
//!   where the Rust [`crate::traits::Storage`] trait names two of them `store`
//!   and `retrieve`. Its methods are synchronous, while the methods of both
//!   Rust declarations are `async`.
//!
//! # Adapter Modules
//!
//! - [`key_custody`] — Android Keystore key management (TEE-backed Ed25519 on
//!   API 33+, Bouncy Castle software fallback on API 26-32).
//! - [`device_attestation`] — Play Integrity device attestation (a Classic
//!   request today; story SCP-111 tracks the Standard request ADR-027 requires).
//! - [`push_provider`] — Firebase Cloud Messaging with opaque data-only payloads.
//! - [`storage`] — `SQLCipher` encrypted storage with TEE-derived AES-256 key.
//!
//! # Conditional Compilation
//!
//! This module is only compiled for Android targets (`target_os = "android"`).
//! See the `#[cfg]` gate in `lib.rs`.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

/// Android Keystore key custody adapter.
pub mod key_custody;

/// Play Integrity device attestation adapter.
pub mod device_attestation;

/// Firebase Cloud Messaging push provider adapter.
pub mod push_provider;

/// SQLCipher encrypted storage adapter.
pub mod storage;

pub use device_attestation::{DeviceAttestation, DeviceAttestationToken};
pub use key_custody::{CustodyType, KeyCustody, KeyHandle, KeyType};
pub use push_provider::{Push, PushToken, WakeSignal};
pub use storage::Storage;
