//! Android platform adapter modules for SCP.
//!
//! This module declares and re-exports the four Android platform adapters that
//! implement the traits defined in [`crate::traits`]. The actual implementations
//! are in Kotlin at `bindings/kotlin/scp-kt-android/` and are injected
//! into the Rust engine via UniFFI callback interfaces (ADR-021, ADR-027).
//!
//! # Adapter Modules
//!
//! - [`key_custody`] — Android Keystore key management (TEE-backed Ed25519 on
//!   API 33+, Bouncy Castle software fallback on API 26-32).
//! - [`device_attestation`] — Play Integrity Standard API for device attestation.
//! - [`push_provider`] — Firebase Cloud Messaging with opaque data-only payloads.
//! - [`storage`] — SQLCipher encrypted storage with TEE-derived AES-256 key.
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
