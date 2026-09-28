//! Android platform adapter modules for SCP.
//!
//! This module declares the four Android platform adapter modules. The
//! adapters themselves are Kotlin classes in `bindings/kotlin/scp-kt-android/`.
//! Each Kotlin class implements a Kotlin interface in `Types.kt`, not a trait
//! in [`crate::traits`] (ADR-021, ADR-027). No Kotlin interface matches both
//! the Rust trait and the `UniFFI` callback interface in
//! `crates/scp-ffi/uniffi/src/lib.rs` for its capability:
//!
//! - `DeviceAttestationProvider` restates the `UniFFI` callback interface of
//!   the same name: `attest(challenge, deviceId)` and
//!   `assertRequest(requestHash)` take and return bytes. The
//!   [`crate::traits::DeviceAttestation`] trait's `attest` takes no argument,
//!   the trait declares a `verify` method the Kotlin interface lacks, and it
//!   declares no `assert_request`, while the Kotlin interface declares
//!   `assertRequest`.
//! - `KeyCustodyProvider` declares the methods of the `UniFFI`
//!   `KeyCustodyProvider` callback except `custody_type`, and it names the
//!   callback's `get_public_key` `publicKey`, the name the Rust trait's
//!   `public_key` takes in Kotlin. The [`crate::traits::KeyCustody`] trait
//!   does not declare `export_signing_key_bytes`, and it also declares
//!   `custody_type`,
//!   `ed25519_to_x25519_agree`, `import_ed25519_signing_key` and
//!   `generate_ephemeral_ed25519_seed`, which the Kotlin interface lacks. The
//!   Kotlin methods take a `KeyHandle` and a `KeyType`, as the Rust trait's
//!   do, while the `UniFFI` callback's methods take a `String` key ID and a
//!   `String` key type. The Kotlin `generateKeypair` returns a `KeyHandle`, as
//!   the trait's does, while the callback's `generate_keypair` returns a
//!   `String` key ID. The Kotlin `destroyKey` returns a
//!   `DestructionAttestation`, while both Rust declarations return nothing.
//!   The Kotlin pseudonym methods return a `PseudonymKeyHandle`, while the
//!   trait returns a `PseudonymKeypair` and the callback returns bytes. The
//!   Kotlin `sign`, `publicKey` and `dhAgree` return a `ByteArray`, as the
//!   callback's methods return bytes, while the trait returns a `Signature`, a
//!   `PublicKey` and a `SharedSecret`. The Kotlin methods are synchronous;
//!   every method of both Rust declarations is `async` except `custody_type`,
//!   which is synchronous in both.
//! - `PushProvider`'s `register` returns a `String` token and suspends, and
//!   its `handleNotification` takes a `Map<String, String>` payload, returns a
//!   `WakeSignal`, and is synchronous. The [`crate::traits::Push`] trait's
//!   `register` returns a [`crate::traits::PushToken`] of bytes, its
//!   `handle_notification` takes the payload as `&[u8]`, and both are
//!   `async`. The `UniFFI` `PushProvider` callback names the two methods
//!   `register_push` and `handle_notification`; both are `async`,
//!   `register_push` returns bytes, and `handle_notification` takes and
//!   returns bytes.
//! - `StorageProvider` declares the six methods of the `UniFFI`
//!   `StorageProvider` callback under the same names (`set`, `get`, `delete`,
//!   `listKeys`, `deletePrefix`, `exists`). The [`crate::traits::Storage`]
//!   trait declares the same six operations but names `set` and `get` as
//!   `store` and `retrieve`. The Kotlin methods are synchronous, while every
//!   method of both Rust declarations is `async`.
//!
//! # Adapter Modules
//!
//! - [`key_custody`] — Android Keystore key management (TEE-backed Ed25519 on
//!   API 33+, Bouncy Castle software fallback on API 26-32, today; ADR-027
//!   requires P-256, and no story tracks that move yet).
//! - [`device_attestation`] — Play Integrity device attestation (a Classic
//!   request today; story SCP-111 tracks the Standard request ADR-027 requires).
//! - [`push_provider`] — Firebase Cloud Messaging with opaque data-only payloads.
//! - [`storage`] — `SQLCipher` encrypted storage whose 32-byte key is derived
//!   from a TEE-held AES-256 key.
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
