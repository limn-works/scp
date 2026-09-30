//! Android platform adapter modules for SCP.
//!
//! This module declares four modules, one per Android adapter capability. Each
//! re-exports from [`crate::traits`] the platform trait for its capability and
//! holds no adapter code. Three also re-export some of their trait's types:
//! [`key_custody`] re-exports [`KeyHandle`], [`KeyType`] and [`CustodyType`]
//! but not `Signature`, `PublicKey`, `SharedSecret` or `PseudonymKeypair`,
//! which [`KeyCustody`] methods return; [`device_attestation`] re-exports
//! [`DeviceAttestationToken`]; and [`push_provider`] re-exports [`PushToken`]
//! and [`WakeSignal`].
//! The adapters themselves are Kotlin classes in `bindings/kotlin/scp-kt-android/`.
//! ADR-021 (the `UniFFI` bridge) and ADR-027 (the Android platform adapter)
//! require each Kotlin class to implement the `UniFFI` callback interface for
//! its capability and to be injected into the Rust engine. No shipped class
//! does either. Each Kotlin class implements a Kotlin interface in `Types.kt`,
//! and no code injects any of them into the Rust engine. Stories SCP-110 to
//! SCP-113 of `.docs/prds/main.json` stay in progress while any acceptance
//! criterion their descriptions record as unmet stands; each adapter's trait
//! criterion is one of them. Story SCP-214 tracks injecting a
//! key-custody provider into the Rust engine. No Kotlin interface matches both
//! the Rust trait in [`crate::traits`] and the `UniFFI` callback interface in
//! `crates/scp-ffi/uniffi/src/lib.rs` for its capability:
//!
//! - `DeviceAttestationProvider` restates the methods of the `UniFFI`
//!   callback interface of the same name: `attest(challenge, deviceId)` and
//!   `assertRequest(requestHash)` take and return bytes and suspend. It
//!   differs from the callback in its error type (see the paragraph
//!   after this list). The
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
//!   Kotlin methods name a key by a Kotlin `KeyHandle`, a data class of a
//!   `String` id and a `CustodyType`, while the trait's [`KeyHandle`] is a
//!   different type, an opaque `u64`, and the `UniFFI` callback's methods take
//!   a `String` key ID. The Kotlin `generateKeypair` takes a `KeyType` enum,
//!   as the trait's takes a [`KeyType`] enum of the same two variants, while
//!   the callback's takes a `String` key type. The Kotlin
//!   `deriveRotatablePseudonym` takes its epoch as a signed `Long`, while both
//!   Rust declarations take a `u64`, which `UniFFI` generates in Kotlin as
//!   `ULong`. The Kotlin `generateKeypair` returns a Kotlin `KeyHandle`, while
//!   the trait's returns its `u64` [`KeyHandle`] and the callback's
//!   `generate_keypair` returns a `String` key ID. The Kotlin `destroyKey`
//!   returns a
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
//!   method of both Rust declarations is `async`. The Kotlin `deletePrefix`
//!   returns a signed `Long`, while both Rust declarations return a `u64`,
//!   which `UniFFI` generates in Kotlin as `ULong`.
//!
//! No Kotlin interface throws the exception class the `UniFFI` callbacks
//! declare. The Kotlin interfaces throw the `scp-kt-android` class
//! `works.limn.scp.android.platform.ScpException`, and the adapters also let
//! other throwables escape. Each `UniFFI` callback declares `ScpError`, which
//! `UniFFI` generates in Kotlin as a different class,
//! `uniffi.scp.ScpException`, and each Rust trait returns a
//! [`crate::PlatformError`]. ADR-027 states that a `UniFFI` callback that
//! throws any exception other than the generated one panics the Rust caller.
//!
//! # Adapter Modules
//!
//! Each bullet names the module that re-exports a capability's trait and
//! describes the Kotlin adapter class for that capability.
//!
//! - [`key_custody`] — Android Keystore key management (Keystore-held Ed25519
//!   on API 33+, reported as hardware custody without a `KeyInfo.securityLevel`
//!   check, Bouncy Castle software fallback on API 26-32, and in-memory
//!   software X25519 key agreement at every API level, today; ADR-027
//!   requires a P-256 signing key in Keystore at every supported API level and
//!   P-256 key agreement in Keystore from API 31; story SCP-110 tracks both
//!   moves).
//! - [`device_attestation`] — Play Integrity device attestation (a Classic
//!   request today; story SCP-111 tracks the Standard request ADR-027 requires).
//! - [`push_provider`] — Firebase Cloud Messaging; checks only the `scp` wake
//!   field of a data-only payload and returns the same wake signal whatever
//!   other fields it carries. §10.7 opacity binds the sender (§10.7.1 step 5
//!   of the infrastructure spec), and no code in this repository sends a push,
//!   so SCP-112's opacity criterion is unmet.
//! - [`storage`] — `SQLCipher` encrypted storage whose 32-byte passphrase is
//!   derived from a Keystore-held AES-256 key; `SQLCipher` derives the database
//!   key from that passphrase.
//!
//! # Conditional Compilation
//!
//! This module is only compiled for Android targets (`target_os = "android"`).
//! See the `#[cfg]` gate in `lib.rs`.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

/// Re-exports the key custody trait and its handle, key type and custody type
/// types; the Kotlin `AndroidKeyCustody` class is the Android Keystore adapter.
pub mod key_custody;

/// Re-exports the device attestation trait and its token type; the Kotlin
/// `AndroidDeviceAttestation` class is the Play Integrity adapter.
pub mod device_attestation;

/// Re-exports the push trait and its types; the Kotlin `AndroidPushProvider`
/// class is the Firebase Cloud Messaging adapter.
pub mod push_provider;

/// Re-exports the storage trait; the Kotlin `AndroidStorage` class is the
/// `SQLCipher` encrypted storage adapter.
pub mod storage;

pub use device_attestation::{DeviceAttestation, DeviceAttestationToken};
pub use key_custody::{CustodyType, KeyCustody, KeyHandle, KeyType};
pub use push_provider::{Push, PushToken, WakeSignal};
pub use storage::Storage;
