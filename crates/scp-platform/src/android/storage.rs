//! Re-exports the storage trait for the Android `SQLCipher` adapter.
//!
//! The Kotlin class `AndroidStorage` in
//! `bindings/kotlin/scp-kt-android/.../AndroidStorage.kt` implements the Kotlin
//! `StorageProvider` interface in `Types.kt`, not [`Storage`]; the [`super`] module
//! docs list where the two differ. ADR-021 and ADR-027 require the class to
//! implement the `UniFFI` `StorageProvider` callback interface and to be injected
//! into the Rust engine. The class does neither, and no code injects it into
//! the Rust engine. Story SCP-113 stays in progress while the class fails its
//! trait criterion. This module documents the Rust-side contract and
//! re-exports the trait type for Android builds.
//!
//! # Encryption Architecture (ADR-027)
//!
//! `SQLCipher` provides transparent full-database encryption. The `SQLCipher`
//! passphrase is a 32-byte value derived from an AES-256 key that Android Keystore
//! generates and holds. Keystore does not hand the AES key to the app; it encrypts a
//! fixed label via AES-GCM with a fixed IV, and the first 32 bytes of the
//! output (ciphertext followed by part of the GCM tag) are the `SQLCipher`
//! passphrase, from which `SQLCipher` derives the database key. The database key
//! sits in process memory while the database is open. The
//! adapter does not read `KeyInfo.securityLevel`, so it does not know whether
//! Keystore put the AES key in the TEE or, on a device whose `KeyMint` runs in
//! software, in software.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::Storage;
