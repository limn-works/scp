//! `SQLCipher` storage adapter for Android.
//!
//! The Kotlin class `AndroidStorage` in
//! `bindings/kotlin/scp-kt-android/.../AndroidStorage.kt` implements the
//! Kotlin `StorageProvider` interface in `Types.kt`, not [`Storage`]
//! (ADR-021); the [`super`] module docs list where the two differ. No code
//! injects the Kotlin adapter into the Rust engine yet. This module documents
//! the Rust-side contract and re-exports the trait type for Android builds.
//!
//! # Encryption Architecture (ADR-027)
//!
//! `SQLCipher` provides transparent full-database encryption. The `SQLCipher` key
//! is a 32-byte value derived from an AES-256 key that Android Keystore
//! generates and holds. Keystore does not hand the AES key to the app; it encrypts a
//! fixed label via AES-GCM with a fixed IV, and the first 32 bytes of the
//! output (ciphertext followed by part of the GCM tag) are the `SQLCipher` key.
//! That derived key sits in process memory while the database is open. The
//! adapter does not read `KeyInfo.securityLevel`, so it does not know whether
//! Keystore put the AES key in the TEE or, on a device whose `KeyMint` runs in
//! software, in software.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::Storage;
