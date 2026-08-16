//! SQLCipher [`Storage`] adapter for Android.
//!
//! The Android storage adapter is implemented in Kotlin at
//! `bindings/kotlin/scp-kt-android/.../AndroidStorage.kt` and injected
//! into the Rust engine via the UniFFI callback interface (ADR-021). This module
//! documents the Rust-side contract and re-exports the trait types that the
//! Kotlin adapter implements.
//!
//! # Encryption Architecture (ADR-027)
//!
//! SQLCipher provides transparent full-database encryption. Android Keystore
//! holds a 256-bit HMAC-SHA-256 key (TEE-backed) under the alias
//! `scp.storage.key`, and its bytes never leave the TEE. The TEE computes one
//! HMAC over a fixed label, which gives the database a hardware-rooted chain of
//! trust, and HKDF-SHA-256 expands that HMAC output into the 32-byte SQLCipher
//! key under the salt and info that section 17.6 of
//! `.docs/specs/17-persistence-and-storage.md` fixes.
//!
//! The Kotlin adapter hands SQLCipher that key through raw-key syntax,
//! `x'<64 hex chars>'`, exactly as [`crate::sqlite::SqliteStorage`] and the
//! Apple adapter send it through `PRAGMA key`. The Rust-side test
//! `sqlcipher_raw_key_argument_opens_a_database_this_adapter_wrote` in
//! `crates/scp-platform/src/sqlite/mod.rs` opens a database this crate wrote
//! using the byte string the Kotlin adapter builds.
//!
//! See ADR-027, the Android platform adapter, in `.docs/adrs/phase-6.md` for the
//! full design rationale, including its 2026-08-15 amendment recording that an
//! earlier revision derived the key by encrypting a label with AES-GCM under an
//! all-zero initialization vector.

pub use crate::traits::Storage;
