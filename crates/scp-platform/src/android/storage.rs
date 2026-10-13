//! Re-exports the storage trait for the Android `SQLCipher` adapter.
//!
//! The Kotlin class `AndroidStorage` in
//! `bindings/kotlin/scp-kt-android/.../AndroidStorage.kt` implements the Kotlin
//! `StorageProvider` interface in `Types.kt`, not [`Storage`]; the [`super`] module
//! docs list where the two differ. ADR-021 and ADR-027 require the class to
//! implement the `UniFFI` `StorageProvider` callback interface and to be injected
//! into the Rust engine. The class does neither, and no code injects it into
//! the Rust engine. Story SCP-113 stays in progress while any acceptance
//! criterion its description in `.docs/prds/main.json` records as unmet
//! stands; the trait criterion is one of them. This module documents the
//! Rust-side contract and re-exports the trait type for Android builds.
//!
//! # Encryption Architecture (ADR-027)
//!
//! `SQLCipher` provides transparent full-database encryption. The adapter derives
//! the 32-byte database key as §17.6 of `.docs/specs/17-persistence-and-storage.md`
//! requires. A non-exportable HMAC-SHA-256 key that Android Keystore generates and
//! holds MACs a fixed label, and HKDF-SHA-256 expands that MAC output under the
//! salt `SHA-256("SCP-SQLCIPHER-KEY-V1")` and the info `"scp-sqlcipher:"` followed
//! by the SHA-256 digest of the database directory's path. The adapter passes the
//! key to `SQLCipher` as the raw-key literal `x'<64 hex>'`. The database key sits
//! in process memory while the database is open. The adapter does not read
//! `KeyInfo.securityLevel`, so it does not know whether Keystore put the HMAC key
//! in the TEE or, on a device whose `KeyMint` runs in software, in software.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::Storage;
