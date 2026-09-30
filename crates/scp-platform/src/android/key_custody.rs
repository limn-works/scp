//! Re-exports the key custody trait with its handle, key-type and custody-type
//! types for the Android Keystore adapter.
//!
//! The Kotlin class `AndroidKeyCustody` in
//! `bindings/kotlin/scp-kt-android/.../AndroidKeyCustody.kt` implements the Kotlin
//! `KeyCustodyProvider` interface in `Types.kt`, not [`KeyCustody`]; the [`super`] module
//! docs list where the two differ. ADR-021 and ADR-027 require the class to
//! implement the `UniFFI` `KeyCustodyProvider` callback interface and to be injected
//! into the Rust engine. The class does neither, and no code injects it into
//! the Rust engine. Story SCP-110 stays in progress while any acceptance
//! criterion its description in `.docs/prds/main.json` records as unmet
//! stands: the trait criterion, the Keystore-attested key-destruction
//! criterion, the criteria for the move to P-256, the P-256 pseudonym
//! keypair and the TEE-generated pseudonym secret, which the shipped Ed25519
//! and X25519 keys and the signature-derived pseudonym secret fail, and
//! acceptance criteria 2, 3 and 10. That description records that neither
//! ADR-027 nor SCP-110 says what the adapter reports for a Keystore key held
//! outside the TEE, puts that decision to a human through the open question
//! "Android Keystore key outside the TEE" in
//! `.docs/specs/00-open-questions.md`, and keeps criteria 2, 3 and 10 unmet
//! until it is decided. This module documents the Rust-side contract and
//! re-exports the trait with its handle, key-type and custody-type types for
//! Android builds.
//!
//! # Key Storage Strategy
//!
//! The Kotlin adapter ships an Ed25519 and X25519 scheme:
//!
//! - **Ed25519 on API 33+ (Android 13+):** Android Keystore natively supports
//!   `EdDSA` with `Ed25519` parameter spec. Keystore holds the key and does
//!   not hand its private bytes to the app. [`CustodyType::Hardware`] is
//!   reported for every Keystore key. The adapter does not read
//!   `KeyInfo.securityLevel`, so on a device whose `KeyMint` runs in software
//!   (an API 33 emulator, for one) the key is held in software and the adapter
//!   still reports [`CustodyType::Hardware`].
//!
//! - **Ed25519 on API 26-32:** Bouncy Castle software Ed25519 fallback.
//!   [`CustodyType::Software`] is reported.
//!
//! - **X25519 (all API levels):** Always software-managed via Bouncy Castle.
//!   The adapter does not use the X25519 key agreement Android Keystore offers
//!   from API 33. [`CustodyType::Software`] is reported.
//!
//! ADR-027, as amended on 2026-09-10, requires a different scheme: an EC
//! P-256 signing key in Keystore at every supported API level, and P-256 key
//! agreement in Keystore from API 31 with a Bouncy Castle software P-256
//! agreement key below it. The adapter has not moved to P-256; story SCP-110
//! tracks that move.
//!
//! # `StrongBox`
//!
//! The adapter does not request `StrongBox`, due to its 10-100x latency penalty
//! incompatible with SCP's frequent signing operations; Keystore chooses where
//! to put the key.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::{CustodyType, KeyCustody, KeyHandle, KeyType};
