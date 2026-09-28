//! Android Keystore key custody adapter.
//!
//! The Kotlin class `AndroidKeyCustody` in
//! `bindings/kotlin/scp-kt-android/.../AndroidKeyCustody.kt` implements the
//! Kotlin `KeyCustodyProvider` interface in `Types.kt`, not [`KeyCustody`]
//! (ADR-021); the [`super`] module docs list where the two differ. No code
//! injects the Kotlin adapter into the Rust engine yet. This module documents
//! the Rust-side contract and re-exports the trait types for Android builds.
//!
//! # Key Storage Strategy (ADR-027)
//!
//! - **Ed25519 on API 33+ (Android 13+):** Android Keystore natively supports
//!   `EdDSA` with `Ed25519` parameter spec. Keys are TEE-backed -- the private
//!   key bytes never leave the Trusted Execution Environment.
//!   [`CustodyType::Hardware`] is reported.
//!
//! - **Ed25519 on API 26-32:** Bouncy Castle software Ed25519 fallback.
//!   [`CustodyType::Software`] is reported.
//!
//! - **X25519 (all API levels):** Always software-managed via Bouncy Castle.
//!   Android Keystore does not support X25519. [`CustodyType::Software`] is
//!   reported.
//!
//! # TEE vs StrongBox
//!
//! TEE is the default and only option. StrongBox is not used due to 10-100x
//! latency penalty incompatible with SCP's frequent signing operations.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::{CustodyType, KeyCustody, KeyHandle, KeyType};
