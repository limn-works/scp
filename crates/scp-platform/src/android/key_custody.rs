//! Android Keystore [`KeyCustody`] adapter.
//!
//! The Android key custody adapter is implemented in Kotlin at
//! `bindings/kotlin/scp-sdk-kotlin-android/.../AndroidKeyCustody.kt` and injected
//! into the Rust engine via the UniFFI callback interface (ADR-021). This module
//! documents the Rust-side contract and re-exports the trait types that the
//! Kotlin adapter implements.
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
