//! Android Keystore [`KeyCustody`] adapter.
//!
//! The Android key custody adapter is implemented in Kotlin at
//! `bindings/kotlin/scp-kt-android/.../AndroidKeyCustody.kt` and injected
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
//!
//! # No `CustodySubstrate` implementation lives here
//!
//! This module declares no Rust type, so there is nothing here for
//! `scp_did::attestation::CustodySubstrate` to describe. The Kotlin adapter
//! crosses the FFI boundary as a `UniFFI` callback, and the Rust side receives
//! it as `CallbackKeyCustody` in `crates/scp-ffi/uniffi/src/bridge.rs`. That
//! callback interface carries one custody question today — `custody_type`,
//! which returns a `CustodyType` string — and asks the adapter neither whether
//! the key can leave the Android Keystore nor which factor unlocks it. An
//! Android identity therefore publishes no `ScpKeyCustodyAttestation` until
//! that interface asks the adapter those two questions across all three
//! bridges.

pub use crate::traits::{CustodyType, KeyCustody, KeyHandle, KeyType};
