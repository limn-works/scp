//! Play Integrity [`DeviceAttestation`] adapter for Android.
//!
//! The Android device attestation adapter is implemented in Kotlin at
//! `bindings/kotlin/scp-kt-android/.../AndroidDeviceAttestation.kt` and
//! injected into the Rust engine via the UniFFI callback interface (ADR-021).
//! This module documents the Rust-side contract and re-exports the trait types
//! that the Kotlin adapter implements.
//!
//! # Play Integrity request (ADR-027)
//!
//! The Kotlin adapter requests a Classic integrity token, passing a nonce
//! through `IntegrityTokenRequest.builder().setNonce(nonce)`. ADR-027 requires
//! a Standard integrity request whose `requestHash` is the lowercase
//! hexadecimal form of the binding digest, and story SCP-111 tracks that
//! change.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::{DeviceAttestation, DeviceAttestationToken};
