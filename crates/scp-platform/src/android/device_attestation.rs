//! Play Integrity [`DeviceAttestation`] adapter for Android.
//!
//! The Android device attestation adapter is implemented in Kotlin at
//! `bindings/kotlin/scp-kt-android/.../AndroidDeviceAttestation.kt` and
//! injected into the Rust engine via the UniFFI callback interface (ADR-021).
//! This module documents the Rust-side contract and re-exports the trait types
//! that the Kotlin adapter implements.
//!
//! # Play Integrity Standard API (ADR-027)
//!
//! Standard integrity requests return a verdict signed by Google's servers,
//! sufficient for SCP's attestation purpose. Classic attestation (APK certificate
//! chain) is not used -- it has stricter rate limits and is designed for offline
//! scenarios SCP does not have.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::{DeviceAttestation, DeviceAttestationToken};
