//! Play Integrity device attestation adapter for Android.
//!
//! The Kotlin class `AndroidDeviceAttestation` in
//! `bindings/kotlin/scp-kt-android/.../AndroidDeviceAttestation.kt` implements
//! the Kotlin `DeviceAttestationProvider` interface in `Types.kt`. That
//! interface restates the `UniFFI` `DeviceAttestationProvider` callback
//! interface in `crates/scp-ffi/uniffi/src/lib.rs`, and no Rust code calls
//! that callback yet. The Kotlin adapter does not implement
//! [`DeviceAttestation`], whose `attest` takes no argument, which declares a
//! `verify` method the Kotlin interface lacks, and which declares no
//! `assert_request`, while the Kotlin interface declares `assertRequest`. OQ-22 of
//! `.docs/specs/27-attestations.md` keeps two questions open: which of the two
//! traits is normative, and whether that trait's `attest` takes the binding
//! digest `D` or `D`'s two inputs (a challenge and an identifier). This
//! module re-exports [`DeviceAttestation`] and [`DeviceAttestationToken`] for
//! Android builds.
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
