//! Firebase Cloud Messaging [`Push`] adapter for Android.
//!
//! The Android push provider is implemented in Kotlin at
//! `bindings/kotlin/scp-kt-android/.../AndroidPushProvider.kt` and
//! injected into the Rust engine via the UniFFI callback interface (ADR-021).
//! This module documents the Rust-side contract and re-exports the trait types
//! that the Kotlin adapter implements.
//!
//! # FCM Payload Opacity (ADR-027, section 10.7)
//!
//! The relay sends **only** `{"data": {"scp": "1"}}` -- a data-only message
//! with no notification fields. No context ID, sender DID, message preview, or
//! any SCP-specific content appears in the FCM payload. The app wakes, connects
//! to the SCP relay, and pulls all pending encrypted envelopes.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::{Push, PushToken, WakeSignal};
