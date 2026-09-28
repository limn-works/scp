//! Firebase Cloud Messaging push adapter for Android.
//!
//! The Kotlin class `AndroidPushProvider` in
//! `bindings/kotlin/scp-kt-android/.../AndroidPushProvider.kt` implements the
//! Kotlin `PushProvider` interface in `Types.kt`, not [`Push`] (ADR-021); the
//! [`super`] module docs list where the two differ. No code injects the Kotlin
//! adapter into the Rust engine yet. This module documents the Rust-side
//! contract and re-exports the trait types for Android builds.
//!
//! # FCM Payload Opacity (ADR-027, section 10.7)
//!
//! Section 10.7 requires the sender of a push to send **only**
//! `{"data": {"scp": "1"}}`, a data-only message with no notification fields.
//! No context ID, sender DID, message preview, or any SCP-specific content may
//! appear in the FCM payload. No relay or other code in this repository sends
//! an FCM message, and no SDK code wakes the app, connects to a relay, or pulls
//! envelopes: the caller does all three when the Kotlin adapter returns
//! `WakeSignal.PULL`.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::{Push, PushToken, WakeSignal};
