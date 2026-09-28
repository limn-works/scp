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
//! Section 10.7 requires a push payload to carry only a wake signal: no
//! sender, no context, no count, no preview. Its §10.7.1 step 5 gives that
//! payload as `{ "scp": 1 }`. ADR-027 carries the wake signal to Android as
//! the FCM data-only message `{"data": {"scp": "1"}}`, with no notification
//! fields and no other SCP-specific content. No relay or other code in this
//! repository sends an FCM message, and no SDK code wakes the app, connects to
//! a relay, or pulls envelopes: the caller does all three when the Kotlin
//! adapter returns `WakeSignal.PULL`.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::{Push, PushToken, WakeSignal};
