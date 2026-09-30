//! Firebase Cloud Messaging push adapter for Android.
//!
//! The Kotlin class `AndroidPushProvider` in
//! `bindings/kotlin/scp-kt-android/.../AndroidPushProvider.kt` implements the Kotlin
//! `PushProvider` interface in `Types.kt`, not [`Push`]; the [`super`] module
//! docs list where the two differ. ADR-021 and ADR-027 require the class to
//! implement the `UniFFI` `PushProvider` callback interface and to be injected
//! into the Rust engine. The class does neither, and no code injects it into
//! the Rust engine. Story SCP-112 stays in progress while any acceptance
//! criterion its description in `.docs/prds/main.json` records as unmet
//! stands; the trait criterion is one of five. This module documents the
//! Rust-side contract and
//! re-exports the trait types for Android builds.
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
//! Opacity is an obligation on the sender: §10.7.1 step 5 has the relay send
//! exactly `{ "scp": 1 }`. FCM has carried every field of a payload before
//! the Kotlin adapter sees it, so no receive-side check can keep a field from
//! FCM, and no code in this repository sends a push. SCP-112's criterion "FCM
//! payload format is opaque" is unmet because no sender exists; rejecting
//! extra fields on receipt would not meet it.
//!
//! See ADR-027 in `.docs/adrs/phase-6.md` for the full design rationale.

pub use crate::traits::{Push, PushToken, WakeSignal};
