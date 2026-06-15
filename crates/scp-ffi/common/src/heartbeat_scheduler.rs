//! Periodic suppression-detection heartbeat scheduler (§9.9.2).
//!
//! Spec §9.9.2 places heartbeat *sending* at the SDK layer:
//!
//! > In active contexts, the SDK SHOULD send periodic heartbeat envelopes
//! > (recommended interval: 60 seconds when the context has active
//! > participants).
//!
//! After the ADR-049 actor refactor the per-context actor has **no signer** —
//! its `key_resolver` resolves only *public* keys, and the `KeyCustody` signer
//! is not mailbox-addressable. The signing key lives at the FFI/SDK boundary,
//! the same layer that owns the relay subscription lifecycle. Therefore the
//! periodic heartbeat send originates here, in a task spawned alongside the
//! subscribe loop, and is routed through the actor's serialized send path via
//! [`Supervisor::send_heartbeat`] (the key enters per-call, exactly like
//! `send_message`). This mirrors the reconnection-driver location decision in
//! [`crate::reconnect`].
//!
//! The cadence is derived from the same per-profile source of truth the
//! receive-side gap monitor uses
//! ([`HeartbeatConfig::for_profile`](scp_transport::HeartbeatConfig::for_profile)),
//! so a sender's interval can never drift out of step with the threshold a
//! peer's monitor expects. `Constrained` profiles send no heartbeats (the
//! interval source returns `None`), matching the monitor's poll-based silence.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use scp_core::context::supervisor::Supervisor;
use scp_identity::DID;
use scp_transport::HeartbeatConfig;
use scp_transport::profile::TransportProfile;
use tokio_util::sync::CancellationToken;

/// Resolves the heartbeat send interval for a transport profile, or `None`
/// when the profile disables heartbeats (`Constrained`).
///
/// Thin pass-through over [`HeartbeatConfig::for_profile`] so bridges depend on
/// one symbol and the send cadence always matches the receive-side monitor's
/// expectation. Returning `None` is the signal to skip spawning the scheduler.
#[must_use]
pub fn heartbeat_interval(profile: TransportProfile) -> Option<std::time::Duration> {
    HeartbeatConfig::for_profile(profile).map(|c| c.interval)
}

/// Drives periodic heartbeat sends for one subscribed context until cancelled.
///
/// Loops on a timer at `interval`, calling
/// [`Supervisor::send_heartbeat`] each tick with the caller-held
/// `signing_key`. The send is best-effort: a transport failure is logged but
/// never breaks the loop, because a failed or undelivered heartbeat is itself a
/// suppression signal — surfaced by the *receiver's* gap detection, not by
/// tearing down the sender. The loop exits cleanly when either `cancel` (the
/// per-subscription token, cancelled on unsubscribe / disconnect) or
/// `bridge_cancel` (the bridge-shutdown token) fires.
///
/// The first immediate tick is consumed so the first heartbeat is sent one
/// full interval after subscription, not instantly (a brand-new subscription
/// has nothing to prove liveness against yet).
///
/// Intended to be `tokio::spawn`'d (or enrolled in the bridge's `JoinSet`)
/// alongside the relay subscribe loop. Holds an owned `Arc<Supervisor>` and an
/// owned key, so it has no borrow ties to the subscribe task.
pub async fn run_heartbeat_scheduler(
    supervisor: Arc<Supervisor>,
    context_id: String,
    sender_did: DID,
    signing_key: SigningKey,
    interval: std::time::Duration,
    cancel: CancellationToken,
    bridge_cancel: CancellationToken,
) {
    let mut timer = tokio::time::interval(interval);
    // Consume the immediate first tick — the first heartbeat fires one full
    // interval in, matching the receive-side monitor's baseline assumption.
    timer.tick().await;

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                tracing::debug!(
                    context_id = %context_id,
                    "heartbeat scheduler cancelled via subscription token"
                );
                return;
            }
            () = bridge_cancel.cancelled() => {
                tracing::debug!(
                    context_id = %context_id,
                    "heartbeat scheduler cancelled via bridge shutdown"
                );
                return;
            }
            _ = timer.tick() => {
                if let Err(e) = supervisor
                    .send_heartbeat(&context_id, &sender_did, &signing_key)
                    .await
                {
                    // Best-effort (§9.9.2): a failed send does not stop the
                    // schedule. Persistent failure surfaces on the peer side
                    // as a suppression suspicion via gap detection.
                    tracing::debug!(
                        context_id = %context_id,
                        error = %e,
                        "periodic heartbeat send failed (best-effort; scheduler continues)"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn constrained_profile_has_no_heartbeat_interval() {
        assert!(heartbeat_interval(TransportProfile::Constrained).is_none());
    }

    #[test]
    fn server_and_desktop_share_the_default_interval() {
        let server = heartbeat_interval(TransportProfile::Server).unwrap();
        let desktop = heartbeat_interval(TransportProfile::Desktop).unwrap();
        assert_eq!(server, std::time::Duration::from_mins(1));
        assert_eq!(server, desktop);
    }

    #[test]
    fn mobile_uses_the_reduced_interval() {
        let mobile = heartbeat_interval(TransportProfile::Mobile).unwrap();
        assert_eq!(mobile, std::time::Duration::from_mins(2));
    }

    #[tokio::test]
    async fn scheduler_select_exits_promptly_on_cancel() {
        // A real `Supervisor` cannot be constructed here without full provider
        // wiring, so this exercises the scheduler's cancel-vs-timer select
        // shape directly: with a long interval the cancel arm must win and the
        // future must resolve to `true` (cancelled) rather than `false` (tick).
        let cancel = CancellationToken::new();
        let bridge_cancel = CancellationToken::new();
        let token = cancel.clone();
        let bridge = bridge_cancel.clone();
        let interval = heartbeat_interval(TransportProfile::Server).unwrap();
        let fut = async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;
            tokio::select! {
                () = token.cancelled() => true,
                () = bridge.cancelled() => true,
                _ = timer.tick() => false,
            }
        };
        let handle = tokio::spawn(fut);
        cancel.cancel();
        let exited_via_cancel = handle.await.unwrap();
        assert!(exited_via_cancel, "scheduler must exit via cancel token");
    }
}
