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
//! The cadence is the local node's per-profile send interval from
//! [`HeartbeatConfig::for_profile`](scp_transport::HeartbeatConfig::for_profile).
//! This interval is **per-node**, not a cross-peer single source of truth — a
//! Mobile sender ticks every 120s while a Server sender ticks every 60s, and
//! neither observes the other's cadence. Cross-peer safety (a peer's monitor
//! never suspecting a slower-but-honest sender) is provided not by matching
//! intervals but by sizing the receive-side suppression threshold to the
//! slowest honest sender — see `HeartbeatConfig::for_profile`, where every
//! sending profile resolves to the same 240s threshold. `Constrained` profiles
//! send no heartbeats (the interval source returns `None`), matching the
//! monitor's poll-based silence.

use std::sync::Arc;

use scp_core::context::supervisor::Supervisor;
use scp_did::DID;
use scp_transport::HeartbeatConfig;
use scp_transport::profile::TransportProfile;
use tokio_util::sync::CancellationToken;

use crate::persona::ResolvedMessageSigner;

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
/// Loops on a timer at `interval`, calling [`Supervisor::send_heartbeat`] each
/// tick with the caller-held `signer`.
///
/// `signer` is a [`ResolvedMessageSigner`] — the key and the `#active`/`#agent`
/// verification method it was resolved under, as ONE value (ADR-039). Taking
/// the pair separately would let a bridge stamp a method its key does not back,
/// and a beacon whose stamp its signature does not match is rejected by every
/// peer — so an honest participant would be read as suppressed (§9.9.2). Each
/// bridge's `resolve_*` helper picks the key handle and the persona in a single
/// match, so the two cannot drift apart between resolution and this call.
///
/// The send is best-effort: a transport failure is logged but
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
    signer: ResolvedMessageSigner,
    interval: std::time::Duration,
    cancel: CancellationToken,
    bridge_cancel: CancellationToken,
) {
    let ctx_for_log = context_id.clone();
    // Wrap the signer (which owns the secret key) in an `Arc` ONCE so each tick
    // clones a refcount handle, never a copy of the Ed25519 secret scalar. The
    // key material exists in exactly one heap location for the scheduler's
    // lifetime (matching the prior single-capture exposure window) rather than
    // being re-copied per tick.
    let signer = Arc::new(signer);
    scheduler_loop(interval, cancel, bridge_cancel, move || {
        // The per-tick async block is `move` and outlives the `FnMut` closure
        // call, so it must OWN what it touches — it cannot borrow the closure's
        // captures. Per tick we clone only cheap handles: the `Arc<Supervisor>`
        // and `Arc<ResolvedMessageSigner>` clones are refcount bumps (no
        // secret-scalar copy), and the DID / context-id string clones are
        // negligible against the ≥60s tick cadence.
        let supervisor = Arc::clone(&supervisor);
        let context_id = context_id.clone();
        let sender_did = sender_did.clone();
        let signer = Arc::clone(&signer);
        async move {
            // ADR-039: the stamp and the signing key are one value from here
            // down, so a peer resolving the declared method always verifies the
            // beacon. `message_signer()` borrows from `signer`, which the
            // surrounding `async move` block owns for the whole call.
            if let Err(e) = supervisor
                .send_heartbeat(&context_id, &sender_did, signer.message_signer())
                .await
            {
                // Best-effort (§9.9.2): a failed send does not stop the
                // schedule. Persistent failure surfaces on the peer side
                // as a suppression suspicion via gap detection. The send
                // path itself enforces the same write gates as `send_message`
                // (active context + `MessagesWrite` capability), so a
                // suspended/revoked member's tick is rejected here and simply
                // logged — it never asserts liveness.
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "periodic heartbeat send failed (best-effort; scheduler continues)"
                );
            }
        }
    })
    .await;

    tracing::debug!(
        context_id = %ctx_for_log,
        "heartbeat scheduler stopped"
    );
}

/// Testable timing core of [`run_heartbeat_scheduler`].
///
/// Ticks on a timer at `interval`, invoking `on_tick` once per tick, until
/// either cancellation token fires. The first immediate `interval` tick is
/// consumed so the first `on_tick` fires one full interval in (a brand-new
/// subscription has nothing to prove liveness against yet). Cancellation is
/// checked in the same `select!` as the tick, so a fired token wins promptly
/// even mid-interval and a future reorder of the arms is observable by tests.
///
/// Separated from the `Supervisor`-bound wrapper so the loop's timing and
/// teardown contract can be exercised behaviorally without full provider
/// wiring (a real `Supervisor` cannot be constructed in a unit test).
async fn scheduler_loop<F, Fut>(
    interval: std::time::Duration,
    cancel: CancellationToken,
    bridge_cancel: CancellationToken,
    mut on_tick: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut timer = tokio::time::interval(interval);
    // Consume the immediate first tick — the first heartbeat fires one full
    // interval in, matching the receive-side monitor's baseline assumption.
    timer.tick().await;

    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            () = bridge_cancel.cancelled() => return,
            _ = timer.tick() => {
                on_tick().await;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Yields the test task enough times for a separately-spawned task to wake
    /// on an advanced paused clock, run its `select!`, and drive the per-tick
    /// async block to completion. A single `yield_now` is not enough — the
    /// spawned task needs several scheduler turns (timer wake → select → tick
    /// future → atomic store) before its effect is observable here.
    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

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

    #[test]
    fn every_sending_profile_resolves_to_uniform_suppression_threshold() {
        // The send interval is per-node (per-profile); the suppression
        // threshold is uniform across all senders (sized to the slowest honest
        // sender's cadence, Mobile 120s × 2 = 240s) so no receiver out-runs any
        // honest sender. Without this a Mobile sender at a Server/Desktop
        // receiver would trip a spurious SuppressionSuspected.
        for profile in [
            TransportProfile::Server,
            TransportProfile::Desktop,
            TransportProfile::Mobile,
        ] {
            let config =
                HeartbeatConfig::for_profile(profile).expect("sending profile must yield a config");
            assert_eq!(
                config.suppression_threshold(),
                std::time::Duration::from_mins(4),
                "profile {profile:?} must resolve to the uniform 240s threshold"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_loop_ticks_on_interval_and_consumes_first_immediate_tick() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let interval = heartbeat_interval(TransportProfile::Server).unwrap();
        let ticks = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let bridge_cancel = CancellationToken::new();

        let ticks_for_loop = Arc::clone(&ticks);
        let cancel_for_loop = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler_loop(interval, cancel_for_loop, bridge_cancel, move || {
                let ticks = Arc::clone(&ticks_for_loop);
                async move {
                    ticks.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;
        });

        // Let the spawned task run up to its first `timer.tick()` await: this
        // consumes the immediate first tick and registers the next deadline at
        // `interval`. Without this initial settle the timer's deadline is never
        // armed before we advance the clock.
        settle().await;

        // The first immediate tick is consumed: just shy of one full interval,
        // no on_tick has fired yet (first send is one interval in).
        tokio::time::advance(
            interval
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap(),
        )
        .await;
        settle().await;
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            0,
            "first immediate tick must be consumed — no send before one full interval"
        );

        // Cross the first interval boundary: exactly one send.
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            1,
            "one send after one interval"
        );

        // Cross a second interval boundary: a second send (it ticks on
        // interval, not once).
        tokio::time::advance(interval).await;
        settle().await;
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            2,
            "scheduler must keep ticking each interval"
        );

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_loop_exits_promptly_on_subscription_cancel() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let interval = heartbeat_interval(TransportProfile::Server).unwrap();
        let ticks = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let bridge_cancel = CancellationToken::new();

        let ticks_for_loop = Arc::clone(&ticks);
        let cancel_for_loop = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler_loop(interval, cancel_for_loop, bridge_cancel, move || {
                let ticks = Arc::clone(&ticks_for_loop);
                async move {
                    ticks.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;
        });

        // Cancel before any interval elapses — the cancel arm of the select
        // must win over the (not-yet-ready) timer and the loop must return.
        cancel.cancel();
        // `handle.await` completing proves the loop exited; if the cancel arm
        // were ever reordered after a blocking tick this would hang.
        handle.await.unwrap();
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            0,
            "cancel before the first interval must stop the scheduler with zero sends"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_loop_exits_promptly_on_bridge_cancel() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let interval = heartbeat_interval(TransportProfile::Server).unwrap();
        let ticks = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let bridge_cancel = CancellationToken::new();

        let ticks_for_loop = Arc::clone(&ticks);
        let bridge_for_loop = bridge_cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler_loop(interval, cancel, bridge_for_loop, move || {
                let ticks = Arc::clone(&ticks_for_loop);
                async move {
                    ticks.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;
        });

        bridge_cancel.cancel();
        handle.await.unwrap();
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            0,
            "bridge-shutdown cancel must stop the scheduler"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_loop_stops_ticking_after_cancel() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let interval = heartbeat_interval(TransportProfile::Server).unwrap();
        let ticks = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let bridge_cancel = CancellationToken::new();

        let ticks_for_loop = Arc::clone(&ticks);
        let cancel_for_loop = cancel.clone();
        let handle = tokio::spawn(async move {
            scheduler_loop(interval, cancel_for_loop, bridge_cancel, move || {
                let ticks = Arc::clone(&ticks_for_loop);
                async move {
                    ticks.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;
        });

        // Let the spawned task arm its first deadline (see the ticks test).
        settle().await;

        // One send, then cancel.
        tokio::time::advance(interval + std::time::Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(ticks.load(Ordering::SeqCst), 1);

        cancel.cancel();
        handle.await.unwrap();

        // After teardown, advancing time produces no further sends — proves the
        // scheduler tears down in lockstep and does not keep firing on a dead
        // subscription (the fix-#1 invariant, exercised at the loop level).
        tokio::time::advance(interval * 10).await;
        settle().await;
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            1,
            "no sends may fire after the scheduler is cancelled"
        );
    }
}
