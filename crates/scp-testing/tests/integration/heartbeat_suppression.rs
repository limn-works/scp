#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

//! Closed-loop heartbeat suppression-detection integration tests (§9.9.2).
//!
//! Closing the §9.9.2 loop wires the heartbeat send/receive path so the
//! long-built [`HeartbeatMonitor`] is finally fed: the SDK subscribe path sends periodic
//! heartbeats, received heartbeats are recorded against the monitor, and a
//! genuine silence raises [`SuppressionSuspected`], which downgrades the
//! offending relay's reliability score.
//!
//! These tests exercise that loop end to end at the transport layer using the
//! monitor's injectable clock (`now` parameter, deterministic — no real
//! timers) and the pure reliability-scoring functions the bridge suppression
//! task drives:
//!
//! - **AC8 negative** — a relay that drops heartbeats raises
//!   `SuppressionSuspected` after the threshold.
//! - **AC8 positive (closed loop)** — a peer that *does* send heartbeats keeps
//!   the monitor quiet: recording the received heartbeat suppresses the
//!   suspicion the silence would otherwise raise.
//! - **AC9** — two relays, one suppressing: feeding the suppression event into
//!   the reliability score (exactly as the bridge suppression→scoring task
//!   does) downgrades the suppressing relay below the honest one and flags it
//!   for replacement, while the honest relay is untouched.

use std::collections::HashMap;
use std::time::Duration;

use scp_transport::scoring::{DeliveryOutcome, ReliabilityScore, get_score, update_score};
use scp_transport::{HeartbeatConfig, HeartbeatMonitor, SuppressionSuspected};
use tokio::time::Instant;

/// Builds a monitor with the default §9.9.2 config (60s interval, 2x
/// suppression threshold = 120s) for the given relay.
fn default_monitor(relay_url: &str) -> HeartbeatMonitor {
    HeartbeatMonitor::new(HeartbeatConfig::default(), relay_url.to_owned())
}

// ---------------------------------------------------------------------------
// AC8 negative — a relay that drops heartbeats raises SuppressionSuspected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dropped_heartbeats_raise_suppression_after_threshold() {
    let mut monitor = default_monitor("wss://suppressing.relay.example");
    let t0 = Instant::now();

    // The local side sends a heartbeat (establishing the baseline) but the
    // relay suppresses everything coming back — no `record_heartbeat_received`
    // is ever called (the receive loop's `record_heartbeat_received` never
    // fires because no heartbeat arrives).
    monitor.record_heartbeat_sent(t0);

    // Within the threshold (2 * 60s = 120s) nothing is suspected yet.
    assert!(
        monitor
            .check_suppression(t0 + Duration::from_secs(119))
            .is_none(),
        "suppression must not fire before the threshold elapses"
    );

    // Past the threshold, suppression is suspected — the relay delivered no
    // heartbeat for longer than 2x the interval.
    let suspicion: Option<SuppressionSuspected> =
        monitor.check_suppression(t0 + Duration::from_secs(121));
    let event = suspicion.expect("suppression must fire once the gap exceeds the threshold");
    assert_eq!(event.relay_url, "wss://suppressing.relay.example");
    assert!(
        event.gap_duration > Duration::ZERO,
        "the reported gap must be positive"
    );
}

// ---------------------------------------------------------------------------
// AC8 positive (closed loop) — received heartbeats keep the monitor quiet.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn received_heartbeats_suppress_the_suspicion() {
    let mut monitor = default_monitor("wss://honest.relay.example");
    let t0 = Instant::now();

    // Baseline send, then a peer's heartbeat ARRIVES one interval later — this
    // is the receive-loop's `record_heartbeat_received` call closing the loop.
    monitor.record_heartbeat_sent(t0);
    monitor.record_heartbeat_received(t0 + Duration::from_mins(1));

    // Even past the point where a silent relay would have tripped (t0+121s),
    // the fresh received-heartbeat baseline (at t0+60s) means the gap is only
    // ~61s — well under the 120s threshold — so nothing is suspected.
    assert!(
        monitor
            .check_suppression(t0 + Duration::from_secs(121))
            .is_none(),
        "a recently-received heartbeat must suppress the suspicion (closed loop)"
    );

    // Confirm the same monitor WOULD have fired absent the received heartbeat:
    // 60s after the last received heartbeat + 120s threshold = t0+180s.
    assert!(
        monitor
            .check_suppression(t0 + Duration::from_secs(181))
            .is_some(),
        "once the received-heartbeat baseline itself ages past the threshold, \
         suppression fires again"
    );
}

// ---------------------------------------------------------------------------
// AC9 — two relays, one suppressing: only the suppressing relay is downgraded.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn suppressing_relay_downgrades_only_itself() {
    const SUPPRESSING: &str = "wss://suppressing.relay.example";
    const HONEST: &str = "wss://honest.relay.example";

    // Two monitors, one per relay, sharing the default config.
    let mut suppressing_monitor = default_monitor(SUPPRESSING);
    let mut honest_monitor = default_monitor(HONEST);
    let t0 = Instant::now();

    suppressing_monitor.record_heartbeat_sent(t0);
    honest_monitor.record_heartbeat_sent(t0);

    // The honest relay delivers a heartbeat; the suppressing relay does not.
    honest_monitor.record_heartbeat_received(t0 + Duration::from_mins(1));

    let check_at = t0 + Duration::from_secs(121);
    let suppressing_event = suppressing_monitor.check_suppression(check_at);
    let honest_event = honest_monitor.check_suppression(check_at);

    assert!(
        suppressing_event.is_some(),
        "the suppressing relay must raise SuppressionSuspected"
    );
    assert!(
        honest_event.is_none(),
        "the honest relay (heartbeats arriving) must NOT raise suppression"
    );

    // Reliability scoring: drive each monitor's outcome into the score map
    // exactly as the bridge suppression→scoring task does — a suppression
    // event records DeliveryOutcome::Failure, a healthy delivery records
    // Success. Repeat enough times that the EMA crosses the 0.5 replacement
    // threshold for the suppressing relay only.
    let mut scores: HashMap<String, ReliabilityScore> = HashMap::new();
    for _ in 0..5 {
        // Suppressing relay: each detected suppression is a delivery failure.
        if suppressing_monitor.check_suppression(check_at).is_some() {
            update_score(&mut scores, SUPPRESSING, DeliveryOutcome::Failure);
        }
        // Honest relay: heartbeats arriving means deliveries succeeding.
        if honest_monitor.check_suppression(check_at).is_none() {
            update_score(
                &mut scores,
                HONEST,
                DeliveryOutcome::Success { latency_ms: 20 },
            );
        }
    }

    let suppressing_score =
        get_score(&scores, SUPPRESSING).expect("suppressing relay must have a score");
    let honest_score = get_score(&scores, HONEST).expect("honest relay must have a score");

    assert!(
        suppressing_score.delivery_success_rate < honest_score.delivery_success_rate,
        "suppressing relay's delivery success rate ({}) must be below the honest relay's ({})",
        suppressing_score.delivery_success_rate,
        honest_score.delivery_success_rate
    );
    assert!(
        suppressing_score.is_flagged_for_replacement(),
        "the suppressing relay must be flagged for replacement (success rate {})",
        suppressing_score.delivery_success_rate
    );
    assert!(
        !honest_score.is_flagged_for_replacement(),
        "the honest relay must NOT be flagged for replacement (success rate {})",
        honest_score.delivery_success_rate
    );
}
