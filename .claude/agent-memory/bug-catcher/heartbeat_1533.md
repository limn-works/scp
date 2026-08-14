# #1533 Heartbeat send/receive loop review (2026-06-15)

Branch: feat/1533-heartbeat-loop. §9.9.2 suppression-detection heartbeats.

## Confirmed findings
- **HIGH — heartbeat scheduler leaks on relay stream termination.** napi context.rs context_subscribe_on:
  subscribe loop `break` on `TransportEvent::Terminated` / stream `None` resets `subscription_active`
  (inner ActiveFlagGuard) but does NOT cancel `cancel_token`. Heartbeat scheduler is a SEPARATE JoinSet
  task (line ~1385) cancelled only by `cancel_token`/`bridge_cancel`. So after stream ends it keeps
  sending heartbeats. Worse: a fresh re-subscribe overwrites `*subscription_cancel` with a NEW token
  (line 1333) WITHOUT cancelling the old one → old scheduler orphaned until bridge shutdown.
  Fix: cancel `cancel_token` on all subscribe-loop break paths (or in the inner active-flag guard's
  Drop / via a scopeguard), OR tie scheduler lifetime to the subscribe task instead of the shared token.
- **MEDIUM — cross-profile interval/threshold mismatch (doc claim false).** Send interval derived from
  SENDER's `TransportProfile::platform_default()`; receive threshold derived from RECEIVER's profile at
  connect. Doc in heartbeat_scheduler.rs + HeartbeatConfig::for_profile claims "single source of truth
  so cadence can never drift out of step with the threshold a peer's monitor expects." FALSE across
  peers: Server receiver (threshold 60s*2=120s) monitoring a Mobile sender (interval 120s) sits at the
  edge → marginal false-positive suppression. Only DeliverOutcome::Heartbeat refreshes last_received;
  app messages do NOT. Fix: either receiver threshold must account for max sender interval, or
  application-message arrival should also refresh the monitor baseline.

## Verified CORRECT (no defect)
- Receive ordering: verify_and_unwrap (sig+access key) → checkpoint dispatch → heartbeat dispatch →
  sequence machinery. Heartbeat returns DeliverOutcome::Heartbeat before sequence tracker → cannot
  poison per-sender app sequence. Good.
- message_type discriminator byte IS in canonical signed hash (inner/mod.rs:548) → type-flip
  Content→Heartbeat is signature-rejected. Good.
- DeliverOutcome ripple: only 2 callers — napi subscribe loop (handles all 3 arms correctly) and
  Supervisor::deliver_commit_blob (collapses Heartbeat|Handled→None correctly for reconnect driver).
  PyO3 uses drain_events (not DeliverIncoming); UniFFI context_subscribe is a stub (on_complete only).
  No application payload dropped.
- empty heartbeat payload round-trips (pad_empty_payload_to_smallest_bucket, wrap_content_empty_plaintext).
- record_heartbeat_received: Vec<Box<dyn>> fan-out, no lock across await; Box blanket forward + Self::
  inherent delegation correct (inherent priority, not recursion); trait default no-op safe.
- interval first-tick consumed correctly (fires one full interval in). select! cancellation prompt.
- SeedPeerPseudonym dispatch arm + handler both cfg(testing)-gated.
