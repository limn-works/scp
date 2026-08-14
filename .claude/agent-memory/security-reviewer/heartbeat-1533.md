---
name: heartbeat-1533
description: Security audit of #1533 heartbeat send/receive loop (§9.9.2) — APPROVE, clean
metadata:
  type: project
---

# #1533 Heartbeat Send/Receive (§9.9.2) — APPROVE (2026-06-15)

Branch `feat/1533-heartbeat-loop`. Full receive/send/forge/DoS/enforcement audit. SECURITY-CLEAN.

**Why:** suppression-detection heartbeats must not let a relay forge liveness or poison sequence.
**How to apply:** reference when reviewing follow-on heartbeat work or other subscribe-loop-internal sends.

## Key facts
- Receive: `messaging_helpers.rs` `deliver_incoming` classifies `MessageType::Heartbeat` (disc byte 5)
  at line ~1126 — AFTER `decrypt_and_dispatch` (MLS membership), cross-ctx/credential-spoof defense,
  and `verify_and_unwrap` (Ed25519 verify_inner_signature + ct hash + access-key unwrap_content).
  Returns `DeliverOutcome::Heartbeat` BEFORE `validate_and_drain_timeouts` → never advances content
  sequence, never buffers. Relay cannot forge (holds no keys). Empty payload `&[]` is wrapped through
  full WrappedContent on send so receive deserializes a well-formed wrapper, not raw empty bytes.
- New `DeliverOutcome` enum {Application((Vec<u8>,String)), Heartbeat, Handled} replaces prior
  `Option<(Vec<u8>,String)>`. `deliver_commit_blob` collapses Heartbeat|Handled → None.
- Send: `send_heartbeat` is structurally identical to already-merged `send_checkpoint` (seq 0,
  broadcast_envelope=None → MLS path, broadcast RID or peer pseudonym fan-out). Empty routing set =
  legit no-op. Key passed per-call via `SigningKeyBytes(Zeroizing<[u8;32]>)`, zeroed on drop, never
  actor-owned, never crosses FFI outward.
- Scheduler: `scp-ffi-common/src/heartbeat_scheduler.rs` `run_heartbeat_scheduler` — owned Arc<Supervisor>
  + owned SigningKey, tokio::select on subscription cancel + bridge cancel + interval tick. First tick
  consumed. Best-effort (logs, never tears down sub). Interval = `HeartbeatConfig::for_profile`
  (60s Server/Desktop, 120s Mobile, None=Constrained skips spawn). NAPI-only (only bridge with live
  context_subscribe_on). Stale-key-after-close guarded TWICE: cancel token + dispatch_command lookup()
  misses on deregistered actor.
- record_heartbeat_received: TransportManager fans out to adapters; native adapter sets
  last_received=Some(now) — O(1), no alloc. Flood = repeated timestamp reset, bounded. Reachable in
  prod ONLY via DeliverOutcome::Heartbeat (authenticated). Trait default no-op for non-native adapters.
- Enforcement: pipeline assertion `b3_heartbeat_send_receive_loop_wired` additive (ratchet 41→42),
  real fn_body_contains call-site checks. Honest.

## Observation (non-blocking)
- sdk-capability-matrix.json `subscribe` entry NOT annotated that the §9.9.2 scheduler is NAPI-only,
  though the analogous subscribe-loop-internal reconnection driver IS noted (line ~241). Heartbeat is
  internal subscribe-loop behavior (not user-callable) so matrix not wrong, but a mirroring note would
  keep coverage story consistent. Recommend adding.

## Reusable pattern
- Subscribe-loop-internal sends (reconnection driver, periodic checkpoint, heartbeat) all live at the
  FFI/SDK boundary because the actor has no signer (key_resolver is public-only post-ADR-049). Key
  enters per-call exactly like send_message. This is the canonical location decision.

## Fix re-review (2026-06-17) — APPROVE, all 4 fix commits clean
Commits 6b0e860f6 (gate), e194a97fa (threshold), a8cd2281e (teardown), 4dce427c1 (scheduler/recv).
1. `send_heartbeat` (messaging_helpers.rs:1441-1461) now byte-identical to send_message gate
   (682-702): `require_active` + broadcast-exempt `MessagesWrite` check + suspended-capability
   message branch. Suspended/revoked member CANNOT emit heartbeat; send racing close → PermissionDenied.
2. Scheduler teardown: napi context.rs:~1629 `cancel_token.cancel()` after subscribe loop, ALL exit
   paths (explicit unsub already-cancelled idempotent, bridge_cancel, None, Terminated). Stops orphaned
   task → releases Arc<Supervisor> + owned SigningKey, no false liveness. Re-subscribe overwrites token
   w/o cancel, so this teardown is the only stopper — correct.
3. Signing key: scheduler holds Arc<Supervisor> (refcount only) + owned SigningKey by value (one task
   copy, NOT broadened into shared state). send_heartbeat takes `&SigningKey`, wraps to
   SigningKeyBytes(Zeroizing<[u8;32]>) for the mailbox cmd (internal Rust msg). Never crosses FFI outward.
4. Per-relay attribution: manager.rs:777-800 documents record_heartbeat_received fan-out-to-all is
   deliberately NOT per-relay (MergedStream discards adapter_idx before yield) → sound conclusion is only
   "some relay alive." Per-relay downgrade delegated to SuppressionTracker cross-check. NO security gap:
   heartbeat reaches record point ONLY via authenticated DeliverOutcome::Heartbeat (after MLS+sig+access-key).
   Relay/network cannot forge a liveness refresh.
- Threshold widening (Server/Desktop 120s→240s) is a false-positive FIX (honest 120s Mobile sender no
  longer trips spurious suppression at a faster receiver), sized to slowest honest sender. Detection
  still occurs, at correct floor. Not a security weakening. debug_assert enforces uniform 240s.
- App-msg refresh (context.rs DeliverOutcome::Application arm) also calls record_heartbeat_received —
  defense-in-depth, app msg is authenticated liveness evidence ≥ heartbeat. Sound.
