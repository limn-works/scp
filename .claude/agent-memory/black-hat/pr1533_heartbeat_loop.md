---
name: pr1533-heartbeat-loop
description: Adversarial review of #1533 heartbeat send/receive closed loop (relay-suppression detection) — malicious relay + malicious member analysis
metadata:
  type: project
---

# #1533 Heartbeat Send/Receive Loop — Adversarial Review

Branch `feat/1533-heartbeat-loop`. Closed-loop wiring of §9.9.2 suppression detection: SDK sends periodic empty-payload `MessageType::Heartbeat` (disc 5), receiver classifies it and calls `record_heartbeat_received` to refresh the `HeartbeatMonitor` baseline.

**Why:** verify a malicious relay cannot forge/replay heartbeats to mask its own suppression, and a malicious member cannot abuse the channel.

## Vector 1 — Defeat suppression detection: NO VIABLE EXPLOIT (sound)
- Heartbeat classified at messaging_helpers.rs:1129 AFTER `verify_and_unwrap` (Ed25519 inner-sig + sender-key + MLS). Relay cannot mint — has no signing key.
- REPLAY of a captured byte-identical heartbeat: rejected at sender-key layer `recv_sequence_tracker` (provider.rs:1745-1759) — every `seal` increments `state.send_sequence` (provider.rs:1622) regardless of message_type, so the (epoch,seq) header is unique per heartbeat; replay has seq <= last seen → "replay or reorder detected" BEFORE reaching classification. Also MLS ratchet generation rejects.
- `HeartbeatMonitor::record_heartbeat_received` sets `last_received = Instant::now()` (local clock, NOT message timestamp) — so even a hypothetical replay reaching it would use current time, but it never reaches it.

## Vector 2 — flooding/amplification: bounded, LOW
- Send bounded by scheduler interval (60s server/desktop, 120s mobile, none constrained).
- Receive of heartbeat = O(1): returns `DeliverOutcome::Heartbeat` immediately, no sequence advance, no state mutation, no buffer push. A malicious member CAN send heartbeats faster than scheduler (own client) but each still pays full MLS+sender-key+Ed25519 verify cost = same as any app message, and sender-key recv tracker advances normally. No amplification.

## Vector 3 — sequence/type confusion: NO VIABLE EXPLOIT
- Discriminator is on INNER envelope `message_type`, part of canonical signed hash (test at inner/mod.rs:576). Cannot flip Content<->Heartbeat without breaking sig.
- Heartbeat bypasses application sequence_tracker by design but NOT the sender-key recv tracker (the real anti-replay). Cannot inject "looks like heartbeat but isn't" — empty payload, verified.

## Vector 4 — DeliverOutcome misclassification: NO VIABLE EXPLOIT
- Clean enum mapping. Application only via SequenceCheck::Expected + not-announcement. Heartbeat/Handled never carry plaintext. Type system enforces.

## Vector 5 — scheduler abuse: MEDIUM finding (defense-in-depth gap)
- **send_heartbeat skips ALL send-path gates** that send_message enforces (messaging_helpers.rs:682-713): NO `require_active`, NO `MessagesWrite` capability check, NO commit-fault check, NO rate limit. `handle_send_heartbeat` (messaging.rs:~560) calls send_heartbeat directly.
- `dispatch_command` only checks actor REGISTERED (supervisor.rs:1460 `self.lookup`), not Active.
- Practical exploit limited: scheduler tied to subscription `cancel_token` (cancelled on unsubscribe/disconnect/close). But TOCTOU window between close and cancel + the principled gap: a suspended/capability-revoked member keeps emitting authenticated heartbeats (signals liveness it shouldn't). `crypto.seal` would still succeed for a valid MLS group member.
- **Fix:** add `require_active` + membership/capability check in handle_send_heartbeat or send_heartbeat, mirroring send_message. At minimum require_active.

## Vector 6 (bonus) — merged-stream fan-out: LOW (documented)
- `TransportManager::record_heartbeat_received` (manager.rs:783) refreshes ALL adapters' monitors on ANY received heartbeat, not per-relay-attributed. Documented as intentional (per-relay attribution = MergedStream cross-check's job). Means: in multi-relay set, one honest relay delivering heartbeats masks a second relay's suppression at the per-monitor liveness layer. Relies on MergedStream multi-relay cross-check (§9.9.2) for attribution — that path NOT exercised in this PR's tests (test AC9 feeds suppression event into scoring manually). Acceptable if MergedStream cross-check exists and works; worth confirming it's wired.
