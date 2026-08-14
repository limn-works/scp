---
name: pr1540-checkpoint-equivocation-reconnect
description: Black-hat findings for #1540 — checkpoint exchange, equivocation detection, reconnection driver
metadata:
  type: project
---

# #1540 Checkpoint exchange + equivocation detection + reconnection driver

Branch `feat/1540-checkpoint-equivocation-sync`. Files: scp-protocol/src/sync/mod.rs,
scp-event-log/src/checkpoint.rs, scp-runtime/src/context/queries_helpers.rs (compare_remote_checkpoint),
messaging_helpers.rs (deliver_checkpoint_message, send_checkpoint), scp-ffi/common/src/reconnect.rs.

## Confirmed findings (severity)

- HIGH BLACK-R1: reconnect.rs collect_equivocation_alerts (lines 165-195) calls supervisor.drain_events()
  which DESTRUCTIVELY drains the SINGLE actor receive buffer, filter_maps for EquivocationDetected and
  DISCARDS all other events (`_ => None`). MessageReceived/MemberJoined/etc drained during Phase 3 reconnect
  are dropped — never delivered to the app. Message-loss bug; also a relay-timed eviction window (relay can
  push events to be silently eaten during reconnect). Same buffer consumed by SDK drain_and_deliver.

- MEDIUM BLACK-R2: checkpoint replay. compare_remote_checkpoint (queries_helpers.rs:724) has NO freshness
  check. Checkpoint carries `timestamp` field but receive path never reads it; no per-sender highest-count
  or last-seen tracking. A relay can replay an OLD validly-signed checkpoint (sig still valid). Effect: if
  replayed at a count the local member is now AHEAD of -> Ahead (benign); but replay of a stale checkpoint
  at a count where local root has legitimately changed via fork/rollback could be weaponized. Main risk is
  no idempotency — repeated replay re-appends EquivocationDetected events + increments checkpoint_events_since
  each time (queries_helpers.rs:832) = unbounded event-log growth + alert spam from one signed blob.

- MEDIUM BLACK-R3: equivocation root compare is NON-constant-time: `local_root == remote.merkle_root`
  (queries_helpers.rs:773). checkpoint.rs compare_checkpoint/cross_checkpoint_verify all use ct_eq. The
  runtime equivocation path regressed to `==`. Low exploitability (roots are public post-detection) but
  inconsistent with the codebase CT discipline.

- MEDIUM BLACK-R4: EQUIVOCATION EVASION via count-skew. Detection fires ONLY on Equal event-count +
  different root (the Ordering::Equal arm). An equivocating relay that keeps two histories of DIFFERENT
  lengths to two members, and ensures the victim is always Behind/Ahead relative to received checkpoints,
  NEVER triggers the Equal arm. The Behind arm (Less) is documented as "#1535 SEAM" and does NOT yet verify
  a consistency proof (that wiring is deferred to #1535). So a member who is Behind cannot currently detect
  that the suffix the relay feeds is a forked continuation — the consistency-proof check is a named TODO,
  not implemented. Equivocation detection is bypassable until #1535 lands.

- LOW BLACK-R5: collect_equivocation_alerts fabricates local_merkle_root=[0u8;32], remote=[0u8;32],
  evidence=None in the EquivocationAlert surfaced to the SDK (reconnect.rs:185-189). The alert loses the
  cryptographic evidence (the two conflicting checkpoints) — forensic value gutted; EquivocationEvidence
  struct exists for this purpose but is never populated on this path.

## Resists attack (genuinely sound)
- deliver_checkpoint_message binds checkpoint.sender_did to MLS-authenticated envelope sender (messaging_helpers
  ~1166) AND compare_remote_checkpoint re-verifies the checkpoint's own Ed25519 sig against resolved key for
  that DID + membership check. Author-spoof + unsigned-checkpoint both blocked. Two independent gates.
- CHECKPOINT_PAYLOAD_TAG + MessageType::ConsistencyCheckpoint discriminator both in canonical hash; type
  confusion blocked (discriminator byte 4 signed). deny_unknown_fields on CheckpointMessage + ConsistencyCheckpoint.
- Malformed payload: from_bytes size-bounded, rmp_serde returns Err -> CryptoFailed, no panic path found.
- deliver_commit_blob per-blob errors are non-fatal (continue) so a forged blob during Phase 2 cannot wedge
  catch-up; bounded by policy.max_sequential_commits (take(limit)).
