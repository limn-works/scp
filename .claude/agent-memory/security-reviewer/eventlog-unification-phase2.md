# Event-Log Unification Phase 2 (runtime substrate swap) — 2026-06-18

Branch `feat/eventlog-unification-phase2-substrate`. Round-1 HEAD 964f186 (APPROVE, one MEDIUM doc fix).
ROUND-4 FINAL @526c50eb4: APPROVE, ZERO findings. Prior MEDIUM doc (state.rs ~929-957) FIXED —
last_seen_remote_checkpoint doc rewritten to match reality (SOLE in-memory dedup, resets on respawn,
re-alert bounded/acceptable, emission always-on / insertion cap-gated). All 6 task vectors re-verified
independently from source (see below).

## ROUND-4 verification (independent, from source @526c50eb4)
- (1) equivocation dedup: verify_remote_checkpoint_authenticity is FIRST stmt in compare_remote_checkpoint
  (queries_helpers.rs:767) — membership + Ed25519 verify_strict before any record. record_equivocation_if_fresh
  (:867): emit always-on (:901), insert cap-gated <MAX_SEQUENTIAL_COMMITS (:897). Distinct-root keying correct.
  No DoS/amplification, real divergence never missed.
- (2)+(3) exclusion removal + truncation: UPGRADED from round-1 — truncation now CLOSED not merely detected.
  verify_merkle_chain (export_import.rs:471) replays every entry via tree::append_unsigned_event which validates
  sequence==running_count + prev_hash==prior-leaf (tree.rs:164-203). Prefix-trunc → entry[0] seq>0 → SequenceMismatch
  reject. Suffix/reorder/middle-remove → different tree::root → ct_eq fail vs SIGNED snapshot.event_log_merkle_root
  (:649). Tests: rejects_prefix/suffix_truncated_log + detects_removed_entry. Supersedes prior "suffix-of-history
  tolerant" caveat in this file.
- (4) unsigned native appends: signature: Vec::new() via append_unsigned_event (providers/event_log.rs:100,
  mirrors WASM). Integrity=prev_hash chain + Merkle root; authenticity=SIGNED checkpoint/export root. No new
  forgery surface (in-process-only, documented).
- (5) buffered governance parity: run_buffered_post_delivery (messaging_helpers.rs:606) runs velocity (:619)
  + consequence eval/enforce (:637-667) UNCONDITIONALLY; only durable append is Some(event_name)-gated.
  Both drain sites (validate_and_drain_timeouts:2245, buffer_ahead_message:2325) call it without an if-let-Some
  gate, re-check membership+MessagesWrite first. Adversary cannot dodge velocity/consequence via buffered path.
- (6) consequence decode: legacy null-term-string branch DROPPED (234017ed8). payload_target_did
  (consequence.rs:884) = exactly 2 branches: rmp fixarray elem0 (rmpv Array only) + JSON object target_did.
  Producer is trusted runtime emitting positional-rmp (payload.rs encode, fixarray 0x9N proven) or JSON.
  JSON `{`=0x7B never parses as rmp Array → no cross-branch false-match. Matcher more-permissive = no suppression.
- prune_before_checkpoint (providers/event_log.rs:413) re-chains tail to fresh genesis → pruned export yields
  different root → won't match a full-log signature; needs own fresh signature. No path to present truncated
  log as another member's signed history.

## (round-1, retained)

## What changed (security-relevant)
- Runtime ContextManager event log swapped onto `scp_event_log::EventLog` (RFC 6962 tree),
  matching WASM. Leaves: `SHA-256(0x00 ‖ rmp_serde(Event))` via new `tree::leaf_hash()` helper
  (pure refactor, bit-identical). Root via `tree::root`.
- Equivocation dedup (`record_equivocation_if_fresh`, queries_helpers.rs ~867): durable
  `EquivocationDetected` Merkle append REMOVED. In-memory per-sender `(count,root)` HashSet capped
  at MAX_SEQUENTIAL_COMMITS=100 is now SOLE dedup. Buffer-only alert (receive_buffer + broadcast).
- `MessageReceived` + `EquivocationDetected` no longer durable Merkle leaves (ContextEvent
  receive-buffer signals kept). Rationale: receiver-minted leaves aren't sender-authenticated →
  appending would let two honest receivers diverge roots and false-positive §9.9.3.
- consequence.rs `payload_target_did`: typed-positional-rmp-FIRST, then JSON object, then legacy
  null-term string. New typed payloads AccessRevokedPayload / GovernanceActionExecutedPayload.

## Threat-model conclusions
- (a) cap amplification DoS: NOT exploitable. `verify_remote_checkpoint_authenticity` runs FIRST
  in compare_remote_checkpoint (queries_helpers.rs ~720/767): membership + Ed25519 verify_strict
  BEFORE any recording. Attacker can't inject forged (count,root). All bounded: set cap 100/sender,
  ReceiveBuffer cap 1000 oldest-drop, tokio broadcast bounded.
- (b) respawn re-alert: in-memory set empties on respawn → re-presented divergent checkpoint
  re-alerts ONCE per distinct signed (count,root) until set refills. Duplicate NOTIFICATION, not a
  security failure. Bounded. Acceptable.
- (c) missed equivocation: NEVER. Real divergence always fires ≥1 alert (even past cap — emit
  always, insert gated). Verified by per_sender_set_is_bounded_and_still_emits test.
- Export truncation (export_import.rs ~615-653): import recomputes root via verify_merkle_chain,
  ct_eq (constant-time) vs SIGNED snapshot.event_log_merkle_root (inside Ed25519 verify_strict
  preimage). Suffix-of-HISTORY (oldest dropped, head preserved) still verifies — chain-head is
  pruning-tolerant; HONESTLY documented incl. consequence-window enforcement caveat (inert under
  default 1-5min windows). Not introduced by this PR.
- Unsigned native appends (signature: vec![]): mirrors pre-existing WASM append_unsigned_event
  model. Integrity = prev_hash chain + Merkle root + SIGNED checkpoint/export over root. No new
  forgery surface.
- consequence decode: no marker collision — rmp fixarray 0x90-9f vs JSON `{`=0x7B / `[`=0x5B
  (fixints). Producer is trusted runtime; payloads signature-gated on append. Matcher strictly more
  permissive (rmp→JSON→legacy). No suppression bypass.

## FINDING (MEDIUM, doc-only): stale contradictory doc in actor/state.rs ~939-948
`last_seen_remote_checkpoint` doc STILL says PRIMARY dedup = durable append advancing local_count,
respawn replay "stays blocked", set is "secondary belt-and-suspenders". Phase 2 REMOVED that append;
queries_helpers.rs correctly says set is SOLE dedup. state.rs doc NOT updated in this diff → directly
contradicts reality. Misleads future maintainers into assuming a durable backstop that no longer
exists. Fix: rewrite to match queries_helpers.rs (sole in-memory dedup, resets on respawn, re-alert
bounded+acceptable).
