---
name: phase2-eventlog-unification-ccf70dc50
description: Phase-2 native↔WASM event-log unification security review (round 6 final, commit ccf70dc50) — APPROVED, no findings
metadata:
  type: project
---

# Phase-2 Event-Log Unification Security Review (ccf70dc50)

Round-6 final confirmation review. APPROVED, zero findings. Fresh independent threat-model of full diff (1c0ccbc7d..HEAD, ~48 files).

**Why:** Native runtime event log diverged from RFC 6962 substrate (hash-chain vs Merkle tree); unification needed for native↔WASM root convergence + #1535/#1540.
**How to apply:** This is the reference for the event-log security model post-unification. The seven properties below are load-bearing — don't regress them.

## Seven security properties verified sound

1. **Equivocation dedup (#G)** — `record_equivocation_if_fresh` (queries_helpers.rs). Authenticity gate FIRST (`verify_remote_checkpoint_authenticity`: membership + key-resolve + Ed25519, line 767, before any root compare line 787). Dedup keyed per-sender on `(event_count, remote_merkle_root)` HashSet, bounded at `MAX_SEQUENTIAL_COMMITS`. Outer HashMap<DID,_> bounded by membership (only authenticated members create entries). Alert ALWAYS emitted (never silently dropped, §9.9.4); only set-insertion is cap-gated. No DoS/amplification.

2. **Durable-append removal for equivocation** — KEY CHANGE: old code appended `EquivocationDetected` to durable Merkle log (advanced local_count = primary dedup). New code does NOT append (receiver-minted leaf is not sender-authenticated → would let honest receivers diverge roots → false-positive §9.9.3). Per-sender set is now SOLE dedup. Bounded consequence: one duplicate alert per divergence after respawn (acceptable, not replay-amplification).

3. **MessageReceived not durably appended** — same rationale. Both in-order (`deliver_message_and_drain_buffered` ~line 2558) and buffered (`run_buffered_post_delivery`) paths: push to receive buffer (SDK-observable, feeds consequence eval Source 2), SKIP durable append, but STILL run velocity + consequence eval + checkpoint increment. Parity confirmed, no enforcement bypass. Membership + MessagesWrite gate before delivery + re-checked per drained buffered msg.

4. **Export truncation CLOSED (not just detected)** — `verify_merkle_chain` (export_import.rs) replaced pruning-tolerant chain check with `append_unsigned_event` replay. Substrate enforces `event.sequence == running_count` (tree.rs:168) + prev_hash chain. Prefix-truncation → first event seq≠0 → rejected outright. Suffix/reorder/middle → different root → rejected by ct_eq vs signed `snapshot.event_log_merkle_root`. Legit prune → re-anchored to genesis = valid prefix → accepted. Closes prior front-truncation consequence-suppression gap. Tests: `verify_merkle_chain_rejects_{prefix,suffix}_truncated_log`.

5. **Unsigned appends add no forgery surface** — empty-signature events; tamper evidence from substrate Merkle tree (prev_hash + RFC 6962 root), not signature. Matches WASM `append_unsigned_event` model. `rebuild_log_from_events` fails closed on tampered/reordered persisted log.

6. **Consequence-matcher decode no bypass** — `payload_target_did`/`payload_starts_with` (consequence.rs) replaced legacy null-terminated fallback with typed-positional-rmp (`rmp_array_first_string` reads array elem 0 = target_did) + JSON-object. All live producers emit one of those two (encode_payload typed structs OR serde_json). JSON bytes (0x7B) decode as rmp fixint not array → fall through to JSON branch. No untrusted-payload injection into matcher (durable governance log written by local node only). AccessRevokedPayload/GovernanceActionExecutedPayload typed structs added.

7. **Prune re-chaining prevents history impersonation** — `truncate_log_keeping_tail` re-anchors retained tail to GENESIS_PREV_HASH, re-chains each, preserves all other fields. Old root intentionally invalidated (RFC 6962 truncation semantics). Structural events (AccessRevoked=structural) retained `multiplier/10000`× longer; 30-day floor. NOTE: GovernanceActionExecuted classified OPERATIONAL (pruning.rs:477) while AccessRevoked STRUCTURAL — NOT a finding: 30-day retention floor >> 1-5min consequence windows, so prunable events are already out-of-window.

## leaf_hash unification
`scp_event_log::tree::leaf_hash(event)` = `SHA-256(0x00 ‖ rmp_serde(Event))` extracted as pub fn; native provider, import verify, AND FFI bridges (common/napi event_log.rs) all use it. Roots converge cross-platform.

## EventLogEntry deleted
Old untyped `EventLogEntry {event:String, hash, payload:Option}` fully replaced by canonical `scp_event_log::Event` everywhere (store/event_log.rs, providers/event_log.rs, queries_helpers.rs). EventType now derives Copy.
