---
name: 1845-replication-plan-review
description: Crypto/convergence review of #1845 cross-member event-log replication PLAN (CommitMetadata sidecar) — soundness verdict + the load-bearing poisoning/ordering findings
metadata:
  type: project
---

# #1845 Cross-Member Event-Log Replication PLAN review (2026-06-20, worktree fb6530cfb)

Plan = tasks #190-196. CommitMetadata sidecar carries {event_type, actor_did, payload, created_at, epoch}; receiver re-appends byte-identical leaf via append_context_event_with_payload. No code yet (forward-looking).

## Substrate facts verified against code
- Leaf = SHA-256(0x00 ‖ rmp_serde(Event)); Event fields: event_type, actor_did, timestamp, sequence, payload, prev_hash, signature. event_log/lib.rs:480.
- signature is ALWAYS Vec::new() in the runtime provider (event_log.rs:96) — so the signature byte does NOT diverge. Good (one fewer convergence hazard).
- sequence/prev_hash assigned by appending log from current state (event_log.rs:81-87) → ORDERING load-bearing for byte-identity.
- §9.9.3 detection: equal event_count + different merkle_root ⇒ Divergent ⇒ EquivocationDetected (queries_helpers.rs:828-877). Checkpoint sig + membership verified first.
- MLS Commit returns Handled at deliver_incoming:1128 BEFORE classification (no inner envelope). CommitMetadata sidecar is a SEPARATE app-layer inner-envelope message_type, decoupled from the MLS commit. THIS DECOUPLING is the core risk.

## CRITICAL finding (finding 2): poisoning is NOT caught by §9.9.3 in general
Plan says "don't require entry.actor_did==sender_did, §9.9.3 catches a bogus leaf." This reasoning is UNSOUND as stated:
- §9.9.3 only fires on equal-count + different-root. If a malicious member M sends ONE CommitMetadata with a fabricated leaf to ALL honest receivers, every honest receiver appends the SAME bogus leaf → all converge on the SAME poisoned root. No divergence ⇒ §9.9.3 silent. M has injected an unauthenticated leaf into every honest log.
- Equivocation framing: M sends DIFFERENT CommitMetadata to A vs B → A and B diverge → §9.9.3 fires but blames... whichever member published the checkpoint; the EquivocationDetected is keyed on the checkpoint sender, and the bogus leaf's actor_did can be an honest third party → FRAMING / wrong-attribution.
- The real defense must be: receiver authorizes the sidecar leaf, not just "sender is MLS member." Need binding of the leaf to the actual MLS commit it describes (e.g. only accept a replicated membership leaf if the receiver independently applied the corresponding MLS commit and the sidecar's {event_type,actor_did,payload} matches what the commit itself authorizes). Without that binding any member forges any leaf.

## creation_timestamp_secs (finding 3) — Plan-A claim CONDITIONALLY OK
- ContextSnapshot has NO creation_timestamp_secs field yet (state.rs:554) — plan must add it INTO the signed JCS preimage (signature-bound). Confirm it lands inside JCS(snapshot).
- Backdating only shortens TTL window (deadline=creation+ttl) = fail-safe for TTL. BUT must audit EVERY consumer: any consumer computing (now - creation) or using creation as a window START extends an attacker window. consequence window uses [now-window,now] not creation, so OK there. Flag: verify no governance/economic deadline uses creation as a lower bound.

## convergent_now (Plan B / finding 5) — definition hazard
- consequence.rs evaluate_consequence_rules window=[now-window, now], now passed by caller (currently deps.clock.now_secs() — LOCAL). Anchoring on convergent_now = max convergent leaf timestamp.
- EDGE: empty convergent log ⇒ convergent_now undefined (what's max of empty set?). Must define (e.g. creation_timestamp). EDGE: a member who hasn't yet replicated the latest commit has a SMALLER convergent_now than one who has → during the replication lag window the SET still differs transiently. Convergence only holds at quiescence/equal-count, same as the root. Acceptable IFF consequence leaves are only emitted at convergent checkpoints, not mid-lag.

## dedup key (finding, Q5): (sender, epoch, event_type, created_at, payload-hash)
- created_at is committer-assigned (1s granularity). TWO legitimately-distinct same-epoch same-type leaves by same actor within the SAME SECOND with identical payload would FALSE-DEDUP (e.g. two identical governance no-op actions, two joins... unlikely but possible). Recommend including the committer-assigned SEQUENCE or a commit nonce in the dedup key to guarantee uniqueness. epoch+created_at+payload is NOT collision-free.

## VERDICT: NOT cryptographically sound as planned. Finding 2 (leaf authorization) is a CRITICAL gap — must bind replicated leaf to the MLS commit / authorize per-leaf, not just per-sender-membership.
