---
name: adr011-messagesent-buffer-vs-durable
description: How to verify ADR-011 MessageSent "buffer-emitted, durable-log-excluded" tests are not gamed/vacuous
metadata:
  type: project
---

ADR-011 amendment (phase-2.md:907-934, §9.9.3): `MessageSent` is per-author, non-convergent — emitted ONLY as a local `ContextEvent::MessageSent` on the in-process receive buffer, NEVER a durable Merkle leaf, so two honest members derive the same merkle_root.

**Why:** Tests asserting this contract are easy to game vacuously (assert an absence that is trivially true). Verified the TS NAPI tests at commit 4ef63ec2b are solid — recording the verification chain so re-reviews are fast.

**How to apply — to confirm a MessageSent test is non-vacuous, check all four:**
- (a) Real send: the test MUST join a peer + seed its pseudonym (`contextSeedPeerPseudonym`). The §9.10.4 lone-member no-op guard at `crates/scp-runtime/src/context/messaging_helpers.rs:943` returns early WITHOUT emitting MessageSent when `send_routing_ids.is_empty()`. Routing IDs come from the pseudonym registry (seeded at messaging_helpers.rs:593). Remove the seed → send no-ops → positive assertion fails. So the peer+seed is load-bearing.
- (b) Positive observable: `expect(drained.some(e => e.includes("MessageSent"))).toBe(true)`. Valid because `ContextEvent::MessageSent` hits the `other => format!("{other:?}")` arm of `format_context_event` (crates/scp-ffi/napi/src/context.rs:1855), Debug output contains the variant name. Emission site: messaging_helpers.rs:1783-1793.
- (c) Meaningful exclusion: `eventLogQuery(..., {eventType:"MessageSent"})` → `length === 0`. NOT vacuous because eventLogQuery is a working filter-honoring mechanism (sibling tests return ContextCreated/join leaves; filter narrows via `filter_manager_entries`, event_log.rs:130-137). length 0 = "no MessageSent leaf", not "query always empty".
- (d) Drain hygiene: explicit pre-act `contextDrainEvents` clears create/join events so observed MessageSent is attributable to the send.

**Surfaces tested:** raw NAPI (`napi.*`) in real-napi.test.ts AND SCP-class (`scp.*`, camelCase→snake_case rename path) in integration.test.ts. Near-identical structure is intentional — pins different layers, not redundant. Integration variant must pass snake_case `event_type` (SCP surface dispatches filter JSON verbatim).

**Good pattern worth replicating:** "drain to clear → act → drain to observe" makes a mutable in-process event buffer assertion unambiguously attributable.
