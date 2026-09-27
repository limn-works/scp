---
name: project-liveslot-collapse-scp-node
description: scp-node keeps one LiveSlot<NodePublishedState>; three design points in it look wrong when re-derived from scratch (position-keyed relay rewrite, address-vs-document gating, publish seam that does not write the slot)
metadata:
  type: project
---

`crates/scp-node/src/published_state.rs` holds the node's only live slot:
`LiveSlot<T>` (private `modify`) over `NodePublishedState { document, relay_url,
record }`, plus `apply_tier_change`, the single writer after construction, in the same
private module.

**Why one slot:** four review rounds each added one more newtype and a long comment for the
same defect class ("a value captured at startup that a NAT tier change invalidates"), and the
simplifier returned BLOCKER as non-convergent. The collapse removed 86 production lines. When
a new `NodeState` or `ApplicationNode` field is re-derived by a background loop, it belongs in
the slot; a plain value is stale by construction, and every reader stores a clone of the slot,
never of its contents.

**Three design points that look wrong if re-derived:**
1. **The document rewrite is keyed on position, not on the current URL.** The first
   `SCPRelay` entry is the subject's preferred relay (§18.2.3). An address-keyed rewrite is
   circular and retry-unstable: the address and the document may differ while a publish is
   failing, so on the retry an address key matches nothing and appends a duplicate.
2. **The address and the document are gated differently on purpose.** The relay URL ("where
   am I") advances on every detected tier change, because the external address has already
   moved and `.well-known/scp` must not keep advertising a dead endpoint. The document and
   signed record are published state and advance only when a publish succeeds. So
   `spawn_tier_reevaluation` compares the document's endpoint to decide whether to skip, and
   `TierChanged` fires on address movement, not on publish success.
3. **The publish seam does not write the slot.** `NodeDidPublisher` is `{ inner, dht_mode }`
   and returns the record; the builders construct `NodePublishedState` from the publish
   result, so the record is required at construction instead of seeded by a side effect.

A `pub` doc comment that links `[LiveSlot]` fails `cargo doc` ("public documentation links to
private item"), because the slot type is crate-private.
