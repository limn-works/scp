---
name: project-liveslot-collapse-scp-node
description: scp-node live-slot collapse (commit 9a7193702) — three newtypes → one LiveSlot<NodePublishedState>; position-keyed relay rewrite; address-vs-document gate split; supersedes the earlier frozen-snapshot memory
metadata:
  type: project
---

`crates/scp-node/src/published_state.rs` now holds the node's ONLY live slot:
`LiveSlot<T>` (private `modify`) over `NodePublishedState { document, relay_url,
record }`, plus `apply_tier_change` — the single post-construction writer — in
the same private module. Supersedes [[project-frozen-snapshot-live-slot-scp-node]]
(`NodeDidDocument` / `NodeRelayUrl` / `PublishedDidRecord` no longer exist).

**Why:** four review rounds each added one more newtype + ~36-line essay for the
same defect class ("a value captured at startup that a NAT tier change
invalidates"). The simplifier returned BLOCKER — non-convergent. The collapse was
net **-86 production lines** (code +14, comment -100) and cut the
`frozen.snapshot|unrepresentable|remember to|forget to` phrase count 21 → 5.

**How to apply** — three non-obvious design points that will look wrong if you
re-derive them from scratch:

1. **The document rewrite is keyed on POSITION, not on the current URL.** The
   first `SCPRelay` entry is the subject's preferred relay (§18.2.3). An
   address-keyed rewrite is circular AND retry-unstable: the address and the
   document are deliberately allowed to differ while a publish is failing, so on
   the retry an address key matches nothing and appends a duplicate.
2. **The address and the document are gated differently on purpose.** The relay
   URL is "where am I" — it advances on EVERY detected tier change, because the
   external address has already moved and `.well-known/scp` (public,
   unauthenticated) must not keep handing peers a dead endpoint. The document and
   signed record are *published* state and advance only on publish success.
   Consequently `spawn_tier_reevaluation`'s skip condition compares the
   DOCUMENT's endpoint, and `TierChanged` fires on address movement, not on
   publish success.
3. **The publish seam no longer writes the slot.** `NodeDidPublisher` is now just
   `{ inner, dht_mode }` and returns the record; the builders construct
   `NodePublishedState` from the publish result, so the record field is required
   at construction rather than re-seeded by a side effect.

Verification that mattered: `cargo doc` "public documentation links to private
item" fires if a `pub` doc comment links `[LiveSlot]` — the slot type is
crate-private, so those sites say "(No intra-doc link: the slot type is
crate-private…)" instead. See [[feedback-local-ci-full-gate-set]].

The pre-commit hook on this repo exceeds a 2-minute foreground Bash timeout —
run `git commit` with `run_in_background: true`. Never `--no-verify`.
