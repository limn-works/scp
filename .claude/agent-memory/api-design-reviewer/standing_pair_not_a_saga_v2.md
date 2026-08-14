---
name: standing-pair-not-a-saga-v2
description: API review of standing_context get-or-create Ok-return contract + saga carve-out (spec §5.15.8 / ADR-049 §3a), branch spec/standing-pair-not-a-saga-v2 @37cf92e51
metadata:
  type: project
---

Reviewed spec §5.15.8 "Standing-Pair Creation (Single-Context Async)" + ADR-049 §3/§3a saga carve-out. Docs-only. Classification SETTLED: standing-pair creation = single-context async via `standing_context(peer) → ContextHandle` get-or-create, NOT a saga / NOT a start_*_saga FFI export. Verdict APPROVED with 2 LOW caller-surface gaps.

**Why:** Standing pair = ONE MLS group, 2 members, both derive identical derived_context_id; replicas synced by MLS + event-log RFC-6962 layer, no cross-context atomicity ⇒ no saga. Saga surface is now exactly TWO: §6.2.4 cross-context tool invoke + §5.14.13 broadcast hosting handshake.

**How to apply (open residuals if this surface is revisited):**
- LOW-1: Ok-return contract is written 100% from the did_lo (initiator-creates) perspective ("initiator's replica created + Welcome dispatched"), but the single-creator rule admits did_hi as a legitimate *initiator* whose call instead fetch/awaits did_lo's Welcome. Spec never states what did_hi's `standing_context()` returns/blocks-on or what handle it hands back when did_hi is not yet a member. Recommended resolution (matches section's async philosophy): did_hi returns same Ok + same handle type immediately, observes its own membership out-of-band. Needs one explicit sentence.
- LOW-2: Reaper (clause d) GC's orphaned single-member replicas, but spec never says what happens to a `ContextHandle` the consumer still holds after reap (fail-closed typed error vs transparent re-drive). Deterministic id makes transparent re-drive natural — matches ADR-049 Decision-10 "standing_context unconditionally resets crash window on re-contact" auto-revive. Also: clause (c) names the join-observation *mechanism* (MLS Commit → two leaves) but not the caller-facing *observable* (does ContextHandle expose member_count()/membership event?).

**Settled / clean (do not re-litigate):** Ok ⇏ peer joined; identical handle type create-or-found; no synchronous join confirmation (block-privacy oracle foreclosed); existence-oracle prohibition (AlreadyExists→Ok ONLY for verified-self-membership, else generic rejection, timing+value indistinguishable); FFI carve-out consistent in all 4 ADR locations; Phase-2E direction asymmetry (initiator→peer functional today, joiner-send gated on spawn-from-Welcome = ADR-049 Follow-up #1); MLS Welcome binding = interim authenticity anchor, per-message Ed25519 InnerEnvelope sig = additional anchor once bidirectional send lands.

`standing_context → ContextHandle` mirrors sibling `create_context → ContextHandle` (05-contexts.md lines 769/780); example flow line 951.
