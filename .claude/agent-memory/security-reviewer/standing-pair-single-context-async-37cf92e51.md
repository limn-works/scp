---
name: standing-pair-single-context-async-37cf92e51
description: Security review of §5.15.8 standing-pair reframe (saga removed -> single-context async), spec/standing-pair-not-a-saga-v2, rounds 1-3 (commits 37cf92e51 -> eb0645733 -> 38b99639a)
metadata:
  type: project
---

# §5.15.8 Standing-Pair Single-Context-Async Reframe — Security Review

Branch `spec/standing-pair-not-a-saga-v2`. DOCS-ONLY normative spec edit. Classification SETTLED: standing pair = ONE 2-member MLS context = single-context async creation, NOT a saga (prior PR #1793 2PC saga framing removed). Synchronized by MLS (epoch Commits + Welcome) + event-log RFC-6962 consistency layer.

## Round 3 (38b99639a) — verdict: SOUND, no findings
Round-3 added ONE change: collision-destroy now requires did_hi confirm the inbound Welcome's creator credential resolves to did_lo (from creator leaf ScpCredential after Welcome processing) BEFORE destroying its own self-created group; check + predicate + destroy atomic. CLOSES the targeted-DoS where an attacker who derives derived_context_id + addresses a Welcome to did_hi's KeyPackage could tear down did_hi's legit group. Verified consistent w/ §5.12.2, §9.3, §3.7.1, §9.4.3. All 6 prior focus areas remain sound. ALL prior round-2 MEDIUMs confirmed closed. No blocking items.

## Round 2 (eb0645733) — closed BOTH round-1 issues
- Reaper (d) gated on Welcome-deliverability: reap only after idle-bound AND Welcome no-longer-deliverable/expired. CLOSES round-1 MEDIUM (reap-Welcome-in-flight gap).
- Consent bypass closed: shared context clears first-contact stranger bar ONLY if not-self-created AND distinct (imports §9.3 "(not self-created)" qualifier). Mirrored into §5.12.2 bullet. CLOSES the manufacture-a-context self-clear bypass.
- Collision model rewritten asymmetric->SYMMETRIC: either party initiates ordinary create; did_lo/did_hi tie-break governs only the genuine simultaneous-create race; keyed on group AUTHORSHIP not leaf count; did_lo ignores did_hi Welcome so destroy equivocates against no peer.

## Round 1 (37cf92e51) — original 6-question pass (now all resolved)
1. Default-deny consent: SOUND. Stranger=no prior shared ctx; MUST NOT auto-join absent AutoAcceptPolicy. bilateral-persistent = memory_scope:full, tools:none.
2. Gate ordering block->opt-in->join: SOUND. Block-first; applied BEFORE MLS Welcome processing.
3. Existence-oracle: SOUND, no overclaim. Non-member AlreadyExists path constant-time(value+TIMING)-indistinguishable from generic rejection. Honestly concedes KeyPackage fetch (step2, pre-gate) is relay-observable; only SYNCHRONOUS reply oracle closed.
4. Collision destroy: SAFE. Fires only on self-created+peerless group (round-3 adds creator=did_lo confirmation). derived_context_id = pure fn of 2 DIDs.
5. Reaper: round-1 MEDIUM -> CLOSED round 2.
6. KeyPackage drain: SOUND. No bespoke reservation; single-use at join (fused-join two-anchor ADR-049 §9); fresh-DID fleet bounded by §9.3 earned-capacity at CONSENT-GATE-EVAL layer (not just join). 60s/1s-floor per-initiator-DID cooldown.

## Standing observations (non-blocking, carry forward)
- Injectivity now rides SOLELY on human method-admission gate (length-prefixed group_id backstop REMOVED). Spec honestly retracts "adds no security", labels len32-framing (§9.5.1 len32(did_lo)‖did_lo‖len32(did_hi)‖did_hi) a RECOMMENDED follow-up. MLS-layer defense-in-depth (GroupId/key-schedule/credentials) bounds blast radius. Ensure follow-up tracked.
- Constant-time-wrt-existence over a storage lookup is hard (row exists/not branches timing). Spec states requirement, not how. Implementer guidance recommended (resolve-then-constant-compare or fixed-cost path).
