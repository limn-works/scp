---
name: standing-pair-async-reframe
description: Attack surfaces in the §5.15.8 standing-pair "single-context async creation" reframe (branch spec/standing-pair-not-a-saga-v2)
metadata:
  type: project
---

# Standing-Pair Async Reframe (§5.15.8) — Attack Surfaces

Branch `spec/standing-pair-not-a-saga-v2` @ 3a161e640 reclassified standing-pair creation
from "cross-context saga" to "single-context async creation" (create + add_member + Welcome,
consent-on-Welcome-receipt). Files: 05-contexts.md §5.15.8, §5.15.4; 09-security-model.md §9.4.3;
ADR-049 §3/§3a; DEFERRED-commit-11.

## Confirmed oracle holes (the "no existence/block oracle" claim is FALSE end-to-end)
- **KeyPackage-consumption oracle (HIGH).** Step 2: A `add_member`s B by fetching+consuming B's
  *published* MLS KeyPackage from the relay BEFORE the consent gate runs (gate is on B's Welcome
  receipt, step 4). KeyPackage pools are public/relay-observable. A observes whether its fetch
  consumed a KP. The async consent gate only hides B's *join*, not A's *KeyPackage consumption* —
  which happens regardless of block. Block-status is NOT constant-time w.r.t. this side effect.
- **Welcome-delivery vs join asymmetry (MED).** A's Welcome lands on B's personal routing id
  `SHA-256(len||invitee_did||"scp-invitations")` — publicly derivable from B's DID. Relay sees
  the blob delivered. Existence of the *standing context* leaks via A's own event-log append +
  register_standing_context (step 3) which happen unconditionally, before/independent of B's consent.
- **Contact-graph self-write is unconditional (HIGH).** Step 3: A registers the pair Active +
  appends event log + register_standing_context BEFORE B consents and regardless of whether B
  ever joins. A blocked initiator still creates a live half-pair on its own node. The "indistinguishable
  from offline/slow peer" claim holds only for the *synchronous reply*, not for A's local state —
  A KNOWS it created the group; the oracle the spec closes is the wrong one.

## Consent-bypass: default-policy gap (CRITICAL candidate)
- bilateral-persistent template (§5.12.1) has NO opt-in field. Consent gate step 4(b) only fires
  "if B's contact policy requires opt-in." AutoAcceptPolicy (§5.12.2) is SDK-local, optional, and
  its TrustRequirement default is unspecified for standing pairs. If a context/identity has no
  opt-in policy configured, the ONLY gate is the block list (4a) — a stranger (not blocked) auto-joins.
  Spec never names a default; "legibility before opt-in" tenet implies default-open. Block-list is
  blocklist not allowlist → unsolicited standing pairs from any unblocked DID.

## Injectivity / id-collision
- Colon-join `"standing:"||did_lo||":"||did_hi` safety rests on DID-grammar (no raw ':'). did:dht
  z-base-32 + did:web %3A. The spec ADMITS a future DID method with raw ':' trips the assumption —
  "fail-loud at method-admission review" is PROCESS not mechanism. No length-prefix framing (explicitly
  omitted). MED: relies on human review gate, not code. derived_context_id MLS guard keys on
  SHA-256("standing-"||hex(id)) — collision-resistant, holds IF preimage injective.

## Amplification / DoS
- 60s default / 1s floor per-peer cooldown is per-INITIATOR-DID. Fresh-DID Sybil fleet (each once)
  bypasses cooldown; bounded only by §9.3 "expensive to sustain" DID minting. reserve-not-consume
  is GONE (saga removed) — now full create+add_member+Welcome+KP-consume per attempt. Each forged
  attempt forces A (victim initiator) or B (victim peer) real MLS work + KP pool drain at B. The
  KP-drain protection the saga's reserve-only Prepare provided is REMOVED; single-use is now only
  enforced at join (fused two-anchor) — but the *fetch* still drains the relay-visible pool.

## Provenance/authenticity
- No signed CreationReceipt (removed). Authenticity = "MLS Welcome binds B + first app msg Ed25519".
  But the Welcome itself is unauthenticated as a STANDING-PAIR assertion: a third party who knows
  B's DID + B's published KeyPackage can mint a Welcome to B's personal routing id. B's only defense
  is block-list + (maybe-absent) opt-in. No proof A *intended* a standing pair vs any other context.
