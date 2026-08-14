---
name: adr051-causal-dag-convergent-clock
description: ADR-051 causal-DAG app-event ordering + multi-vantage median convergent clock — crypto soundness review (APPROVE)
metadata:
  type: project
---

# ADR-051 Causal-DAG Ordering + Multi-Vantage Median Clock

Reviewed 2026-06-19. Verdict APPROVE (model-level; implementation deferred to own program per ADR sequencing §1-2).

## What changed from prior design
Convergent clock redesigned member-population-median -> **multi-vantage median**: each event accrues signed sender/node/relay/receiver-quorum stamps. Canonical time = median of receiver-attestations (primary weight = counterparty audience) CLAMPED >= max(sender, relay-ingest) causal lower bound; node/relay = upper-sanity cross-checks. Deterministic closure over anchoring-epoch membership. Integer ms. Even-quorum = lower-of-two. NO small-context floor.

## Soundness verdicts
1. CONVERGENT: yes. Determinism inputs all convergent — receiver set closed by §5 predicate (anchoring-epoch membership attested by deadline, evaluated over convergent commit-ordered log = observation-order-independent); integer ms (no float nondeterminism); lower-of-two even tie (no mean); clamp bounds are signed stamps in the leaf. All honest members compute identical value.
2. CLAMP: SOUND. time >= max(sender, relay-ingest) makes backdating-EARLY require BOTH sender AND relay to lie low simultaneously (independent trust domains) AND receiver majority. "early clamped / late gameable" is correct asymmetry. RESIDUAL (acknowledged in ADR): clamp is a LOWER bound only — does not stop pushing time LATER. Late-bias = the stated residual (receiver-Sybil-majority claiming late receipt). Upper-sanity cross-check + admission cost + local throttle backstop. Honest.
3. TRUST CHARACTERIZATION: HONEST + materially better than rejected member-median. 4 vantages = independent trust domains, opposing incentives (sender under-reports; receivers are counterparty). Not honest-majority-of-single-population. Correctly labeled soft signal not guarantee, per "attestation is not a guarantee". Local throttle (§7, zero-trust, sender-unforgeable) is the real backstop — clock only feeds the DURABLE record, not live spam defense. Strong separation.
4. NO SMALL-CONTEXT FLOOR: SOUND. Spread among receiver stamps = latency + online/offline, not member count -> size-independent. 2-member context introduces no NEW unsoundness vs N-member: same clamp, same closure, same residual. Median of 1 receiver = that receiver's stamp clamped to max(sender,relay) — still bounded, still convergent. Removing floor is correct.

## Wire-auth fixes — design landed in ADR, concrete wire spec DEFERRED
- frontierRoot (sorted/dedup head-hash SET, not bare root) inside SCP-CHECKPOINT-V2 signed preimage: SPECIFIED in ADR §5 + sec-req #2. Equal-frontierRoot/equal-root test (never raw count).
- Receive-time signed: SPECIFIED (§6 + 09-security-model.md:813 amendment).
- Even-N lower-of-two + integer ms: SPECIFIED, KAT REQUIREMENT stated (sec-req #5, §25). 
- GAP (not blocking — ADR explicitly defers impl): §23.16.1 wire spec (23-sync-and-offline-strategy.md:332) and §25 KAT (25-test-vectors.md:412) STILL define only SCP-CHECKPOINT-V1, no frontierRoot, no receive-time. ADR-051 is "model decided; implementation is separate forward program" — the concrete V2 wire amendment + KAT vectors are step-2 deliverables. Provenance is clean (ADR is upstream of those wire edits).

## Open observations (LOW, for impl program — not ADR blockers)
- relay-ingest used as lower-bound clamp input is relay-signed but relay is untrusted; a lying relay can set ingest HIGH to push clamp up (late-bias) — falls under stated residual + upper-sanity check, but impl must ensure upper-sanity bound actually rejects relay-inflated ingest, else relay alone biases late. Worth a KAT.
- "relay = median-of-relays" (§6) needs the multi-relay set to itself be convergent for the clamp input to be convergent; single-relay deployments degrade to one relay stamp (acknowledged graceful degradation).
- node/relay omitted when no signing identity -> clamp degrades to max(sender) only (sender alone is the floor). Sound (sender stamp still signed) but weaker; documented.
