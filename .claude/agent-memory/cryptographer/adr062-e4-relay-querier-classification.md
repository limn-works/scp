---
name: adr062-e4-relay-querier-classification
description: ADR-062 E4 NoOpRelayQuerier is a completeness/defense-in-depth gap (fails CLOSED), NOT a security nullifier — resolved from spec §3.10 + §17.17.2 + code
metadata:
  type: project
---

# ADR-062 E4 (NoOpRelayQuerier) — completeness gap, NOT nullifier

VERDICT (2026-07-14, grounded spec+code read): E4 `NoOpRelayQuerier` (scp-identity/src/resolver.rs:309) is a **completeness / defense-in-depth gap that fails CLOSED**, not an SCP-CAPSEL security nullifier. The second reviewer was right; "fails-OPEN on suppression detection" is unsupported. May ship honestly as DHT-only interim until Slice 11 builds the real `MultiRelayQuerier` (§3.10.12). ADR-062 §Decision 5 / classification table (lines 41, 111) is correct.

**Why:** The §17.17.2 discriminator (17-persistence-and-storage.md:1022): durability-only/fail-closed = "unable to answer, not able to answer falsely"; nullifier/fail-open = "continues to answer, but the answer no longer carries the guarantee the caller believes." NoOpRelayQuerier.query ALWAYS returns `Ok(None)` — it never answers at all, let alone falsely. Every real relay record is BEP44-verified (verify_and_deserialize) before accept anyway. DualLayerResolver pick_winner (None,None)=>None; resolve returns `Ok(None)` on both-fail — §3.10.4 "MUST NOT fabricate" honored.

**Key distinctions:**
- vs in-memory DHT nullifier (§17.17.3 / SCP-CAPSEL-8013): DHT nullifier fails open on the PUBLISH side ("silent false success" — reports publish OK while DHT got nothing) AND empties the namespace on resolve. NoOpRelayQuerier is RESOLVE-only, makes no success claim, and the real DHT (Pkarr) still publishes+resolves. The publish-both MUST (§3.10.6) is honored → every conformant identity is on the DHT → still resolvable.
- Anti-Segmentation MUST (§3.10.6) is a PUBLISH-side invariant ("Publishing to both layers is a MUST"). Resolution-from-both is explicitly a **SHOULD** ("not required for correctness"). NoOp touches only the resolve side → nullifies no MUST.
- §3.10.8 dual-layer suppression resilience is an **alternate resolution PATH**, NOT a detection-triggered protective ACTION. Protocol takes no action ON suppression detection — it just has redundant paths. So there is no "behavioral fail-open" NoOp skips.
- Only detection-triggered action in resolver = maybe_trigger_healing (§3.10.7), fires on STALENESS DIVERGENCE (both layers return valid docs, different seq), not suppression; and it's a MAY-republish best-effort. Its non-firing under NoOp is the completeness gap itself, not a fail-open.

Under DHT suppression a NoOp-relay node returns honest not-found `Ok(None)`/DID_RESOLUTION_FAILED (5010), never a forged/stale/false doc (rollback-protected: rejects seq<cached_seq, resolver.rs:518-545). Availability reduced (suppress "DHT alone" vs "all relays AND DHT"); authenticity/reachability/freshness preserved. Disabled-DHT + NoOp-relay = every resolve Ok(None), still fail-closed (ADR line 195).
