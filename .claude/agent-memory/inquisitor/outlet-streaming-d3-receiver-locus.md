---
name: outlet-streaming-d3-receiver-locus
description: SCP-OUT-039 D3 gap-detection receiver-locus re-review — spec §5.4.5 elevation RESOLVES incoherence/provenance-inversion; one residual MED doc contradiction survives at vectors_common.rs:392
metadata:
  type: project
---

# SCP-OUT-039 D3 receiver gap-detection — round-2 re-review @b523535c4 (feat/outlet-streaming-ffi)

Round-1 verdict INTERROGATE FURTHER: receiver-side gap-detection sited in 4 SDK drains by a
test-vector story, with same-PR incoherence (Rust tracker labeled TEST-ONLY/deferred-to-slice-3
while SDK ships production) + asymmetric revocation analogy. Acceptance condition: IF retained,
must become an explicit WRITTEN defense-in-depth spec decision, not a default inherited from a
vector story.

**Round-2 verdict: PREMISE RESOLVED (core sound).** The fix (a) elevated the locus into normative
spec §5.4.5 "Ordering and gaps" — a new receiver-locus paragraph naming the invoker-side SDK
`InvocationHandle` drain as the receiver bound by the MUST, paralleling the pre-existing §5.4.5
"Revocation re-check cadence (receiver-side)" locus; (b) reframed §25.21 from "slice-3 replaces
the tracker at the Rust layer" into a defense-in-depth reconciliation (slice-3 cross-context
detector is reconciled WITH the SDK-drain check, NOT a replacement). 
- Producer/receiver roles now cleanly split: runtime pump = PRODUCER (no gap to detect,
  same-context mpsc lossless); SDK drain = permanent transport-agnostic RECEIVER; Rust
  `ReceiverSequenceTracker` = TEST ORACLE (no prod Rust-layer receiver same-context). Same-PR
  incoherence GONE.
- Transport-independence grounding SOUND (tenet: no structural coupling to a transport; the
  drain is the transport-agnostic consumption point, dormant on lossless same-context, load-bearing
  on lossy cross-context/relayed). Revocation analogy now SYMMETRIC/apt (both are receiver-side
  SDK-framework invariants; revocation precedent is real spec prose, not invented).
- Provenance inversion RESOLVED: outlet.json SCP-OUT-039 description now cites the spec
  receiver-locus paragraph as source (spec→story, not story→code).

**RESIDUAL — MED doc-coherence contradiction (only surviving instance):**
`crates/scp-testing/tests/integration/outlet_stream_vectors_common.rs:392` still reads
"...slice-3, at which point the production detector replaces this tracker..." — the EXACT retired
framing the same commit struck from spec §25.21, reinstating the mental model (receiver gap check
= temporary Rust-layer thing awaiting a singular slice-3 production replacement) the reframe
killed. The fix pass DID edit this file (credit_stall rename) so it was in scope. vectors_real.rs
comments (:35/:265-267) are fine ("test-local reimplementation", "live trigger is slice-3
transport" — accurate, no "replaces"). Fix = restate line 392 to match spec: SDK-drain is the
permanent locus; slice-3 adds a reconciled cross-context detector as defense-in-depth; the
test-local oracle synthesizes the receiver rule until a lossy transport can drive it live.

Also folded in this fix pass (adjacent, sound): credit_exhaustion→credit_stall vector rename
(name now matches the terminal it drives, SCP-OUTLET-6133 credit-stall; distinct cumulative-ceiling
execution.credit-exhausted 6131 explicitly declared OUT of the 7-vector set = honest coverage
gap); multi_chunk gains a non-billable Progress chunk (advances seq cursor, not billed);
Swift OutletError.sequenceGap→streamGap rename + Execution-class recategorization.
