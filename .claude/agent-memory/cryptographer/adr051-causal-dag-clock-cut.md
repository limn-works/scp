# ADR-051 Causal-DAG Application-Event Ordering (clock cut) — crypto review 2026-06-19

ADR replaces convergent velocity clock with clockless causal-DAG. Reviewed for crypto soundness.

## Verdict: CHANGES-NEEDED (one real dangling-clock reference + spec/ADR coherence gaps)

### Core construction = SOUND
- Convergent ORDER+COUNT, not time. Linearization: topo sort on causal edges, concurrent events tie-break by ascending canonical leaf hash SHA-256(0x00 ‖ rmp_serde(Event)) (§25), constant-time compared. Clock-independent — correct.
- Tie-break author-influenceability neutralized on count axis by must-include-frontier (§1, prevents manufactured concurrency) + per-author-aggregate rule (§2, counts key on sender's own aggregate not cross-author position). Sound: reordering A vs B changes no per-author count, and there is no time axis to protect.
- §5 frontier equivocation test: ConsistencyCheckpoint gains frontierRoot = commitment to canonically-sorted/deduped head-hash SET, inside signed preimage of versioned SCP-CHECKPOINT-V2. Test = equal-frontierRoot ⇒ equal-merkleRoot. Well-defined and does NOT depend on receive-time (no receive-time field ever existed in ConsistencyCheckpoint — V1 had context_id/sender_did/event_count/merkle_root/epoch/timestamp; timestamp is a freshness hint, not a clock input to the test). Clock removal left frontier test intact.

### FINDING 1 (MEDIUM, real, fix): phase-2.md:912 dangling "median clock"
ADR-011 amendment text in phase-2.md line 911-912 reads "**ADR-051 (causal-DAG application-event ordering + median clock)**". ADR-051 REJECTS the median clock as "the central decision" (Alternatives, line 77). Phantom provenance — downstream artifact names a construction the governing ADR explicitly cut. Fix: delete "+ median clock".

### FINDING 2 (LOW, coherence): SCP-CHECKPOINT-V2 / frontierRoot not yet in §23.16.1
ADR-051 §5 + Security-req 2 mandate authenticated frontierRoot inside SCP-CHECKPOINT-V2 signed preimage. §23.16.1 still documents only SCP-CHECKPOINT-V1 (no frontierRoot field, no V2 preimage). ADR is explicitly an "implementation program" sequenced AFTER step-1 unification, and §9.8.5/§23.7 carry interim qualifiers, so this is acceptable as deferred IMPLEMENTATION — but the V2 wire format / preimage byte layout is undefined at spec level. When DAG step lands, §23.16.1 must define: V2 domain sep, where frontierRoot sits in the BE32-len-prefixed preimage, and the canonical sort+dedup byte rule for the head-hash set. Not blocking the ADR; flag so it isn't lost.

### FINDING 3 (LOW): §25 KAT vectors for Security-req 5 absent (expected — deferred)
Security-req 5 mandates KAT: (a) DAG linearization partial-observation snapshot, (b) frontierRoot bytes for unsorted/duplicate head set, (c) tool_invocation_count over fixed DAG. None exist in §25 yet (29 vectors, none frontier/DAG). Correct for step-1 interim (the median/clock KATs are gone, good — no stale vectors left). These 3 are the right & complete set for the DAG step. anchored=false interim KAT (Security-req 6) also pending.

### No crypto incoherence introduced by clock cut
- anchored bool field (ParticipationProfile.tool_invocation_count_anchored, PaymentReceipt.anchored) covered by existing signature — consumers mechanically distinguish convergent vs interim-local. Sound.
- Velocity→local throttle (receiver clock, unforgeable by sender, no record) + suspension→governance commit (execution IS record). Governing theorem "automatic+convergent iff trigger input convergent" is correct.
- Economic SenderVelocity/ContextMessageRate enforced at authorize() against local ledger — no convergent clock needed. Coherent.
