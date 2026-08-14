---
name: outlet-streaming-033-034-035-cancel-billing
description: SCP-OUT-033/034/035 completion @f96079706 — cancel-boundary billing Option-B (billed=5), durable monotonic_seq, Option<u64> cancel_ack_seq, slice-2-in-slice-3 status flips
metadata:
  type: project
---

# SCP-OUT-033/034/035 completion @f96079706 (branch feat/outlet-xctx-streaming-saga)

Interrogated the cancel-boundary billing decision + adjacent choices. Verdict: central decision SOUND.

## Central decision (Option B, billed=5 not =6) — PREMISE HOLDS, spec+story mandated
- §5.4.5:530(1) "chunks already in flight at that sequence are NOT counted as billable" + 530(3) "terminal chunk's `sequence` IS the cancel-ack sequence" JOINTLY mandate: terminal occupies cancel_ack_seq, Data at seq>=cancel_ack_seq dropped-not-billed. The gate boundary MUST be `>=` (not `>`) — `>` would force the terminal to seq cancel_ack_seq+1, breaking 530(3). So `>=` is the ONLY choice consistent with 530(3).
- STORY AC24 itself says "cancel at 5 after 8 Data; chunks_billed=5 (not 8)". Option-B matches the story verbatim. The =5 is ONLY reachable via the terminal-occupies-slot model. Option C (accept =6 + reword AC) would require BOTH rewording AC24 AND contradicting spec 530(3) — not actually available. This is code conforming to spec+story (one-way flow honored), not AC-gaming.
- inclusive `<= cancel_ack_seq` formula (§5.4.5:563/`compute_chunks_billed_ref`) UNCHANGED and correct: manifest never carries a Data at the ceiling (terminal is there), so inclusive count == data at seq < ceiling. Verify path (invoke.rs `is_billable_chunk`, `<= ceiling`) is consistent because the `>=` gate already dropped seq==ceiling before that check runs.
- No under-bill race: cancel_ack_seq pinned = next_emission_seq under the SAME state.write() lock as gate+forward (dispatch.rs:3110/3164). Already-forwarded Data got seq<ceiling→billed; not-yet-forwarded at cancel got seq==ceiling→dropped. Exactly 530(1).

## Findings
- MED (decision-rot scar tissue): dispatch.rs:5322-5328 test NOTE on `pump_midstream_cancel_truncates_billing_035_ac3_034_ac24` states "with cancel_ack_seq=5 the runtime bills Data at outer sequences 0..=5 (SIX chunks). The two Data at sequences 6,7 are dropped" — the RETIRED Option-C/`>`-boundary mental model, contradicting the assertions right below it (billed_count==5, stream_chunk_count==6, "seq>=5 dropped"). Actively misleading in the canonical doc for the boundary decision. Strike/rewrite the NOTE.
- MED (coherence/provenance overstatement): commit claims it resolves "the 037/038/039-done-over-pending dependency inversion" but only closes the 033/034/035 leg. 037 depends on 036 (Best-effort xctx re-encrypting bridge) which is STILL pending; 037/038/039 all done. Done-over-pending persists on the 036 leg. Either the 037→036 dep edge is wrong (remove it) or 037/038/039 are prematurely done. ROOT of the inversion = prior commit #2125 flipping slice-3 FFI/SDK (037/038/039) done while runtime deps pending.
- LOW-MED QUESTION: `CancelAckTracker::cancel_ack_seq()` returns None for BOTH Active AND Closed (stream.rs:1078) — None overloaded ("no cancel" vs "cancel+terminal-emitted"). Safe TODAY only because dispatch.rs:3164 reads cancel_ack_seq() BEFORE record_terminal() at :3165. No structural guard prevents a future reorder → cancelled streams would silently record cancel_ack_seq=None in the durable event (and wire-verify would use u64::MAX ceiling). Cleaner: Closed{cancel_ack_seq: Option<u64>} to keep the value recoverable post-terminal.

## Decisions checked and SOUND
- Durable monotonic_seq (scp-ffi/common/outlet_stream_credit.rs, AC31): story MINOR-22 explicitly names option (a) persist to ProtocolRepository `context/{id}/stream_credit_counter/{request_id}` OR option (b) (stream_epoch,wall_clock_ns). Chose (a). (b) is arguably DOA: wall_clock can regress across restart → seq regression → CreditReplay. New failure mode (storage-fail→Err→no grant) is FAIL-SAFE and consistent with streaming's existing ProtocolRepository dependency (saga journal/reservations). persist cursor+1 BEFORE returning; reload = the retrieve on next grant. Minor: module doc could note why (b) is unsound.
- cancel_ack_seq: Option<u64>, None→billing_ceiling u64::MAX (stream.rs:1091): NOT a footgun. None=uncancelled=bill every Data is the CORRECT default. Event field derived single-source from the tracker (dispatch:3164), can't desync from ceiling.
- Slice-2 stories completed in slice-3 branch: acceptable remediation (slice-3 sits atop this runtime; branch is internally consistent once runtime is real). Minor atomicity: bundles G4 spec fix (§5.4.5:521 6100→6101, correct: 6100=protocol.violation, 6101=protocol.session) + 3 status flips + new durable subsystem in one commit.
