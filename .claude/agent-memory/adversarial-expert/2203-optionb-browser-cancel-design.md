---
name: 2203-optionb-browser-cancel-design
description: #2203 Option-B browser-initiated OutletCancel (fetch-then-sign) design review — DO NOT SHIP AS-IS; headline is the next_seq-in-preimage DOA + economic-equivalence-with-floor redundancy.
metadata:
  type: project
---

# #2203 Option-B cross-context browser OutletCancel (fetch-then-sign) — design verdict

Reviewed design doc @ scratchpad/2203-design.md against code @ commit 14c3dd93c
(outlet streaming lives on feature branches only; main/HEAD 1620de983 has NO outlets dir).
Key files: crates/scp-runtime/src/context/outlets/dispatch.rs + stream.rs; §5.4.5 in .docs/specs/05-contexts.md; ADR-057.

## Factual claims in design VERIFIED true
- apply_outlet_cancel_verbatim (dispatch.rs:1146): cross-checks cancel.next_seq==guard.next_emission_seq FIRST (CursorAdvanced, NO mutation), THEN verify_cancel_signature under pinned invoker_pk + (ctx,outlet,caveats) triple. dead_code awaiting caller. Real.
- current_next_emission_seq (877): reads guard.next_emission_seq. Real.
- Native apply_outlet_cancel_signed (1009): ALREADY does fetch-then-sign IN-PROCESS — lock1 read cursor → off-lock await sign → lock2 re-check, retry cap MAX_CURSOR_RETRIES=4, else CursorAdvanced (retryable). This is the co-located analog Option-B distributes over the network.
- record_cancel (stream.rs:1049) idempotent (Active→Pending once); cancel_ack_seq = billing ceiling; billing_ceiling u64::MAX when no cancel. Cursor monotonic (only bumps on signed emission under gate lock, dispatch.rs:3079).
- Option-A floor real: credit-stall (parked-chunk path only) + cancel-ack timers fire in BOTH parked/non-parked selects (2854/2916); settlement (3128) refunds escrow + releases per-context AND origin admission.

## HEADLINE FINDINGS (blockers)
1. ECONOMIC EQUIVALENCE = redundancy. Convergence REQUIRES withholding credit (design admits). But a frozen cursor makes cancel_ack_seq == emitted count == the u64::MAX-ceiling floor's billed amount. So Option-B bills IDENTICALLY to just letting the floor fire. Its only real benefit is faster close + explicit invoker-signed cancel_ack in provenance. In case (a) executor-has-parked-chunk it may even be SLOWER (waits stream_cancel_ack_secs vs stream_credit_stall_secs). Genuine value is narrow: case (b) idle-but-open executor with no timeout_ms — pure Option-A hangs (credit-stall only arms on a parked chunk; timeout_ms is Optional and applies to the inner executor pump, not the outer). Cleaner fix: mandate a universal outer-pump idle/max-duration floor, not a browser retry protocol.
2. next_seq-in-preimage is the DOA smell. SCP-OUTLET-CANCEL-V1 binds next_seq INTO the invoker signature → browser MUST fetch cursor before signing → the entire network-TOCTOU retry protocol exists ONLY to satisfy this. The ceiling is node-derived anyway (cross-check). A next_seq-FREE cancel-intent (bind only ctx,outlet,request_id,caveats) would let the invoker sign "terminate" with no fetch, node reads its own cursor atomically at ingest = ceiling. Eliminates fetch RTT + retry loop + livelock entirely, serves native+browser uniformly. next_seq-in-preimage may only be load-bearing for cross-context multi-hop FORWARDING (verbatim replay of originator ceiling to a downstream) — which is node-side coordination, NOT the browser direct path. Design has NOT ruled this out. Must justify before committing permanent wire.

## Axis verdicts
1 Money: no billing forge via cancel path. Cross-check pins ceiling=truth; cursor-lie→retry/floor never wrong ceiling; replay killed by monotonic cursor + idempotent record_cancel; malicious node already billing authority (no new capability). SOUND.
2 Liveness: convergence argument holds under honest-node/untrusted-relay TM (emission consumes credit ⟹ withdrawal freezes cursor). Relay can only force retries→floor. Floor reachable EXCEPT idle-no-timeout executor (case b). Griefing bounded.
3 Fence: HOLDS mechanically (no scp-runtime dep; reuses wasm-safe scp-protocol crypto). But browser driving a state-reactive bounded-retry loop is a precedent worth explicitly bounding to {self-signed, single-party, idempotent, bounded-retry, passive-floor}. Native-vs-wasm asymmetry (atomic in-proc vs distributed saga for the SAME op) is a smell.
4 "Hint not load-bearing": TRUE. Fetched cursor only gates accept/reject; recorded ceiling always == live == truth. IMPL BLOCKER: fence the fetched value to the cancel-signing path ONLY (must not feed receiver gap-detection / billing-display — conflation with OUT-048 #expectedSequence would mislead user).
5 DOA: fetch-then-sign is NOT clearly the right permanent design given #1+#2.

## Recommendation
DO NOT SHIP as-is. Not because it's exploitable (billing is sound) but because it commits a permanent TOCTOU retry wire format that (a) is economically redundant with the floor and (b) is very likely avoidable via a next_seq-free node-derived-ceiling cancel-intent. Escalate the next_seq-in-preimage question to cryptographer + human BEFORE any code. Preferred: node-derived ceiling + mandatory universal floor timeout.
