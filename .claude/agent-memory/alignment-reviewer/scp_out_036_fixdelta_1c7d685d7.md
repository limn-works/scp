---
name: scp-out-036-fixdelta-1c7d685d7
description: SCP-OUT-036 cross-context bridge fix-delta 1c7d685d7 review — resolves prior #4b caveat_binding:None finding; ALIGNED w/ 2 LOW spec-text reconciliations
metadata:
  type: project
---

# SCP-OUT-036 fix-delta @ 1c7d685d7 (feat/outlet-xctx-036-bridge, scp-wt-slice3, 2026-07-14) — ALIGNED; resolves prior [[scp_out_036_bridge_runtime_9475d6d82]] #4b; 2 LOW spec-letter reconciliations + 3 OBS

Base 036 impl = 9475d6d82. Double-zero delta closing 5 findings (F1 caveat-binding thread, F2 authoritative cost gate, F3 terminal-on-truncation, F4 bounded reassembly, F5 request_id pin) + outlet.json nits.

**Why:** verifies each delta change vs governing artifacts (§5.4.5:568/570/572, §7.3.8, §6.2.4:276, ADR-061:64) for over/under-reach/contradiction.
**How to apply:** F1 RESOLVES my prior #4b (base passed caveat_binding None unconditionally → skipped entire §7.3.8 post-input hook). Don't re-raise #4b against this branch.

## Verdict: ALIGNED (2 LOW non-blocking reconciliations)

- **F1 caveat_binding thread — ALIGNED.** caveat_binding now first-class `Option<InvocationCaveatBinding>` threaded invoke_outlet_cross_context → open_outlet_stream_cross_context (supervisor.rs:11518) → open_outlet_stream. Slot VERIFIED: open_outlet_stream sig (supervisor.rs:11245) has caveat_binding as 12th positional, immediately before params — delta replaces the correct 4th-Some None. Some ⇒ §7.3.8 post-input hook + durable cross-invocation counter CAS (max_calls/amount_max_cumulative/rate_window) run; None = parity w/ same-ctx Option pattern (future FFI/SCP-OUT-047 supplies Some; story = "no FFI export (SCP-OUT-047)"). FIX1 test (supervisor.rs:11060) proves rate_window{max:1} rejects 2nd cross-ctx open w/ CaveatViolation. Removes silent narrowing vs same-ctx — correct direction.
- **F2 cost gate — ALIGNED to intent; closes REAL money bug.** cross_context_economy_gate now takes params.cost_per_chunk, rejects registered_paid||billed_paid. VERIFIED open_outlet_stream (supervisor.rs:11293) uses params.cost_per_chunk DIRECTLY for reserve w/ NO cross-check vs registration.cost.amount → split-source bypass (registration.cost==0 + cost_per_chunk>0 slips paid stream through zero-escrow pump-bills path) is GENUINE, not redundant defense. §5.4.5:554 says per-chunk accrual == cost.amount, so cost_per_chunk should never legitimately diverge; gating both-must-be-zero faithfully implements §5.4.5:572 zero-escrow ("serves zero-cost").
- **AC7 provenance — ACCURATE post-delta.** append_outlet_invoked_verified call site invoke.rs:4433 inside record_cross_context_a_event (4386); FIX3 terminal-synthesis inserts BEFORE the record call, doesn't displace it. grep returns 4376(doc)/4433(call)/7586(test).
- **outlet.json nits — 2 of 3 landed.** sources[] §9.7/§9.8/§6.2.4 all exist as headings (09:568/711, 06:240); §9.16 kept, no dup. description + AC9(seal-for-A) harmonized to §9.7/§9.8/§9.16 matching spec §5.4.5:568 verbatim triple.

## FINDINGS
1. **LOW — incomplete §9.7/§9.8/§9.16 harmonization.** outlet.json SCP-OUT-036 actionItems[2] STILL reads "§9.8/§9.16" while description + AC9 updated. Item-3 "no remaining stale refs" is FALSE. Authoritative=spec §5.4.5:568. Fix: update actionItem2.
2. **LOW spec-precision — F2 code stricter than AC12/spec letter.** §5.4.5:572 + AC12 frame rejection on cost.amount ONLY; code also gates cost_per_chunk. Faithful to zero-escrow INTENT (present in spec) but letter diverges. Per one-way flow: amend §5.4.5:572 + AC12 to bless the billed-value gate. Not a contradiction.

## OBS
- Root behind F2: open_outlet_stream (supervisor.rs:11293) trusts caller params.cost_per_chunk w/o validating ==registration.cost.amount (§5.4.5:554 unit). F2 closes it for zero-escrow; general cost_per_chunk==cost.amount invariant unguarded for paid saga path (SCP-OUT-046 scope).
- F5 request_id pin is redundant DiD: caveats_binding already commits request_id (§5.4.5:435), foreign-request_id chunk already fails sig verify. Comment honestly admits this; "matching §5.4.5:570 literally" slightly overclaims (§5.4.5:570 lists operator_pk/context_id/caveats_binding, NOT request_id) but spirit holds. Harmless, clarifies rejection reason.
- MAX_CROSS_CONTEXT_STREAM_CHUNKS=1<<20 is impl-chosen DoS bound, not artifact-derived (comment honest). Acceptable for best-effort; no spec governs it.
- invocation_error_to_terminal_payload dead arm now reuses registered SLUG_ECONOMIC_BUDGET_EXCEEDED (round-trips to Economic 6150) vs unregistered literal — cleaner, still 6150-not-6160 consistent w/ prior #2.
