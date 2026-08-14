---
name: scp-out-036-xctx-bridge
description: SCP-OUT-036 best-effort cross-context outlet-stream bridge (commit 9475d6d82) black-hat findings — caveat-counter bypass, divergent cost gate, unbounded reassembly
metadata:
  type: project
---

# SCP-OUT-036 xctx outlet-stream bridge @9475d6d82 (branch feat/outlet-xctx-036-bridge)

## FIX DELTA @1c7d685d7 (F1/F2/F5) re-attack — NO BYPASS, fixes SOUND
- F2 CLOSED: billing on this path driven SOLELY by `params.cost_per_chunk` — reserve(supervisor.rs:11293) + counter_reservation(11354) + pump bill(dispatch.rs:3399) all read it; registration.cost NEVER bills here. Gate(invoke.rs:4288/4859) now rejects `registered_paid || billed_paid` → forces params.cost_per_chunk==0 → StreamEscrow::zero_escrow(dispatch.rs:1695). Amount=u64 (no negative). No cost_per_chunk mutation between gate(4859) and open(4900); supervisor(11541) passes params straight through. Gated field == billed field: split-source bypass gone.
- F1 ENFORCED not dropped: open_outlet_stream(11351-58) builds post-input hook + durable counter CAS from Some(binding), `?`-propagated into open_stream_session(11448-49). Test enforces_durable_counter NON-vacuous (2 opens distinct request_id same ucan_cid → 2nd CaveatViolation; would succeed if dropped). §7.3.8 caveat_binding (caveats+ucan_cid, gates open-admission counter) is SEPARATE from 32-byte descriptor.caveats_binding (gates chunk verify) — unrelated. None legit = no UCAN value-caveats (parity free path); binding-vs-UCAN authenticity is SCP-OUT-047 FFI job (no prod caller).
- F5 money-moot (path zero-cost) but correctness DiD: verify_forwarded_chunk(4230) rejects foreign request_id.
- Sole prod caller open_outlet_stream_cross_context(11510)→invoke(11541); no FFI export; rest are tests.


Files: crates/scp-runtime/src/context/outlets/invoke.rs (invoke_outlet_cross_context ~4629,
run_cross_context_bridge ~4444, cross_context_economy_gate ~4244, verify_forwarded_chunk ~4212),
supervisor.rs open_outlet_stream ~11229 / open_outlet_stream_cross_context ~11499.

KEY CONTEXT: seam is PLUMBED BUT UNWIRED. `open_outlet_stream_cross_context` has NO production
caller (only tests). FFI/consent-gate wiring is SCP-OUT-047. So findings are LATENT — they bake in
invariant decisions + a misleading comment that become live when wired.

FINDINGS:
- **F1 MED(→HIGH when wired): durable §7.3.8 caveat counter bypassed cross-context.** invoke.rs:4699
  passes caveat_binding=None to open_outlet_stream. None ⇒ build_stream_post_input_hook not called ⇒
  counter_reservation=None ⇒ commit_counter_reservation (dispatch.rs:1433, the durable Class-S
  caveat_counters CAS: max_calls one-increment-per-open, amount_max_cumulative reserve, rate_window)
  NEVER runs. Only the PER-STREAM max_billable ceiling survives (derived inside the pump from
  params.caveats.max_calls via effective_max_billable_chunks, stream.rs:642). The invoke.rs:4687-4689
  comment "§7.3.8 caveat ceiling still enforced through params.caveats/ucan_cid" is MISLEADING — it
  conflates per-stream ceiling with the cumulative cross-invocation counter. Same-context prod path
  (PyO3 outlet_stream.rs:556-580) passes Some(binding) → counter enforced. Cross-context evades a
  max_calls-limited delegation: unlimited cross-context streams under a max_calls:1 UCAN. Spec §5.4.5
  "zero-escrow" only blesses skipping ESCROW SETTLEMENT, not the caveat counter. Fix: build the binding
  from params.caveats+params.ucan_cid and pass Some, OR document + spec the intentional skip.
- **F2 MED: economy gate and escrow reserve read DIVERGENT cost sources.** Gate reads
  registration.cost (invoke.rs:4247, from caller-supplied registry). Escrow reserve reads
  params.cost_per_chunk (supervisor.rs:11293, caller-supplied). Neither re-fetched authoritatively from
  B's actor (contrast: caps+timing ARE re-fetched from ctx_params at supervisor.rs:11398-11421 as
  defense-in-depth). A caller with registry.cost=0 + params.cost_per_chunk>0 passes the zero-escrow
  gate while the pump bills + debits escrow — violates "best-effort is zero-escrow." Fix: gate on the
  same value the reserve bills, or re-derive cost from B's authoritative registration inside the seam.
- **F3 LOW-MED: unbounded reassembly + unbilled Progress = memory DoS on A by malicious B operator.**
  run_cross_context_bridge pushes EVERY forwarded chunk to `reassembled` Vec (invoke.rs:4573) with no
  total-count cap. Progress chunks are never billed and never terminal, so credit_window/max_billable
  don't bound them. A malicious/compromised B operator streams infinite Progress → A's bridge task RAM
  grows unbounded. The "no-buffer (bounded mpsc(1))" claim covers only the FORWARD channel, not the
  retained snapshot (which IS an unbounded in-memory buffer).
- **F4 LOW (defense-in-depth): verify_forwarded_chunk descriptor omits request_id.**
  CrossContextVerificationDescriptor pins (operator_pk, B ctx_id, outlet_id, caveats_binding) but NOT
  the stream's request_id; verify reconstructs preimage from chunk.request_id (chunk-asserted). Not
  triggerable inside run_cross_context_bridge (genuine inner_rx), but this is the spec's documented
  "verification source at the crossing" that A's OTHER members reuse against the UNTRUSTED shared-member
  bridge. A malicious bridge can splice operator-signed chunks from a DIFFERENT same-outlet/same-caveats
  stream (different request_id) and pass verification — a cross-stream replay the spec explicitly closes
  for cancels. Receiver should assert chunk.request_id == expected.
- **F5 INFO: chain_depth never incremented; depth-budget punted to unwired consent gate.**
  build_onward_a_leg_open clones incoming open verbatim (spec-consistent: same stream, inherited not
  incremented). Amplification bound (§5.4.5:276/ADR-043) depends entirely on the initiation path (NOT in
  this commit) incrementing. Carry-forward risk for SCP-OUT-047, not a defect here.

WHAT RESISTS: equivocation binding (operator sig preserved end-to-end, verified vs PINNED descriptor
not bridge-supplied); paid-Action reject checked BEFORE open (gate 4657 < open 4690); A-side independent
manifest recompute + ChunksBilledMismatch wire-reject at append_outlet_invoked_verified; chunks
structurally cannot carry chain_depth; repudiation closed for content B signed (A retains signed chunks).
Best-effort truncation/drop by bridge is an ACKNOWLEDGED gap correctly requiring the saga (SCP-OUT-046).
