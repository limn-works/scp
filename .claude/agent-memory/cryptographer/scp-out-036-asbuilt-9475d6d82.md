---
name: scp-out-036-asbuilt-9475d6d82
description: As-built crypto verification of SCP-OUT-036 best-effort cross-context outlet-stream bridge (commit 9475d6d82) — SOUND
metadata:
  type: project
---

# SCP-OUT-036 as-built (commit 9475d6d82, feat/outlet-xctx-036-bridge)

Realizes the Option-1 design I previously validated ([[xctx-036-plaintext-bridge-mls-reencrypt]]). VERDICT: cryptographically SOUND, no findings above INFO.

**Files:** invoke.rs (`invoke_outlet_cross_context`, `run_cross_context_bridge`, `CrossContextVerificationDescriptor`, `verify_forwarded_chunk`, `cross_context_economy_gate`, `forward_bridge_terminal`, `record_cross_context_a_event`); supervisor.rs (`open_outlet_stream_cross_context`); outlets_helpers.rs (6150 ContextError mapping).

**Q4 (the crux) — `caveat_binding: None` is NOT a crypto weakness.** Two DISTINCT confusingly-named fields:
- `caveats_binding: [u8;32]` (`params.identity.caveats_binding`) = the 32B hash committed into EVERY chunk-sig preimage. Threaded through `params`; read by BOTH the B-side pump signer (dispatch.rs:2275) AND the A-side descriptor (`descriptor.caveats_binding = params.identity.caveats_binding`, captured before `params` is moved into open_outlet_stream). Identical by construction ⇒ AC11 pinning + equivocation binding intact.
- `caveat_binding: Option<InvocationCaveatBinding>` (the `None`) = the DURABLE §7.3.8 cross-invocation caveat COUNTER hook. `None` ⇒ `(caveat_post_input_check, counter_reservation) = (None,None)` (supervisor.rs:11351). Disables only the durable counter/post-input check; does NOT touch `params.identity.caveats_binding`.
No economic consequence: bridge is zero-escrow (paid Action rejected), so cost_per_chunk=0 ⇒ amount_max_cumulative counter bounds zero spend. `verify_caveats_binding_at_open` (dispatch.rs:1649) still recomputes+pins the sig-preimage binding vs params.caveats when ucan_cid non-empty (early-returns Ok on empty ucan_cid — PRE-EXISTING, shared w/ same-context path).

**Q1 no re-sign:** `outer_tx.send(chunk.clone())` forwards B's operator sig verbatim; bridge NEVER re-signs a forwarded operator chunk. Synthesized terminals (`forward_bridge_terminal`) carry `sig:[0u8;64]` — genuinely bridge-authored, and CANNOT masquerade as operator-signed because `verify_chunk_signature` uses `verify_strict` which rejects all-zero R (small-order). Zero-sig terminals carry no data/economic authority.

**Q2 AC10 real MLS:** `stand_up_two_party` = REAL openmls (KeyPackage reserve, real Welcome, X25519 DH, create_mls_group_with_context). Outsider = fresh MlsCryptoProvider, no A key ⇒ open() Err (confidentiality). Member recovers chunk, `verify_chunk_signature(&recovered, operator_pk, B_CTX, ...)` true. Non-vacuous.

**Q3 AC11 pinned:** descriptor pinned at open from governed params (operator_signer key = the SAME key that signs B's chunks ⇒ can't disagree). Forged ctx_id chunk ⇒ `verify_forwarded_chunk` false ⇒ CODE_AUTHORIZATION_DENIED terminal.

**Q5 no new codes/domains:** CODE_ECONOMIC_FAULT="SCP-OUTLET-6150" pre-existing; CrossContextPaidActionUnsupported maps to it. Terminal-payload exhaustiveness arm documented-unreachable (open-time Err, not a chunk). No new `b"SCP-*"` domain const/preimage — all compute_chunk_sig_preimage additions are TEST code reusing existing fn. Preimage sound: domain prefix `SCP-OUTLET-CHUNK-SIG-V1:`, len-prefixed var fields, fixed-width remainder.

**INFO only:** naming collision `caveat_binding` (counter hook) vs `caveats_binding` ([u8;32] sig input) is a maintainer footgun. In-process `verify_forwarded_chunk` is partly redundant (verifies B's own fresh sigs vs B's own key) but correct defense-in-depth + governed-pinning demonstration for the DELIVERY seam to A's other members.
