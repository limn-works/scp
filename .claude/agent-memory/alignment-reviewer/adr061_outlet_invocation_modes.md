---
name: adr061-outlet-invocation-modes
description: Review of ADR-061 (outlet invocation modes taxonomy) + §6.2.5 spec edit on branch feat/outlet-streaming-runtime — taxonomy sound but 3 missing upstream anchors + 1 fabricated ADR-049 §5 citation
metadata:
  type: project
---

# ADR-061 outlet invocation modes @ f5269dc59 (feat/outlet-streaming-runtime, worktree scp-wt-streaming, 2026-07-12) — NEEDS DISCUSSION

Reviewed new `ADR-061-outlet-invocation-modes.md` + new spec §6.2.5 "Outlet Invocation Modes" + §6.2.4 intro edit (all commit f5269dc59); HEAD 69fdd7ae8 ports streaming primitives stream.rs/signer.rs. Related: [[xctx-outlet-saga-streaming-reconciliation]] (this ADR is the canonical write-up of that proposal's synthesis).

**Taxonomy itself is SOUND**: two orthogonal axes delivery(unary/streaming) × envelope(best-effort/saga) = 4 modes. The synthesis (streaming saga = §6.2.4 envelope with committed artifact output_hash→stream_manifest_hash, single commit over bounded Merkle root, NOT per-chunk 2PC) is correct and matches prior reconciliation review. Reconciliation with what IS on this branch is accurate: ADR-049 §9 (Class-S, commit_class_s_keep) cite CORRECT; §6.2.4 saga present+detailed; §7.3.8 caveat-counter Class-S analogy defensible.

**THE PROBLEM — provenance broken/fabricated on THIS branch (3 of 5 cited upstream anchors absent, 1 fabricated):**
1. **FABRICATED (blocker-tier):** ADR-061 cites `ADR-049 §5 ("every outlet call is a stream" ergonomics)`. ADR-049 §5 is actually `OwnedIdentityDid: unforgeable by constructor visibility`. The phrase "every outlet call is a stream" appears NOWHERE in ADR-049 (grep-confirmed) — ONLY in ADR-061 itself. Real source per memory = OUTLET-refresh PLAN §5 Decision #1 (a plan, not ADR-049). Phantom citation in an Accepted canonical ADR. Fix the cite; if a plan really decided "every call is a stream," ADR-061 makes unary+streaming BOTH first-class w/ DIFFERENT integrity artifacts (output_hash vs stream_manifest_hash) → that DEPARTS from strict "unary = 1-chunk stream" and should be framed as superseding that plan framing, not citing it as support.
2. **MISSING anchor:** PRD SCP-OUT-036 cited repeatedly ("AC[2] bridge does not buffer... artifact-flow constraint") but SCP-OUT-036 exists ONLY on `origin/feat/outlet-redesign:.docs/prds/outlet.json` (status:done), NOT on this branch, NOT on main. AC[2] characterization is ACCURATE (0-indexed 3rd AC = "Bridge does not buffer; chunk-to-chunk latency bounded by MLS+relay"). But grounding story not resolvable here.
3. **MISSING anchor:** ADR-061 + §6.2.5 assert "delivery is a §5.4 concept". §5.4 on this branch = 5.4.1/5.4.2/5.4.2.1/5.4.3/5.4.4 — NO §5.4.5. §5.4.5 "Progressive Output (Streaming)" exists ONLY on origin/feat/outlet-redesign. The entire delivery axis (unary/streaming) has no §5.4 anchor here.
4. **MISSING registry:** SCP-OUTLET-CHUNK-SIG-V1 domain separator introduced by ADR-061 but NOT in §9.18.2 registry (which has SCP-XCTX-RECEIPT-V1). stream_manifest_hash defined nowhere but the ADR-061 edits themselves (no RFC-6962 construction spec, no §9.18 row). Not flagged as a consequence.

**RECEIPT SWAP (MODERATE, crypto):** §6.2.4 receipt preimage line 311 hardcodes `Fixed32(output_hash)` and line 319 declares "SCP-XCTX-RECEIPT-V1: is a new first-version separator, so the full field set is FIXED here with NO compatibility concern." ADR-061 Consequences says streaming-saga receipt "carries stream_manifest_hash" — so the swap IS flagged (not silent) but presented as clean field-swap. Reinterpreting the Fixed32 slot output_hash→merkle-root under the SAME closed separator is a domain-separation hazard (consumer can't tell which hash kind). Needs new separator (e.g. SCP-XCTX-STREAM-RECEIPT-V1) or explicit discriminator; ADR should flag the receipt-version question is OPEN.

**AC[2] "no buffer" vs durable capture (LOW):** NOT violated — durable SagaId-keyed capture is a Class-S replay snapshot (xctx_committed_outputs), not a latency buffer; per-chunk forwarding stays credit-gated. But ADR-061 doesn't explicitly reconcile "durable output capture" against "bridge does not buffer" — a future reviewer will read it as an AC[2] violation. Should state the distinction (matches prior reconciliation-review recommendation).

**Status claim ACCURATE (Q5):** plain invoke_outlet + start_cross_context_outlet_invocation_saga both on origin/main (core). "outlet stream in progress" matches HEAD porting stream.rs. "streaming saga planned" consistent (SCP-OUT-036 bridge=best-effort outlet-stream, done on sibling; saga envelope around it = planned).

**Naming (Q6, OBS):** "unary" is NEW vocab (gRPC-borrowed), introduced cleanly via normative naming rule. Residual tension: §6.2.4 heading still "Cross-Context Outlet Invocation Saga" while ADR says cross-context is NOT a mode discriminator — defensible (heading=where, mode=what) but noted.

ROOT CAUSE: ADR-061 + §6.2.5/§6.2.4-intro landed on a branch that ports streaming CODE but lacks the streaming SPEC anchors (§5.4.5) and PRD (SCP-OUT-036) that live on origin/feat/outlet-redesign. Per artifact-flow, upstream anchors must exist before the ADR cites them. Either integrate outlet-redesign's §5.4.5 + outlet.json onto this branch first, or the ADR dangles. VERDICT: NEEDS DISCUSSION (phantom ADR-049 §5 cite = fix-before-merge).
