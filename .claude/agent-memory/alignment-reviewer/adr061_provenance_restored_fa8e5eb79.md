---
name: adr061-provenance-restored-fa8e5eb79
description: RE-REVIEW of ADR-061 streaming-outlet provenance @ fa8e5eb79 — all 4 prior BLOCKERs resolved, VERDICT PROVENANCE RESTORED; residual §5.4.5-anchoring + SCP-TOOL code + §6.2.0.5 drift
metadata:
  type: project
---

RE-REVIEW of [[adr061_outlet_invocation_modes]] BLOCKERs @ fa8e5eb79 (feat/outlet-streaming-runtime worktree scp-wt-streaming). Fix commits: 2c854d05a (revise ADR-061+§6.2.5 four-lens), 38592c876 (§5.4.5 + §9.18.2 separators), 04c552b06 (port outlet.json PRD), fa8e5eb79 (register 3 remaining §9.18.2 rows).

**VERDICT: PROVENANCE RESTORED.** All 4 prior BLOCKERs resolved:
1. FABRICATED ADR-049 §5 cite — RESOLVED. ADR-061:7 now explicitly "**Supersedes** the informal 'every outlet call is a stream' unification (a *planning-note* framing, never an ADR)...(An earlier draft mis-cited this as 'ADR-049 §5'; ADR-049 §5 is OwnedIdentityDid...The mis-citation is removed.)". Phrase now appears ONLY in ADR-061 as a superseded-framing note, not as an authority cite. Correctly reframed as supersede-not-cite (unary→output_hash vs streaming→stream_manifest_hash, distinct integrity artifacts, NOT 1-chunk stream).
2. SCP-OUT-036 findable — RESOLVED. .docs/prds/outlet.json present (270KB), SCP-OUT-036 intact @ line 2130, sources trace to real headings (§6.2.5, §5.4.1, ADR-061 all exist). `python3.12 scripts/validate-prd.py` PASSES (14 files, 418 stories).
3. §5.4.5 present — RESOLVED. 05-contexts.md:345 "### 5.4.5 Progressive Output (Streaming)" fully authored + numbered consistently. Wire types, caveats_binding/chunk-sig/credit/cancel preimages, admission caps, billing, cross-context all present. Cross-refs resolve (§6.2.5, §6.2.4, §7.3.8, §9.18.2).
4. §9.18.2 rows — RESOLVED. 09-security-model.md:1631-1636 all 6 separators present: SCP-OUTLET-CHUNK-SIG-V1, -CHUNK-V1, -CAVEAT-BIND-V1, -CREDIT-V1, -CANCEL-V1 (all →§5.4.5), SCP-XCTX-STREAM-RECEIPT-V1 (→§6.2.4). Match §5.4.5 "registered in §9.18.2" claims.
+ RECEIPT-SEPARATOR HAZARD (prior MOD) — RESOLVED. §5.4.5:566 + §6.2.5:366 use DISTINCT `SCP-XCTX-STREAM-RECEIPT-V1` carrying stream_manifest_hash directly, NOT reinterpreting output_hash slot under §6.2.4's closed SCP-XCTX-RECEIPT-V1 separator. Domain-sep clean.

**RESIDUALS (none reopen a BLOCKER):**
- MODERATE cross-artifact drift: PRD numeric error codes are SCP-TOOL-61xx throughout outlet.json (e.g. AC `code: 'SCP-TOOL-6133'`); spec §5.4.4 (governing taxonomy, canonical at base 6e7cd3066) + §5.4.5 define them as SCP-OUTLET-61xx (spec has ZERO SCP-TOOL). PRD SCP-OUTLET-* refs are all separator/class names (letter after dash), never the numeric codes. 04c552b06 reconciled section citations but NOT the code namespace. Implementer following AC would emit wrong prefix. Spec-side SCP-TOOL→SCP-OUTLET rename IS complete; PRD-side is not.
- LOW: SCP-OUT-036 description (outlet.json:2140) cites "§6.2.0.5" which does not exist on this branch (06 has §6.2.0/.0.1/.0.2 only; streaming content is §6.2.5). Sole dangling ref; sources[] correctly cite §6.2.5. The "§6.2.0.5→§6.2.5" reconciliation the branch intended is incomplete in this one prose string.
- LOW: ADR-061:5 anchor-integration note now stale — "§5.4.5 and SCP-OUT-036 originate on feat/outlet-redesign and MUST be integrated onto the implementing branch before the streaming-saga slice" reads as still-pending but they ARE now on-branch (38592c876/04c552b06). Update to past-tense or remove.

**§5.4.5-ANCHORING PRECISION CHECK (user asked):** NONE of SCP-OUT-032..039 cite §5.4.5 in sources[] (PRD reconciled in parallel before §5.4.5 landed). Recommendation — ADD §5.4.5 to sources[] of:
- STRONG (description literally says "per §5.4.5"; §5.4.5 is sole normative def site): SCP-OUT-032 (wire types), 034 (credit/billing lifecycle), 035 (stream_manifest_hash/chunk manifest), 039 (conformance vectors), 037 (FFI verify_chunk_signature/compute_caveats_binding must match §5.4.5 preimages byte-for-byte).
- MODERATE: SCP-OUT-038 (SDK grantCredit/cancel = §5.4.5 CREDIT-V1/CANCEL-V1).
- ACCEPTABLE as-is (§6.2 genuine home): SCP-OUT-033 (executor arch), SCP-OUT-036 (xctx bridge — but fix §6.2.0.5→§6.2.5).
Current §6.2.5/ADR-061 anchoring is a PRECISION DEFECT (not a blocker): validate-prd passes + chain reachable transitively via §6.2.5→§5.4.5, but §6.2.5 is taxonomy/envelope layer, §5.4.5 is the definition site — machine-checkable provenance omits the true normative anchor for stories that literally say "per §5.4.5".
