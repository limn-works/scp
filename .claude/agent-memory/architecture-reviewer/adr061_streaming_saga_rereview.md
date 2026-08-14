---
name: adr061-streaming-saga-rereview
description: ADR-061 streaming-saga RE-REVIEW @ scp-wt-streaming fa8e5eb79 — all 5 prior NEEDS-REVISION findings resolved, but a NEW HIGH inconsistency (§5.4.5 opening vs ADR Supersedes)
metadata:
  type: project
---

RE-REVIEW of [[adr061-streaming-saga-synthesis]] (prior verdict NEEDS REVISION) @ worktree scp-wt-streaming HEAD fa8e5eb79, branch feat/outlet-streaming-runtime. Files: `.docs/adrs/ADR-061-outlet-invocation-modes.md` (rewritten 2026-07-13 four-lens revision), `.docs/specs/06-cross-context-communication.md` §6.2.4/§6.2.5, `.docs/specs/05-contexts.md` §5.4.5 (newly ported from feat/outlet-redesign), `.docs/specs/09-security-model.md` §9.18.2.

**All 5 prior findings RESOLVED:**
1. Receipt DOA — new `SCP-XCTX-STREAM-RECEIPT-V1:` separator carries 32-byte root directly, reproduced from SagaId-keyed durable capture; registered §9.18.2 line 1636; unary `SCP-XCTX-RECEIPT-V1` (output_hash, carry-bytes-recompute) untouched. Rejected-alt #5 documents why reuse fails. RESOLVED.
2. Commit-transition vs stream-close split — ADR §"seal phase" (lines 34-44): Commit-transition triggers pump (prompt, no receipt), streaming pump captures O(log n) frontier durably, seal/close finalizes root+receipt+escrow+dual-log+Committed. §6.2.5 line 366 restates. Consistent w/ §6.2.4 FSM + §17.16.4. RESOLVED.
3. Seal-prefix-and-close crash rule — ADR line 44 normative; reuses CancelAckTracker billing-ceiling (accrue only ≤ cancel-ack-seq, §5.4.5 line 528/552). RESOLVED.
4. ADR-049 §5 provenance — mis-citation removed; Supersedes paragraph (line 7) explains it was OwnedIdentityDid. RESOLVED.
5. O(n) manifest RAM trap — incremental-frontier requirement stated (ADR line 39 "pump MUST use the incremental frontier"; batch compute_chunk_manifest_root demoted to "convenience for bounded inputs"). RESOLVED.

**NEW issue — HIGH (blocks clean RESOLVED verdict):** `.docs/specs/05-contexts.md` §5.4.5 line 347 opening — "Outlet invocations are streams by construction. A non-streaming invocation is the degenerate single-chunk case; there is no separate OutletResponse wire type." — is VERBATIM the "every outlet call is a stream" unification that ADR-061 line 7 Supersedes explicitly REJECTS ("unary and streaming genuinely distinct modes w/ different committed artifacts output_hash vs stream_manifest_hash; a unary call is NOT modeled as a 1-chunk stream"). Introduced by porting §5.4.5 (commits 38592c876/04c552b06) without reconciling its stale opening. Also INTERNALLY inconsistent: §5.4.5 line 566 itself references "the unary saga's ... receipt which commits output_hash" (distinct-modes framing). Fix is localized: reword line 347 so unary is not "the degenerate single-chunk case," or scope it to wire-type only + reconciling note. If everything is a stream, unary's output_hash (central to §6.2.4) has no origin.

**NEW-issue checks that PASSED:**
- Envelope-by-guarantee reframe vs §3b: SOUND + honest. ADR lines 16-18 explicitly state best-effort⟺same-context / transactional⟺cross-context is a "current realization fact, not a definitional identity"; same-context transactional would be a "single-actor journal" NOT a saga (so no §3b violation — §3b forbids same-context SAGA, not same-context journal). Forward-compatible, not DOA.
- §3a phase-timeout reconciliation: HOLDS as target design. Stream runs in NEW seal phase bounded by credit/escrow envelope (effective_max_billable_chunks + timeout_ms + stall timers), NOT the 30s per-phase timeout; Commit-transition returns promptly; Committed reached async at close; §17.16.4 seal-prefix recovery specified. Slice-3 wiring must register seal phase timeout-exempt. No enforcement-gate conflict (check-saga-gating-granularity.sh is about gating granularity not timeout).
- §5.4.5 seal-phase/receipt model (line 566): ALIGNS precisely with ADR (durable-capture reproduction, root-binding not inline-recompute).

**LOW nit:** §9.18.2 line 1636 `SCP-XCTX-STREAM-RECEIPT-V1:` cites §6.2.4 as spec-ref, but that separator is defined in §6.2.5/§5.4.5/ADR-061 — §6.2.4 is the unary saga. (Unary RECEIPT + DIVERGENCE rows correctly cite §6.2.4.)

Verdict: NOT clean-RESOLVED — one NEW HIGH open (§5.4.5 line 347). Everything else resolved/sound.
