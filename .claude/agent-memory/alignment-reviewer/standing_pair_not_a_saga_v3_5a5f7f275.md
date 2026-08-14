---
name: standing-pair-not-a-saga-v3-5a5f7f275
description: ALIGNED review of standing-pair NOT-a-saga reframe v3 @ 5a5f7f275 (branch spec/standing-pair-not-a-saga-v2, merge-base f37372b25); docs-only, 1 LOW finding
metadata:
  type: project
---

# Standing-Pair NOT-a-Saga reframe @ `5a5f7f275` — ALIGNED, 1 LOW

Branch `spec/standing-pair-not-a-saga-v2`, HEAD `5a5f7f275` ("converge §5.15.8 collision prose to closed invariants; honest residual disclosure; sync sdk-common standing-context contract"). Merge-base `f37372b25`. DOCS-ONLY, 5 files +116/-74: `05-contexts.md` (§5.15.8 rename "Standing-Pair Creation Saga" → "Standing-Pair Creation (Single-Context Async)"; §5.15.4, §5.12.2), ADR-049 §3/§3a + §3a registry note + Decision-3 correction marker, DEFERRED-commit-11 (historical-correction/superseded markers on Gap-1/Gap-5/exit-criteria), `09-security-model.md` §9.4.3, `sdk-common.md` (standing_context semantics + reserved-band relabel).

**WHAT IT DOES:** reclassifies standing-pair creation from a two-phase cross-context saga → ordinary single-context async MLS creation (1 MLS group, 2 members, symmetric `derived_context_id`; sync = MLS epoch-Commits + bootstrapping Welcome + event-log RFC-6962 layer, NOT a saga journal). Asserts genuine cross-context sagas are EXACTLY TWO: §6.2.4 (cross-context tool invocation) + §5.14.13 (broadcast-hosting handshake). FFI saga surface = two `start_*_saga` exports; standing-pair reached via `standing_context` get-or-create (NO `start_*_saga` export). Code deletion (`SagaInput::StandingPairCreate`/`StandingPairCreatePrepared`/`creation_receipt.rs`) deferred to a separate code-correctness PR.

**VERDICT: ALIGNED, ship after 1 LOW fix (or accept as nit).** Correct, internally + corpus-consistent, provenance-honest, artifact-flow-compliant, roadmap-aware.

**THE 1 LOW (weak anchor, NOT a correctness defect):** §5.15.8 (05-contexts.md:1830 + cross-ref list :1881) NEWLY introduced a "§3 (canonical DID string form)" anchor (merge-base old line 1822 cited only "canonical DID string form as produced by DID resolution" + §9.6.1, NO §3). But §3 (03-identity.md) has NO section stating a canonical-DID-string-form / did:web-normalization rule — its did:web entry (03-identity.md:749) is security-mitigations-only; z-base-32 form actually lives in §9.6.1; the did:web normalization rule (host lowercased, `:`→`%3A`) lives ONLY in §5.14.13 (05-contexts.md:1670) + inline in §5.15.8. Body is self-sufficient (inlines rule + cites §9.6.1). FIX: drop "§3" qualifier OR re-point to §5.14.13 (same paragraph already says "same canonical-DID-as-key rule §5.14.13 applies to snapshot keys" — re-point is the stronger fix).

**VERIFIED CLEAN:**
- No leftover `start_standing_*_saga` in `.docs/`. All `StandingPairCreate`/`CreationReceipt`/`InitiateStandingPairCreate` confined to superseded/historical blocks.
- No surviving "three sagas" enumeration outside correction markers (ADR-049:96 IS the correction; security-model:271 "all three tiers"=§9.16 block enforcement, unrelated). CORPUS-WIDE grep: no doc anywhere calls standing-pair a saga.
- No raw `#NNNN` PR refs introduced into prose (the `#1` tokens = ADR-049 §Follow-up item numbers, not PRs — OK).
- ALL cross-refs resolve + say what's claimed: ADR-049 §10 (auto-revive, exists), §Follow-ups #1 (spawn-from-Welcome decrypt-not-send contract verbatim), §9.6.1 (z-base-32), §9.7.1 (KeyPackage sig MUST verify vs VM in DID doc — backs bound-creator rule), §9.3 "(not self-created)", §9.5.1, §9.16.3, §3.7.1 (block list, best-effort propagation, severance via sender-key rotation), §5.12.1/.2/.3.3/.4/.5/.6, §5.14.13, §6.2.4, §17, §17.16, §9.4.3.
- §17.16:970 durable-caller-reservation crash-recovery now references ONLY §6.2.4 tool saga (no stranded standing-pair-saga machinery). §9.4.3 propagated cleanly to "Both defined sagas".
- POSITIVE: ADR-049 §3a now correctly says SCP-SAGA IS registered at 13000-13999 (sdk-common canonical-prefix table line 45 + partitioned codes 13072+; check-error-codes.sh lines 71-73 validate band) — improvement over old text that wrongly said "not yet registered". Reserved-band example relabeled "standing-pair handshake" → "cross-context saga families".

**OBS (non-blocking):** §Follow-up/§Follow-ups label drift (singular vs plural) across §5.15.8 + sdk-common; ADR heading is "## Follow-ups". Cosmetic.

LESSON: when a reframe ADDS a cross-ref anchor, diff the merge-base to confirm whether the anchor is new — then verify the cited SECTION actually states the cited rule, not just that the chapter exists. Here "§3" resolves to a chapter but no §3.x section asserts the canonical-DID-string-form rule (it's really §9.6.1 + §5.14.13).
