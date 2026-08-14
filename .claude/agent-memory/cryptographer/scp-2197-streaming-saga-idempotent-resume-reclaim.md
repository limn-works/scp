---
name: scp-2197-streaming-saga-idempotent-resume-reclaim
description: SPEC-DRAFT review #2197 — streaming-saga idempotent resume + universal seal reclamation; crypto/anti-replay/money verdict + Q-D resolution
metadata:
  type: project
---

# #2197 streaming-saga idempotent open + universal seal reclamation (SPEC DRAFTS, no code yet)

Reviewed drafts (summary at scratchpad/2197-spec-drafts.md) vs origin/main d5de8b153 (worktree scp-wt-audit).
Foundation is SPEC-ONLY: §6.2.4 xctx outlet saga + its B-side nonce-dedup are NOT implemented in runtime
(grep: no CrossContextOutletInvoke/nonce-dedup in crates/scp-runtime; prompt's "class_s.rs nonce-dedup" pointer
is aspirational). Streaming-saga sites still hardcode stream_manifest_hash:[0u8;32] (ADR-061 wiring targets).
So both the B-dedup and the new A-side resume index land together at spec level — coherent to co-specify.

## VERDICT: SOUND to land, conditional on the fixes below. No unconditional blocker.

Two anti-replay controls at two loci (draft framing CORRECT, not conflated):
- B-side (target, Prepare-B) nonce-dedup: 16B nonce, 10k oldest-first, TTL=2×skew. Catches replayed envelope
  under fresh SagaId. §6.2.4 Freshness/anti-replay + Window-relationship + Cache-eviction clauses.
- A-side (initiator, before Prepare-A) idempotent resume index: key=(caller_ctx,caller_did,target_ctx,
  outlet_reg,nonce)→SagaId. Same-principal dup RESUMES (budget-neutral, no 2nd reserve).

## Q-D (CRUX) — post-abort resume vs retained B-dedup: draft "wait out TTL / rerun fresh nonce" is SAFE but SUBOPTIMAL.
- DO NOT PURGE B's dedup on abort. Purge reopens replay (in future cross-node untrusted-link model, §6.2.4
  Forward-obligation) AND needs a NEW authenticated cross-context purge message that is itself a replay surface
  (forged purge → evict live nonce → replay). Purge = converts liveness nuisance into a safety hole. Reject.
- Better fix (recommend, not strict blocker since fallback is sound): RETAIN the A-side index entry as a
  terminal TOMBSTONE (carrying the outcome) through grace ≥ B-dedup TTL on ALL terminals incl Aborted (draft
  only grants grace to Committed). Same-nonce retry hits tombstone → short-circuit returns recorded terminal
  WITHOUT minting a fresh saga → no B-dedup wall, no self-DoS-till-TTL, AND no burned non-refundable §6.2.0.2
  budget unit (the mint-fresh fallback burns budget per rejected retry — anti-griefing double-counts a
  legit retry). ⇒ Q-G wording MUST change: evict-in-critical-section = mark terminal tombstone, not delete.

## Q1(a) caller-auth: SOUND IFF resume keys on the CHANNEL/BRIDGE-authenticated local principal, never a
caller-supplied caller_did param. Same class as §5.4.5 CRITICAL#1 / §6.2.4 Caller-authentication. If a bridge
lets in-process code assert an arbitrary caller_did to the resume lookup, a CO-TENANT hijacks a victim's saga
(reattach = victim's stream chunks confidentiality breach + victim receipt). Relay/target cannot reach the
initiator-side index. LOAD-BEARING CONDITION — drafts must state it for the resume path.

## Q2 money: holds across all 3 crash windows PROVIDED (i) discard recovery paths (Pre-Prepare, PreparingA
w/o durable deduction) ALSO evict/tombstone the index (else orphan pointer→absent saga); (ii) resume
lookup-or-create is ATOMIC under A's actor lock (else concurrent same-nonce double-mint → double-reserve);
(iii) §6.2.4 new "Durably-staged caller deduction" clause honored (it is). Index-before-escrow ordering
correctly forecloses reserve-without-index. Mid-seal handled by ADR-061 seal-prefix-and-close (billed≤delivered).

## Q3 reclamation: SOUND. billed≤delivered≤produced (cancel-ack ceiling primitive = reclaim cutoff). Valid
attestation (seals real per-chunk-signed prefix). No double-settle: routes thru EXISTING single settlement
block + `settled` flag under state lock (dispatch.rs ~634) → first-fire wins, late real terminal / concurrent
resume are no-ops; SagaId-idempotent at Committed. max-duration cap (min(timeout_ms,900), pump-owned server
timer) closes detached-UniFFI-open escrow-stranding hole — STRENGTHENS money conservation. REQUIRED: reclaim
must DURABLY record the seal cutoff (last-sealed-seq / billed_count) BEFORE signing receipt — it determines
stream_manifest_hash, so replay must reseal the IDENTICAL prefix (same by-SagaId replay-determinism discipline
as recorded_timestamp_ms/nonce). REQUIRED: reclaimed event must populate cancel_ack_seq (or reclamation
StreamTerminalStatus variant carries the ceiling) so §5.4.5:570 chunks_billed_ref log-insert check passes.
seal-idle(30) vs credit-stall(30) both→force-terminal; settled-flag makes race safe but codes differ — set
precedence or make seal-idle strictly > credit-stall (legibility nit).

## Q4 index recovery race: don't assume cross-key atomicity of index-evict + journal-terminal (ADR-049 journal
on injected Storage, no multi-key txn guaranteed). Make resume TOLERANT of stale/dangling index (→terminal/
absent saga ⇒ read tombstone outcome or treat fresh). Resume MUST dispatch on pointed-to saga's FSM state:
live→reattach; Aborting/terminal→return terminal, NEVER reattach-to-corpse or re-drive Prepare.

## Q5 weakening: NONE if the above hold. B-dedup unchanged (no purge). Caller-auth preserved IFF authenticated
keying. Settlement invariants (billed≤delivered, chunks_billed_ref) preserved IFF cutoff durable + cancel_ack_seq
populated. Resume must be budget-neutral on hit (draft says so — required for anti-griefing consistency).

## SPEC-TEXT VERIFICATION PASS (commit 9067782d3, worktree scp-wt-2197-spec) — 2026-08-02
Core money-safety model is SOUND and all six refinements R1-R6 are NORMATIVELY CAPTURED (not just claimed):
R1 06:269+272 (channel-auth principal, never caller-supplied caller_did, ties to §5.4.5 CRITICAL#1); R2 05:575
(durable cutoff BEFORE signing); R3 05:581 (cancel_ack_seq=cutoff); R4 06:281-283 (3-way FSM dispatch
live/terminal/absent); R5 06:272-275 (atomic lookup-or-create + mint, one crit section, before escrow); R6
06:270+286 (never purge B; tombstone A on ALL terminals incl Aborted; grace≥max(B dedup TTL, seal max-dur)).
Focus-1 at-most-once settle: SOUND — invariant = cutoff-durable-before-sign (R2) ⇒ byte-identical replayed
close + escrow settle by-SagaId-idempotent (§17.16.4) ⇒ crash-mid-force-settle re-runs seal-prefix-and-close
(ADR-061:48) once. Resume never settles ⇒ resume-vs-reclaim money-safe (money-safety independent of reattach,
05:127). Focus-3 idle>credit-stall SUFFICIENT: the two seams are disjoint-by-CAUSE (credit-stall needs credit=0
which needs executor emitting ⇒ forward-progress up to credit-0 ⇒ idle can't head-start; caller-wedge/silent-
executor ⇒ backpressure/silence ⇒ credit never 0 ⇒ only idle arms). Focus-4 no signing-order hazard (frontier
incrementally persisted, billed=chunks_billed_ref over sealed frontier).
FINDINGS filed (NOT in earlier design pass):
- HIGH: DEFAULT CONFIG SELF-INVALID. credit-stall default=30 (05:490, 09:2044) AND seal-idle default=30
  (05:571, 09:2050) → idle==credit-stall violates the MUST-reject "strictly greater" rule (05:571) ⇒ every
  conformant impl must REJECT default ContextParams. Bump seal-idle default (e.g. 45s) above credit-stall.
- MED: UNIT MISMATCH. `min(timeout_ms, stream_max_duration_secs)` mixes ms and seconds (05:386, 05:572,
  09:2051). Must be min(timeout_ms, stream_max_duration_secs*1000) in ms.
- MED: tombstone GC unspecified — "delete only after grace" (06:286) but index has "no independent
  reconciliation pass" and §17.16.4 sweep touches only NON-terminal; resolved-terminal tombstones have no
  reaper ⇒ unbounded durable growth. Needs a durable TTL.
- MED: retryable-abort stuck under same nonce — Aborted tombstone short-circuits same-nonce retry to cached
  abort for ≥grace(≥900s); "retryable" abort is un-retryable w/o a FRESH nonce. Spec must state client
  contract: retry ⇒ new nonce.
## RE-CONFIRM PASS (commit 37b0cfd1b, rebased on origin/main 093c5afca) — 2026-08-02: ALL 7 FINDINGS RESOLVED, no new hazard.
HIGH default: seal-idle default now 45 > credit-stall 30 (05:494, 09:2050/2036, ADR-061 addendum); +deployer-must-raise note. FIXED.
MED unit: min(timeout_ms, stream_max_duration_secs*1000) both-in-ms at all 3 sites (05:83-84, 05:95, 09:2051); no other ms/s confusion. FIXED.
MED tombstone GC: new clause 06:145 = bounded durable-store TTL (delete once now>terminal_at+grace), EXPLICITLY not §17.16.4 sweep;
  bounds accumulation; grace≥max(B dedup TTL, seal-max-dur) intact ⇒ tombstone always outlives B dedup ⇒ no replay-window reopen. FIXED.
MED fresh-nonce: new clause 06:147 = true retry (incl retryable abort) MUST mint fresh nonce; same-nonce=idempotent cached outcome;
  SDK retry helpers MUST rotate nonce; resume alone reuses nonce. Consistent w/ R5/R6, no contradiction, fresh-nonce=new-budget (correct). FIXED.
LOW tie-break: 6136 wins idle-vs-maxdur tie (05:576, ADR-061); deterministic + money-neutral. FIXED.
LOW seal-phase arm: §17.16.4 now has explicit "Seal-phase-in-progress recovery is distinct — seal-prefix-and-close" arm (06:157). FIXED.
LOW skew: cross-node §9.14 margin folded into grace bound as deferred fwd-obligation (06:143). FIXED. LOW cancel_ack_seq note (05:585). FIXED.
BONUS: dispatch clause split into 4 explicit cases open-in-progress/seal-running/terminal/absent (06:138-141) — closes my earlier live⇒reattach-conflation LOW.
Rebase integrity: 17 registry rows == "seventeen" (grep -c confirmed); #2209's 6132(stream-cap-exhausted) kept, 6134/6136 re-applied, no collision;
  gap example repointed 6134→6137 (only 6134 refs left are allocated-code cites in tie-break + cancel_ack_seq). CLEAN.
ADR-049 §3a(a) got honest correction: envelope-enumeration NOT exhaustive; reclamation deadlines complete the always-bounded model. Additive, no regression.
VERDICT: zero blocking findings — cryptographically sound. Invariant = cutoff-durable-before-sign(R2) + escrow settle by-SagaId-idempotent(§17.16.4,
  now w/ explicit seal-phase arm) ⇒ at-most-once over durable prefix; B-dedup-untouched + A-tombstone-grace≥max(...) ⇒ replay closed, no self-deadlock.
Two OPTIONAL non-blocking polish notes (neither NEW, neither a hazard): (a) 6133-vs-6136 (credit-stall vs max-duration) coincident-tick still
  undisambiguated — tie-break 05:576 names only idle-vs-maxdur; money-identical, measure-zero; cleanest fix = "max-duration wins ANY coincident tie".
  (b) same-context-scope clause "force-settles identically" (05:108) slightly overstates for best-effort streams (no receipt/dual-log/Committed);
  shared part is deadline+escrow/credit-settle+permit-release, saga-receipt steps are saga-only. Money-safer broadening, not a hazard.
## FINAL PASS (commit a585ab9f3) — both optional polish items landed, ZERO findings, cryptographically sound.
Tie-break generalized (05:576 + ADR-061 mirror): max-duration 6136 wins ANY coincident tie (idle 6134 OR credit-stall 6133);
  honest "true tie is measure-zero" note; money-neutral (same durable prefix, changes only recorded code). CORRECT.
Same-context scope (05:588): "share the reclamation, not the transactional envelope" — same-ctx outlet stream gets idle/max-dur
  deadlines + escrow/credit settle(reserved−billed) + pump-permit/stream-table release; explicitly NO receipt/dual-log/Committed
  (cross-ctx-saga-only). Accurate, not overstated. Amend = ONLY these 2 hunks in 05 + 1-line ADR mirror; core clauses grep-confirmed
  intact (R2 cutoff-before-sign, §17.16.4 seal-phase arm, no-purge-B, grace≥max, fresh-nonce). At-most-once + R6 replay-closure UNCHANGED.
## Q5/Q3 REWORK PASS (commit 4d4143176) — replaced joint-txn w/ happens-before + index-keyed resume FSM. ONE HIGH FINDING.
Good: joint-txn assumption ("same critical section marks journal terminal") was IMPLEMENTABLE-FALSE (prod SagaJournal has no cross-store txn + COMPACTS resolved saga to zero entries) — correctly replaced by happens-before (tombstone durable BEFORE mark_resolved/compact) + settle_at_close SagaId-idempotent. At-most-once settlement over durable prefix HOLDS across terminal crash-windows (a-d): idempotent settle makes re-driven seal-prefix-and-close a no-op; R2 cutoff-durable-before-sign untouched ⇒ signing-order intact ⇒ tombstone carries byte-identical receipt. Q3 tombstone payload (status + cutoff seq/billed_count + receipt/manifest_hash or durable handle) SUFFICIENT + no receipt-binding leak/weaken (returns verbatim, same principal per R1, R2 reproducible). Q4 clamp effective_idle=max(cfg, credit_stall+1s) money-NEUTRAL (changes only WHICH code 6133<6134 + bounded reclaim latency, never amount; aligned w/ closed-by-construction tenet). R6 replay closure HOLDS: index key is per-principal (caller_ctx+caller_did+...) so different-principal replay MISSES index→fresh→Prepare-B→B per-nonce dedup Rejects; B dedup untouched; grace≥max intact; new Nonce triple-purpose invariant (06:84) hardens "resume MUST short-circuit at A before B re-sees nonce".
HIGH (06:277 vs 279/281/289): NEW open-ordering line 277 = index-write(Live) → escrow reserve+CallerReservationRecord → journal PreparingB append (journal LAST, after reserve). This makes 3 things FALSE:
  (1) line 281 "journal can never be absent while index reads Live" (the stated basis for FSM soundness) — FALSE: index is written BEFORE first journal append, so crash in that gap = index=Live + journal-absent, reachable.
  (2) line 289 FSM "index Live + journal ABSENT ⇒ impossible by construction ⇒ fail-closed SagaNeedsRepair" — the state is NOT impossible; it's the normal open-crash-before-first-journal-append. Contradicts line 278 ("re-drive cleanly").
  (3) line 279 "§17.16.4 crash recovery reverses the reserve" for the reserve-taken-pre-PreparingB window — FALSE: §17.16.4 (line 327) is JOURNAL-driven (re-drives unresolved JOURNALS); a reserve persisted before any journal entry has NO journal for the sweep to load ⇒ reserve reachable ONLY via the index ⇒ if impl trusts line 279 (journal sweep) the reserve ORPHANS = the exact #2197 defect. Also contradicts pre-existing line 329 which implies a PreparingA journal covers any live reserve.
  Money-safe ONLY IF impl ignores 279/289 and does index-driven reclaim; fail-closed(289) is safe-but-heavy IF built (but framed as can't-happen). FIX: either append a PreparingA/started journal marker BEFORE the escrow reserve (restore 329 invariant → live reserve always journal-covered, index=Live+journal-absent reduces to no-money pre-reserve window) OR make reserve-reclaim explicitly index-driven and rewrite 289 to treat index=Live+journal-absent-with-reserve as index-driven reclaim not impossible. Reconcile 277/279/281/289/329.
  NOT a double-settle/double-reserve/re-execute (reserve is SagaId-idempotent; outlet invoked only at Commit-B) — it is an ORPHAN-RESERVE (money-leak) + false-soundness-premise + dispatch contradiction.
## ORPHAN-FIX PASS (commit dabe12877, option-a) — HIGH RESOLVED, ZERO findings, cryptographically sound.
Open reordered to (i) index{Live} → (ii) journal PreparingA → (iii) escrow reserve+CallerReservationRecord → (iv) journal PreparingB.
PreparingA now STRICTLY PRECEDES the reserve ⇒ every live CallerReservationRecord is covered by a non-terminal journal entry
(PreparingA/PreparingB) that the journal-driven §17.16.4 sweep loads + reverses (via Durably-staged-caller-deduction, 06:337) ⇒
NO orphaned reserve in any open-crash window. HIGH RESOLVED. False invariant "journal never absent while index=Live" (06:281 prev)
RETRACTED + replaced with correct one: "a LIVE RESERVE is never journal-absent" (reserve always follows PreparingA). index=Live+journal-absent
is now correctly the BENIGN pre-PreparingA reserveless window ⇒ re-drive the open (NOT SagaNeedsRepair); FSM (06:289) + crash-window
narrative (06:278) now AGREE. SagaNeedsRepair correctly re-scoped to true contradiction (Terminal index over a live ADVANCING
non-terminal journal — unreachable under terminal-ordering happens-before). journal-present⇒index-was-written (index (i) strictly first);
reserve-taken⟺journal-covered (⟺ NOT journal-less); so journal-less⟺no-reserve (money-safe to drop).
NEW reaper (journal-less Live entries) SOUND: deletes a Live entry only if (a) no journal + no live in-flight saga AND (b) age>TTL ⇒
protects in-flight opens (tiny (i)→(ii) window) by BOTH live-saga check + age-TTL; drops only reserveless crashed opens (no money);
post-reap same-nonce ⇒ fresh mint = FIRST execution (outlet invoked only at Commit-B, never reached) ⇒ no double-execute/reserve; B never
saw the nonce (pre-Prepare-B) ⇒ no B-dedup entry ⇒ no spurious reject + no replay-window (R6 unaffected). Reaper TTL needs NO grace
coupling (no B-dedup entry exists for a pre-Prepare-A crash). Reapers are pure GC (never settle) ⇒ no double-settle. Terminal-side
(tombstone-before-mark_resolved), force-settle signing-order/R2, Q5.3 tombstone payload, Q3 clamp, R6/grace, nonce triple-purpose ALL
UNTOUCHED by this commit (only open-side ordering + FSM prose + reaper added). §17.16.4-driven PreparingA-crash→Terminal(Aborted) composes
w/ terminal-ordering idempotently (reserve-reversal SagaId-idempotent, same as settle). Invariant restated: "no live reserve without a
covering journal entry" + "no reserve without a durable index key" + "tombstone durable before journal compacts" + "settle/reverse
SagaId-idempotent" ⇒ at-most-once settlement, no orphan, R6 replay closed.
## LOW-CLARITY PASS (commit a76fa1c35, 06 only) — money-neutral, ZERO findings, sound.
Fix1 SagaNeedsRepair carve-out: index=Terminal + non-terminal-journal AT REST reclassified from corruption to the BENIGN
tombstone-before-mark_resolved transient (crash between force-settle-terminal-side step1 tombstone-write and step2 mark_resolved).
Recovery = idempotently re-run mark_resolved/compaction. Money-neutral: settlement (force-settle step4) already completed BEFORE
tombstone write (tombstone carries the signed receipt+cutoff), so mark_resolved is pure journal GC (no settle); even if recovery instead
re-runs full seal-prefix-and-close, settle_at_close is SagaId-idempotent → no-op + R2 byte-identical receipt. SOUND IMPROVEMENT: old
discriminator "still-advancing journal" is UNDECIDABLE at crash-restart REST → unimplementable; new discriminator = DURABLY-DECIDABLE
contradiction (tombstone cutoff/billed_count vs sealed sequence, or settlement values disagree) is decidable + correctly partitions
benign-transient vs real corruption. A WRONG tombstone still caught (durable-contradiction ⇒ SagaNeedsRepair). Money-safety rests on
settle-idempotency NOT mark_resolved-idempotency (mark_resolved is money-free GC; compact-to-zero naturally idempotent).
Fix2 pre-PreparingA §17.16.4 recovery arm: index=Live+no-journal+no-reserve ⇒ re-drive-on-resume OR reap; makes arms EXHAUSTIVE over
open ordering (every durable reserve journal-covered+swept; every reserveless index-only remnant re-driven-or-reaped). No settle/reserve/
execute (no reserve exists; outlet invoked only at Commit-B). Fix3 reaper read-only journal-coverage/existence check EXPLICITLY permitted
(bare existence read, not FSM load/advance) — no reconciliation-pass violation. No TOCTOU: a reserve is only taken by a LIVE in-flight saga,
which the reaper's live-saga check + age-TTL both exclude from reaping (read-timing irrelevant). Reapers = pure GC, never settle.
UNTOUCHED (grep=1 each): R2 signing-order, terminal-ordering tombstone-before-mark_resolved, Q5.3 tombstone payload, Q3 clamp, grace≥max,
nonce triple-purpose, open-ordering PreparingA-before-reserve, FSM Live+journal-absent benign re-drive. Four happens-before orderings intact.
## ADR-061 STALENESS FIXED (commit 42c100f27, ADR-only 2-hunk delta) — ZERO FINDINGS, cryptographically sound end-to-end.
R4 bullet (ADR-061:99) rewritten to index-keyed dispatch (index-absent⇒fresh only-mint; Live+journal-live⇒re-drive/reattach;
Live+journal-absent⇒benign pre-PreparingA re-drive; Terminal⇒recorded outcome; "Journal absence alone is NEVER fresh") + cross-ref
title fixed to "§6.2.4 Resume dispatches on the INDEX state" (matches spec 06:289 heading). SagaNeedsRepair example (ADR-061:110)
rewritten to durably-decidable contradictions (cutoff/billed_count vs sealed sequence) + explicitly demotes "Terminal-over-non-terminal-
journal at rest" to benign mark_resolved transient (mirrors spec 06:297-301). ADR no longer contradicts spec NOR itself; all R1-R6
cross-refs resolve. Rest of cumulative change byte-identical to prior fully-cleared pass ⇒ all normative invariants still sound. CLEAN.

## FINAL DOUBLE-ZERO PASS (commit a76fa1c35, full origin/main...HEAD read) — normative spec SOUND end-to-end, but ONE LOW artifact-consistency finding in ADR-061 (now FIXED by 42c100f27, above).
Normative §6.2.4/§5.4.5/§9.18.B verified internally self-consistent + correct on ALL invariants (at-most-once settle, 4 happens-before
orderings, orphan closure, R2 signing-order, Q5.3 payload, Q3 clamp, R6/grace, nonce triple-purpose). BUT ADR-061 addendum summary is
STALE vs the refined index-keyed §6.2.4 (last commit a76fa1c35 touched ONLY 06; ADR-061 last changed in dabe12877, not re-synced):
  (a) ADR-061:99 R4 bullet says "dispatches on the pointed-to saga's FSM state (... absent → fresh)" — CONTRADICTS spec 06:289
      "keyed on the INDEX, NOT on journal/FSM presence; journal absence alone is NEVER fresh" (the exact #2197 double-reserve/re-invoke
      defect). "absent → fresh" read as FSM/journal-absent = the forbidden bug. Also cross-refs a RENAMED §6.2.4 subsection title
      ("Resume dispatches on the pointed-to saga's FSM state" → now "...on the INDEX state") = broken intra-doc link.
  (b) ADR-061:110 "SagaNeedsRepair ... (e.g. Terminal index over a live advancing journal)" — spec 06:297-301 DEMOTES exactly this to a
      BENIGN at-rest transient (recover via idempotent re-run mark_resolved) + says "still-advancing" is NOT decidable at rest ⇒ MUST NOT
      be the discriminator; repair re-scoped to durably-decidable contradiction (tombstone cutoff/billed_count vs sealed sequence).
  ADR-061:99 and ADR-061:110 are ALSO internally inconsistent (99=FSM-state/absent-fresh; 110=index-state/journal-absence-never-fresh).
  Severity LOW (normative spec authoritative + correct; these are stale ADR summary/illustrative text) but REAL: artifact-flow invariant
  (ADRs govern specs) + R4's "absent→fresh" phrases the precise defect the spec forbids + broken cross-ref. FIX: resync ADR-061:99 R4 to
  index-keyed dispatch ("index absent→fresh; Terminal→outcome; Live→re-drive/reattach; journal-absence-never-fresh") + fix cross-ref title;
  resync ADR-061:110 SagaNeedsRepair example to durably-decidable-contradiction. Then re-run the clean pass.
--- earlier design-pass LOWs (now resolved above) ---
- LOW: 6134-vs-6136 terminal-code nondeterminism unconstrained (only 6133<6134 ordered); measure-zero, money
  identical. LOW: "live⇒reattach" (06:281) conflates open-in-progress (PreparingA/B, drive-forward) with
  seal-phase-running (reattach stream); PreparingA-without-reserve re-drive (06:278) is a 4th unenumerated
  case. LOW: §17.16.4 enumerated arms don't name seal-phase-in-progress (lives in ADR-061:48). LOW: cross-node
  grace needs §9.14 skew margin (fwd-obligation). LOW: cancel_ack_seq overloaded as billing-ceiling absent a
  real cancel — consumers must key off stream_terminal_status.
