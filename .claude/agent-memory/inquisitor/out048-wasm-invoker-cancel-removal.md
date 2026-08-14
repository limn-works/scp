---
name: out048-wasm-invoker-cancel-removal
description: SCP-OUT-048 browser-invoker streaming session — Option-A cancel removal, TS-local error-code registration, WeakMap single-consumer guard; verdict + the §5.4.5:515/:547 spec-drift root cause
metadata:
  type: project
---

# SCP-OUT-048 final premise audit @ 4d54f107c (outlet slice 3 last gate)

Verdict: SOUND decisions, 1 CONCERN (artifact-flow), no BLOCKER. Merge-able.

**UPDATE @ 8d5da1912 (fix commit) — CONCERN RESOLVED (SOUND).** The Q1 artifact-flow
concern is closed: §5.4.5 got a new "Co-located vs. remote receiver (cancel locus)" carve-out
that bifurcates the gap MUST into two loci of ONE MUST — co-located receiver signs OutletCancel
(reads StreamSessionHandle::current_next_emission_seq per :547); remote/browser invoker MUST NOT
sign (caller-supplied next_seq = the forgery :547 rejects), instead surfaces StreamGap(6131) +
stops replenishing credit → node reclaims via credit-stall (stream_credit_stall_secs→6133) OR
timeout_ms. :513 summary line de-fanged ("cancels by the locus appropriate … see carve-out").
Verified consistent w/ :547/:530/:485/ADR-057; both credit-stall AND timeout_ms cited so
reclamation is complete (timeout_ms backstops the already-terminated-executor edge). Code
(outlet-stream-session.ts:471-491) now provably matches spec; phantom provenance gone. Story
note = "carve-out landed in this slice (closes #2204)"; #2203 correctly kept as the SEPARATE
future active-cross-context-cancel (Option-B) capability. Code comment line-numbers→section-title
anchors (stale-doc-reference lesson). In-slice fix honors one-way flow + No-deferral. Root
(047's partial :547-without-:515 edit) fully healed. NIT non-blocking: 6131 is overloaded in
§5.4.5 (StreamGap AND StreamCapExhausted) — PRE-EXISTING taxonomy collision, separate ticket.

**Q1 Option-A (remove browser cancel) — DECISION SOUND ON MERIT, artifact-flow CONCERN.**
Premise (remote browser invoker structurally CANNOT sign a valid OutletCancel) HOLDS:
§5.4.5:547 requires cancel `next_seq` = runtime's live emission cursor read from
`StreamSessionHandle::current_next_emission_seq`, "never caller-supplied"; browser is
remote from the executor pump, its receive cursor ≠ emission cursor (in-flight chunks) →
any browser-signed cancel is forgeable or rejected-by-construction. Stub/caller-supplied
next_seq would VIOLATE :547 → worse. Gap→StreamGap(6131)+node credit-stall(30s)/timeout
reclamation is economically COMPLETE for best-effort zero-escrow streams (browser stops
granting on close → pump stalls at zero credit → 6133 credit-stall cancel; paid=saga,
different path). NOT a hidden capability gap.
CONCERN (root cause): §5.4.5:**515** ("Ordering and gaps") STILL literally mandates the
invoker-side SDK drain "cancels via the signed OutletCancel path" on gap — with NO
remote-invoker carve-out — and is load-bearing EXACTLY for lossy/cross-context transport,
i.e. the browser case. 047 updated :547 (cancel-signature, per CRITICAL #3 line 2283
"Spec §5.4.5 cancel-signature block updated") but left the COUPLED :515 obligation
unreconciled. 048 makes the contradiction load-bearing (browser IS the :515 drain) then
DEFERS the spec fix to #2204 (open; title literally "spec: §5.4.5:515 lacks a
remote-receiver carve-out") + #2203 (deferred Option-B cancel). Per CLAUDE.md one-way flow
("code reveals a spec is wrong → fix the spec FIRST"), the small deterministic :515
carve-out (flows from :547) should have landed IN this slice. Shipping code against an
acknowledged-wrong canonical MUST + tracking-issue = the phantom-provenance state the
project forbids. Root decision = 047's partial spec edit (:547 without :515).

**Q2 registering TS-local 7025/7026/7028/7029 in Rust error_codes.rs — SOUND.**
They use the SHARED `SCP-VALID-` namespace (established broad family, e.g. 7010), so the
number-space IS shared and MUST be centrally reserved — central registration is exactly
what prevents the 7027 collision that already bit them (SDK TS literal collided w/ Rust
"Governance action validation error"; check-error-codes.sh Phase-2 doesn't scan TS
literals). Consts honestly doc'd "never minted by an FFI bridge." Single-source-of-truth,
coheres with ADR-057 "share never fork." Partial guard (stops Rust→reuse; a NEW unregistered
TS literal could still collide) but strictly better + correct direction. NOT scope creep.

**Q3 WeakMap single-live-consumer guard — SOUND (conservative fail-loud), root is inherited.**
Root = `ScpBrowserClient.drainEvents(contextId)` is a DESTRUCTIVE whole-per-context drain
(inherited wasm receive path, predates 048, matches native drain_events). Session consumes
whole buffer, keeps own request_id, DROPS rest. WeakMap guards the two-SESSIONS case
fail-loud (7028) — genuine defense (silently starving two streams >> loud throw), NOT
papering. NOT a DOA: when a per-request_id demux lands the guard is REMOVED (hazard gone),
not replaced. Residual = co-tenant NORMAL-traffic loss on a shared client is doc-only (not
mechanically guarded) — but that's a property of the inherited destructive drainEvents, not
048's decision. Per-request_id demux = cleaner root fix but client-layer scope, not the
invoker-session slice. Recommend tracking; not a blocker.

**Q4 coherence with 047 + slice 3 — COHERENT** (one cross-slice spec drift, see Q1).
CRITICAL #3 (047, line 2283) ALREADY declared WASM cancel "N/A per ADR-057" → 048 consistent.
Credit wire uses shared scp_protocol sign_credit_grant → byte-parity w/ node verify by
construction (cryptographer KAT byte-exact). Two-package typescript-wasm split matches
ADR-057 2026-07-15 amendment (#2189). check-sdk-coverage.py change = additive aliases only
(legit coverage expansion, not a weakening). Only drift = §5.4.5:515/:547 inconsistency
spanning 047→048.
