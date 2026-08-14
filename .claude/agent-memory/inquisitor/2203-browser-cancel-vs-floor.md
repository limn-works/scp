---
name: 2203-browser-cancel-vs-floor
description: #2203 browser-initiated cross-context OutletCancel interrogated against a universal streaming-pump timeout floor — verdict DON'T-BUILD
metadata:
  type: project
---

# #2203 browser cross-context cancel vs universal timeout floor @d5de8b153

VERDICT: DON'T-BUILD (floor suffices). Interrogated the premise "given a universal
streaming-pump/seal force-settle timeout, browser-initiated xctx cancel (Option-B) is
unnecessary." The strongest pro-build case (signed non-repudiable billing-boundary
attestation + immediacy of stopping billing) COLLAPSES because the #2203 target deployment
is the BROWSER BEST-EFFORT outlet stream, which is ZERO-ESCROW (§5.4.5:576 — best-effort
xctx serves only Query + zero-cost Action; paid xctx MUST use the streaming saga, whose
cancel/coordination is NODE-delegated, not browser). The browser invoker is never billed
per-chunk → no billing dispute to attest, no stall-window cost to wait out. Attestation =
nice-to-have crypto property with NO spec/PRD consumer (grepped: no abort/non-repudiation/
signed-cancel-ack requirement).

DECISIVE COHERENCE POINT: current spec §5.4.5:517-519 (round-8 carve-out) does not merely
omit browser cancel — it FORBIDS it: remote receiver "structurally cannot read the executor's
emission cursor... therefore MUST NOT sign an OutletCancel" and instead surfaces StreamGap +
stops granting credit; node reclaims via credit-stall (30s) or timeout_ms. Spec calls the
co-located-signed-cancel and remote-induced-reclaim "the two loci of the same cancel-on-gap
MUST, not alternatives." So NOT building satisfies the gap MUST (Q4: no spec MUST left
unsatisfied); BUILDING requires AMENDING a round-8 hardening clause + adding a NEW cursor-serve
wire op = permanent DOA-weight reversal. Also SCP-OUT-039 (merged) already DECIDED browser
cancel out-of-scope and its AC asserts `grep outlet_stream_sign_cancel returns nothing`.

Option-B's own flow step 1 = "browser stops granting credit" (the passive floor's mechanism);
fetch+sign+retry is strictly ADDITIVE ceremony over the convergence it depends on. Executor
can't both advance cursor (consumes credit) AND survive credit withdrawal → "stop granting" IS
the abort. Dominance chain: build-nothing ≻ next_seq-free-terminate ≻ Option-B (fetch-then-sign).
next_seq-free dominates Option-B (no fetch/retry/TOCTOU-livelock) but nothing dominates it
(no requirement, floor is spec-sanctioned). "Primitive already exists" (apply_outlet_cancel_
verbatim dead-code-ready @dispatch.rs:1179) = textbook sunk-cost non-argument; dead-code status
is evidence it was built speculatively ahead of a decided consumer.

CAVEAT: the universal timeout floor MUST actually land — real pre-existing bug (adversarial-vet):
credit-stall arms ONLY on parked-chunk path, so executor finishing w/o terminal chunk + no
timeout_ms leaks escrow forever (same root as #2197-R2). Browser cancel is neither necessary nor
SUFFICIENT for that money-safety gap (does nothing for crashed/abandoned browser or silently-
finished executor). Floor is load-bearing; browser cancel is strict luxury on top.
Native co-located next_seq-free terminate ALREADY exists (outlet_stream_terminate FFI →
terminate_with_error @dispatch.rs:1265); browser can't call it (fenced from scp-runtime).
