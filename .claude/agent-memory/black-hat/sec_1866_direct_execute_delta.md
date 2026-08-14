---
name: sec-1866-direct-execute-delta
description: Adversarial review of #1866 follow-up delta (remove identity_did from direct-execute, WASM strict proposal_id hex, test seed repair) — no exploitable issue; one test-fidelity/stale-comment note
metadata:
  type: project
---

# #1866 follow-up delta review (c9db30486..3fb78a5da)

Reviewed the direct-execute governance follow-up. **No exploitable vulnerability introduced.**

## What the delta does (all sound)
- Removes `identity_did` param from `governance_execute` on all 4 bridges + 4 SDKs. Safe because the executor param had NO authorization role — direct-execute is unprivileged post-approval finalization (proposal already engine-`Approved` at genuine quorum). Executor + consequence subject now resolved from tracked `proposal.proposer_did` inside the runtime, matching native.
- WASM strict proposal_id hex: `validate_proposal_id_hex` (hex::decode + len==32) at bridge boundary + `parse_proposal_id_bytes` (replaces `unwrap_or_default()` zero-pad) in manager. Routed to SCP-CTX-2040 to match native PyO3/UniFFI/NAPI.

## hex parser behavior (hex 0.4.3, verified empirically)
- Accepts: lower/UPPER/mixed-case 64-char (decodes to same canonical [u8;32] — case cannot forge a different id).
- Rejects: 0x-prefix, leading/trailing whitespace, embedded null, '+', unicode digits, newline, odd-length, non-hex, wrong length. All → CTX_2040.
- Identical to native parse_napi/uniffi/pyo3 proposal_id (all hex::decode + try_into::<[u8;32]>, CTX_2040). No bypass.
- No length pre-cap → huge-input allocates len/2 transiently then rejects; SAME on all 4 bridges (pre-existing, negligible, not a regression).

## Caller cannot influence which action executes
proposal_id is a pure lookup key into engine-validated tracked state. Action is whatever engine retained; require_proposal_approved / engine.get_proposal gate status. Untracked id → WASM CTX_2045 "not found" / native PermissionDenied "not tracked" — both hard-reject (forgery rejected on both bridges).

## Test seed repair = correct, not hiding a behavior change
Old 4-byte ids (deadbeef etc.) would now fail the strict parse at step 4 of propose_governance_action BEFORE reaching the per-action ceiling gate (step 5, inside dispatch). Widening to 64-char hex restores the tests' ability to REACH the ceiling assertion target. Tests retain regression-catching power (remove ceiling gate → is_err() false → fail).

## NOTE (not exploitable, test-fidelity): stale parity-test shape + comment
- `cross_impl_..._direct_executor` (wasm/src/consequence.rs ~L1273) and manager.rs L9341/L9356 still call `execute_governance_action(ctx, caller, resolved_proposer, pid)` — OLD shape (initiator=caller ≠ proposer). Comment at consequence.rs ~L1270 says "auth-subject = caller" — STALE: the shipped bridge (wasm/src/context.rs L758) now passes `(proposer, proposer)`.
- Invisible because these tests configure NO consequence rules, so `dispatch_consequences_for_subject(ctx, initiator_did=caller)` divergence is unobservable; assertions only pin leaf actor_did (executor=proposer, correct) + Merkle root (built from executor+payload, not consequences).
- Production path is correct (proposer for both). Recommend updating test call shape + comment to use proposer for both, to actually lock consequence-subject convergence.

## Out-of-scope residual (task #205, pre-existing, NOT this delta)
- WASM QUORUM path (manager.rs L4521) calls `execute_governance_action(ctx, voter, voter, pid)` → consequence subject = VOTER. Native quorum path consequence subject = `proposal.proposer_did`. Divergence on quorum path only; direct-execute path converges. Tracked as #205.
- Pipeline assertion (pipeline_wiring.rs L900) pins `dispatch_consequences_for_subject` call COUNT (>=2) but not WHICH subject — would not catch the quorum-path divergence.
