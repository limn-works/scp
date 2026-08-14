---
name: sec1866-direct-execute-trust
description: Review of #1866 follow-on commits (B drop identity_did from direct-execute, C WASM strict proposal-id hex) — CLEAN
metadata:
  type: project
---

# #1866 direct-execute trust removal + WASM strict hex (c9db30486..b297553c9) — CLEAN, 2026-06-23

Reviewed READ-ONLY on branch fix/1866-direct-execute-trust. Two commits on top of the
already-confirmed core quorum-bypass fix (c9db30486). Verdict: NO findings.

## Commit B — drop identity_did from direct-execute (4 bridges + 4 SDKs)
- PyO3/UniFFI/NAPI: identity_did was ACCEPTED-THEN-DISCARDED (PyO3 validate_did'd then
  `let _ =`; UniFFI/NAPI not even validated, just `let _ =`). It fed NO authz/capability
  check. Removing it loses nothing security-relevant. Native execute handler explicitly has
  "NO executor capability check" — execute is unprivileged finalization of an already-
  engine-Approved (quorum-verified) proposal.
- WASM: identity_did WAS load-bearing but WRONGLY — it was the consequence-evaluation
  SUBJECT (`dispatch_consequences_for_subject(ctx, ctx_id, initiator_did, ...)`), caller-
  controlled, diverging from native. Now both args to WASM `execute_governance_action`
  (`initiator_did`=consequence subject, `executor_did`=leaf actor_did) are set to the
  TRACKED `proposer_did` from `mgr.proposal_proposer_did()`.
- NATIVE GROUND TRUTH (governance_helpers.rs finalize_governance_action ~L4364): dispatches
  consequences for `proposal.proposer_did` and `proposal.action.target_did()` (if distinct).
  Leaf actor_did = `executor_did.unwrap_or(&proposal.proposer_did)`; direct path passes
  None → proposer. WASM now byte-matches: subject=proposer, target dispatched, leaf=proposer.
  This is the fix for task #205 (consequence-subject convergence). No misattribution path left.
- Enforcement: scp-testing pipeline_wiring.rs added STATIC assertion
  `!entry_sig.contains("identity_did")` on WASM context_execute_governance signature —
  positive structural lock against reintroducing caller trust.
- Grepped all bindings+crates: zero residual identity_did callers on execute path (only the
  assertion text itself).

## Commit C — WASM strict proposal_id hex validation
- New `validate_proposal_id_hex` (scp-ffi-common/validate.rs): hex::decode + len==32 else
  ValidationError. Replaces WASM's old `hex::decode().unwrap_or_default()` + truncate/zero-pad
  (silently widened short/non-hex id into well-formed-looking all-zero/right-padded [u8;32] →
  cross-platform proposal_id divergence → broke Merkle equivocation detection).
- Added at WASM boundary on execute/propose/approve/reject/withdraw/get_proposal AND server-
  side via manager `parse_proposal_id_bytes` (defense in depth). 6 unit tests + 2 manager tests.
- DoS: NO new surface. `hex::decode` allocates len/2 transiently then len-check rejects —
  IDENTICAL to native parse_proposal_id (PyO3 L1400 / NAPI / UniFFI all `hex::decode` with no
  pre-cap). Symmetric, MB-scale transient alloc immediately freed, no amplification.
- Error-leak: hex::FromHexError Display = offending char/position only (no full-input echo);
  len branch = byte count only. No internal/PII leak.
- propose direction: native PyO3 propose does NOT take caller proposal_id (runtime GENERATES
  it, always 32 bytes). WASM (ADR-034 reimpl) DOES take caller id (pre-existing shape diff).
  Strict validation converges WASM to native's always-32-byte invariant; cannot diverge in
  accept direction (native never emits short id). No regression.

## Convergence verdict
native↔WASM still reject identical forgeries: untracked id → rejected (engine get_proposal /
pending|resolved lookup both bridges); unapproved → status!=Approved both; action substitution
structurally impossible (no action param); malformed id → rejected both (strict hex). Executor
+ consequence subject both = tracked proposer on both bridges. No authz/provenance/replay
regression introduced by B or C.
