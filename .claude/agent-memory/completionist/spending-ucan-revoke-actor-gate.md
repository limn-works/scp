---
name: spending-ucan-revoke-actor-gate
description: Review of §19.5 spending-UCAN revocation wired into actor Class-S paid-action gate across 3 FFI bridges; WASM correctly N/A; spec self-contradiction + compromise-recovery unwired path
metadata:
  type: project
---

Review @e019b6b26 (worktree agent-a32cd09f9850dfdd7, off origin/main). Fix routes spending-UCAN
revocations from FFI `ucan_revoke` into the actor Class-S `revoked_spending_ucan_cids` gate.

**Verdict: INCOMPLETE(narrow) — code wiring COMPLETE, one spec self-divergence blocks.**

WIRED COMPLETE across all 3 bridges that HAVE the gate: PyO3 (src/ucan.rs:767 block_on),
NAPI (napi/src/ucan.rs:715 .await), UniFFI (uniffi/src/bridge.rs:14907 .await). Each: after
the general `revoke_ucan`→RevocationList write, `if is_spending_ucan(&parsed)` →
`sup.revoke_spending_ucan(ctx, compute_revocation_cid(token), revoker_did)`. New
`EconomyCommand::RevokeSpendingUcan` (commands.rs), handler (handlers/economy.rs:97) inserts via
fail-closed `commit_class_s_keep`+`rest_mut().governance.revoked_spending_ucan_cids.insert` then
appends `SpendingUcanRevoked` leaf. Supervisor no-actor direct-dispatch fails CLOSED (Err, not
silent Ok). CID consistency verified: gate computes `compute_revocation_cid(&token.encoded)` where
parse_ucan sets encoded=raw input → matches FFI `compute_revocation_cid(token)`. Single writer
(economy.rs:138) feeds BOTH readers: paid-action gate (economy_logic.rs:164
validate_spending_ucan_signed step F) + cross-context saga §7 re-validation (saga.rs:1164).

**WASM: correctly N/A.** No `crates/scp-ffi/wasm/` — the WASM bridge is `crates/scp-client-wasm`
(participant-message-path ONLY, ADR-057 fence; lib.rs:45 "Economy, governance ... are node-side
by construction"). Zero ucan_revoke, zero spending, zero paid-action gate. No unwired path there.

**Matrix: no new entry needed (correct).** Public op is UCAN-domain `revoke` (matrix line 1374,
all 4 SDKs true); enhancement is bridge-internal. `revoke_spending_ucan` is an internal Supervisor
method (NOT exported as its own FFI op). SDK ucan_revoke wrappers (py/ts/swift/kt) pass through
unchanged — no SDK change required. Correct.

**FINDINGS:**
- (LOW, BLOCKING per role) Spec self-contradiction: §19.6.1 line 494 says leaf "records the
  revocation (token CID + reason)" but same-section line 492 says "carries no free-text reason" and
  code `SpendingUcanRevokedPayload` has ONLY `token_cid` (no reason). Leftover from reconcile commit
  dae02cfb4 which fixed the table+payload but missed line 494. One-phrase fix (delete "+ reason").
- (MEDIUM OBS, pre-existing, NOT this change) Compromise-recovery `revoke_ucans`
  (identity/recovery.rs:964) revokes via a BLANKET RevocationList scope-marker
  (`recovery:{ctx}:scopes=...:before={ts}`) distributed by notification — does NOT write the actor
  Class-S gate. Per §19.5 the paid-action gate consults ONLY the Class-S set by exact per-token CID,
  so a spending UCAN revoked via compromise recovery does NOT reach the gate by CID. Whether it's a
  real re-admission depends on whether key rotation invalidates the spending UCAN's signature at the
  gate (24h expiry window). Separate mechanism; flagged for judgment, not a blocker on this change.
- (LOW test) No direct positional-MessagePack round-trip test for SpendingUcanRevokedPayload (every
  sibling payload has one, e.g. access_revoked_round_trip). Exercised indirectly by supervisor test.
- (LOW test) `revoke_spending_ucan_populates_gate_and_rejects_subsequent_spend` executes the
  §19.6.1 leaf append but does NOT assert the leaf exists/its token_cid in the log.

Pipeline_wiring lives at crates/scp-testing/tests/integration/pipeline_wiring.rs (NOT scp-runtime);
3 new fn_body string-scan tests pin is_spending_ucan+revoke_spending_ucan in each bridge body.
