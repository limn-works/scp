---
name: project-2069-f2-recovery-ucan-failclosed
description: Branch fix/2069-f2-revoke-ucans-fail-closed removes the §9.12 step-3 UCAN-revocation nullifier but does NOT close #2069 — no blanket revocation predicate, no two-gate regression test; #2069 must stay OPEN
metadata:
  type: project
---

`fix/2069-f2-revoke-ucans-fail-closed` (recovered 2026-08-08 from a session that
died on a usage limit before pushing; 12 commits, based on `origin/main` @
`d1ebc5ab9` — needed NO rebase, it was 0 behind / 12 ahead).

**It removes the nullifier. It does NOT close #2069.** 1 of 6 issue requirements met.

* MET: the synthetic marker `format!("recovery:{}:scopes={}:before={}", ...)`
  (was `recovery.rs:1075` on main) is gone; `ProductionRecoveryBackend::revoke_ucans`
  now returns `Err(RecoveryStepErrorCode::UcanRevocationUnwired)` unconditionally.
* NOT MET: neither gate changed — `scp-protocol/src/crypto/ucan/revoke.rs:431` and
  `scp-runtime/src/context/economy_logic.rs:132` are byte-identical to main, still
  exact-CID. No `{key_scope, revoked_before_ts}` store (issue option A), no CID
  enumeration (option B), and no regression test presenting a token at BOTH gates
  after recovery. The §9.12 spec edits are about step *scope*, not a revocation
  predicate.

**Why the branch is still worth landing:** it deletes a false guarantee on a
security-critical control. Attacker capability is unchanged before vs after; only
operator visibility improves. Keep #2069 OPEN — no closing keyword in any commit.

**Two facts that recontextualise the whole area (verify before acting):**
1. §9.12 recovery has NO production entry point. `ProductionRecoveryBackend::new`
   is constructed only under `#[cfg(test)]`; `CompromiseRecoveryOrchestrator` has
   zero non-test callers. All three bridges reject with `SCP-IDENT-1022`
   ("recovery backend not configured") before reaching it — pre-existing on main.
   So this branch changes NO observable SDK behaviour.
2. `governance.revoked_spending_ucan_cids` has zero PRODUCTION writes (only two
   `#[cfg(test)]` inserts at `supervisor.rs:23085`/`:24395`), so the runtime-side
   gate is permanently empty by construction — even a fully wired `revoke_ucans`
   would enforce nothing there until #2072 adds a receive-side merge.

**Why:** Alec asked for stranded work to be recovered and adjudicated honestly,
explicitly preferring "the branch is a half-fix" over a quiet merge.
**How to apply:** when anyone proposes closing #2069, or builds on §9.12 recovery,
check these two facts first. The remaining work is the whole issue: a blanket
scope+timestamp predicate honoured by both gates, plus the #2072 write path.

See [[feedback-check-scripts-need-cargo-target-dir]] and
[[feedback-worktree-absolute-path]].
