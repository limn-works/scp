---
name: adr049-2148-birth-into-actor
description: #2148 MlsCryptoProvider struct dissolution review — dissolution done, but orphaned fail-injection seam + lost Class-S rotation test coverage + stale ADR present-tense refs
metadata:
  type: project
---

# #2148 birth-into-actor (PR #2186) completionist review

Reviewed the ADR-049 §6/§15 MlsCryptoProvider per-context-STATE dissolution.
Verdict: INCOMPLETE (core dissolution correct; residue + artifact gaps).

**What was fully correct (do not re-flag):** the three shared maps
(`contexts`/`taken_context_ids`/`broadcast_keys`) and 12 methods deleted with
ZERO live refs; owned-return birth constructors (`create_mls_group_with_context`,
`install_joined_group`, `build_restored_owned`) wired into real create
(`builder.rs`), welcome/join (`supervisor.rs`), restore (`lifecycle_helpers.rs`);
golden-oracle `handle_sender_key_request` retired from provider, re-homed on
actor `ContextCryptoState` with golden test; `pipeline_wiring.rs::provider_steady_state_crypto_methods_are_deleted`
is REAL (matches `fn NAME(` against `PROVIDER_SRC`, closed positive list) and
additive; `check-deleted-primitives.sh` +6 bans, 0 removals; TOCTOU #2167 closed
(supervisor first-writer-wins guard `supervisor.rs::spawn_actor_with_state`);
CloseOrchestrator fieldless, uniffi updated, pyo3/napi route close through actor
(no asymmetry — they never constructed it).

**The findings (lessons for where the gap hid):**
- **Orphaned test-only seam after its consumer is deleted.** `force_rotation_failure`
  field + `arm_rotation_failure_once` pub fn are WRITTEN/armed but NEVER READ —
  their only reader was provider `rotate_sender_key`, deleted by PR-7. Dead code
  compiles clean because a *written field* + a *pub fn* dodge dead_code warnings.
  Pre-existed on origin/main (PR-7), but the dissolution PR is the right place to
  delete it. **Grep pattern:** when a method is deleted, grep for `#[cfg(test)]`
  fields/methods that only that method consumed — they become write-only orphans.
- **Deleting a consumer strands its fault-injection TEST coverage.** The §15(c)
  Class-S rotation fail-closed branch is now UNTESTED; a standing "COVERAGE FLAG"
  comment admits the fault seam wasn't re-homed onto the actor rotate. A
  security-critical (Class-S) fail-closed path with no test = HIGH.
- **ADR temporal residue = phantom provenance.** #2148 added supersession notes to
  §6/§15 but left §9 (line 252) and §15 (361/365/369) describing the DELETED
  primitives (`take_crypto_state`/`taken_context_ids`/`provider.contexts`) in
  present tense as the live mechanism. Commit msg claimed "§6/§15/§9/Consequences"
  but diff only touched §6 + 2 §15 paragraphs. Verify commit-message scope claims
  against the actual diff.
- **Broad denylist smell:** `check-deleted-primitives.sh` bans `\.with_context\(`
  crate-wide — would false-positive on future anyhow `.with_context()`. Sound now
  (0 matches), name-based not definition-based.
