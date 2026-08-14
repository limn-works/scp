---
name: adr049-2j-fix-pass-fb59eb3f7
description: ADR-049 Phase 2J spawn-from-Welcome fix pass re-review @ fb59eb3f7 — Fix 11 artifact update accurate; ONE new doc-drift (provider.rs:784 "now-deleted")
metadata:
  type: project
---

# ADR-049 Phase 2J spawn-from-Welcome fix pass @ `fb59eb3f7` (2026-07-02) — ALIGNED w/ 1 doc-drift finding

Branch `feat/adr049-2j-spawn-from-welcome`. Diff `origin/main...HEAD` (12 files +1652/-167). Re-review of the fix pass that followed the prior 2J core-slice alignment review (see [[adr049_2j_spawn_from_welcome_core]] @ cf080adeb).

**Fix 11 artifact update = ACCURATE, non-over-claiming.** ADR-049 §9 (~line 176) + §Follow-ups Deferred Work #1 + plan `generic-moseying-lightning.md` Phase 2J block (line 17-23, 2026-07-02 UPDATE) all now record the core-slice-landed / #127-FFI split. Repeatedly qualified ("no non-test caller", "production-unreachable meanwhile, so NO live gap", "deliberate slice boundary, not a broken invariant"). Verified: `spawn_actor_from_welcome` is `pub(in crate::context)` (supervisor.rs:10334) with NO non-test caller (grep confirms only tests + doc-refs). Legacy `MlsCryptoProvider::join_from_welcome` still present + `#[cfg(any(test, feature="testing"))]`-gated (provider.rs:2586), NOT deleted — matches ADR claim deletion→#127. Note ADR §9 calls it "the production entrypoint" (lightly loose since unreachable) but immediately qualifies — acceptable.

**Design after reorder = SOUND (correct Decision-1/8/9).** Entrypoint order: reversible prechecks [A registry-collision `lookup`, B require real §9.10.4 pseudonym (reject None, no [0u8;32] sentinel), C `check_version_compatibility`+`validate_governance_model`] → build_actor_deps → ConfirmConsume (irreversible KP burn) → read `joined_group.epoch()` → `install_joined_group` (Vacant-guarded) → build_welcome_joiner_state (rollback-on-err) → `persist_state_fail_closed` (rollback-on-err) → 4b crypto-durability recheck `welcome_snapshot_crypto_is_durable` (rollback-on-err) → `spawn_actor_with_state` (rollback-on-err) → finalize. Persist-before-ack (persist step4 BEFORE handle-register step5); fully-keyed-or-nothing (every post-consume err rolls back `destroy_mls_group` + `delete_context`). Rollback = bootstrap-style. Correct.

**Epoch seeding = ALIGNED w/ absolute-epoch semantics.** `mls_epoch = joined_group.epoch()` = OpenMLS `g.epoch().as_u64()` (scp-mls group.rs:193-196), absolute, ≥1 for joiner (creator@0 + add-commit → 1). Consistent triad: create=`mls_epoch:0` (lifecycle_helpers.rs:1468), restore=persisted-absolute (2137/2645), join=joined_epoch. `0` placeholder would've stamped wrong epoch into checkpoints (§9.9.3). bug-catcher F1 fix genuine.

**`fresh_governance_state` extraction = ALIGNED, no divergence.** state.rs:1787 `fresh_governance_state(engine, params, last_known_members, context_id, clock)` — identical field set for BOTH create (lifecycle_helpers.rs now delegates) + Welcome-join (build_welcome_joiner_state). Threshold signers/value derived from `params.governance` in the shared helper (empty/0 for non-Threshold). DRY, cannot drift. Import/restore deliberately NOT routed through it. Correct.

## FINDING (NEEDS DISCUSSION, doc-only, minor) — NEW drift introduced by the fix
**provider.rs:784** — the new `install_joined_group` doc (authored by THIS diff) says "exactly the shape the **(test/feature-gated, now-deleted)** single-slot join path produced." The single-slot path (`join_from_welcome` + `pending_joins`) is NOT deleted — still present provider.rs:2495-2609, gated. "now-deleted" directly contradicts (a) code 1700 lines below, (b) the ADR §9 the SAME commit wrote (deletion→#127), (c) plan ("now-dead ... provider path" = #127). This is the exact over-claim class Fix 11 existed to eliminate. FIX: "now-dead"/"pending #127 deletion", not "now-deleted". Governing artifact: ADR-049 §9 + Follow-ups #1.

## Secondary (minor, pre-existing now-stale)
**provider.rs:2506-2508** — "It is retained only until the join-from-welcome spawn entrypoint lands; it will be removed then." Entrypoint HAS now landed (core slice); path NOT removed (→#127). Fix pass edited this file (+install_joined_group) + updated ADR to #127-framing but left this in-code note on the old "when entrypoint lands" framing. Should read "until the #127 FFI follow-on lands." Same class as [[adr049_2j_spawn_from_welcome_core]]'s doc-drift note (now resolved in ADR/plan, but leaked one word into provider.rs).
