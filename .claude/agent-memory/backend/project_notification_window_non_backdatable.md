---
name: project-notification-window-non-backdatable
description: deferred econ-policy/ceiling apply gate must use max(convergent effective_at, local observed_at+PERIOD); effective_at IS a leaf base so can't just revert to local now
metadata:
  type: project
---

HIGH security fix on eventlog-unification-phase2 branch (commit 4cad781e5, base 16a2cd42b). Commit bf9266777 changed deferred-governance-change `effective_at` from `now()+PERIOD` (observing member's local clock) to `proposal.created_at+PERIOD`. `proposal.created_at` is proposer-chosen and backdatable → collapses the mandatory notification window to zero on first apply tick.

**Investigation result (the non-obvious part):** `effective_at` DOES feed a durable Merkle leaf — `apply_pending_economic_policy_change` appends `EconomicPolicyApplied` with `pending.effective_at` as the leaf *timestamp*, and `apply_pending_ceiling_modification` appends `CeilingModified` likewise (governance_helpers.rs ~456 / ~502). So a naive revert to local `now()` would re-break cross-member leaf convergence (the whole point of bf9266777). The window-gate base and the leaf base are the SAME field but need DIFFERENT properties.

**Fix:** keep `effective_at` convergent (leaf base) BUT add `observed_at: u64` (local clock at commit-processing time, non-backdatable) to `PendingEconomicPolicyChange`/`PendingCeilingModification` (state.rs ~236/~278). `is_effective` now = `current >= max(effective_at, observed_at + PERIOD)`. Set `observed_at = deps.clock.now_secs()` in `execute_set_economic_policy`/`execute_modify_ceiling`. Only 2 non-test construction sites exist.

**Freeze (item 3, governance_helpers.rs ~593):** left as-is with a `// SECURITY:` residual comment. It's a liveness safety valve (auto-resolves a 2-proposal deadlock EARLIER when backdated — benign, never grants capability), requires two colluding signed proposals, and widening the `state.governance.freeze` (ProposalId,ProposalId,u64) tuple would ripple into 5+ consumers for no authz gain.

**preserve_order guard:** the consequence/token_revoked KATs (wasm_conformance.rs ~2354/~2397) depend on `serde_json::json!` emitting SORTED keys = `serde_json/preserve_order` OFF. Added a dedicated `serde_json_emits_sorted_keys_preserve_order_must_stay_off` test that inserts keys reverse-sorted and asserts sorted output — fails loud + self-explaining if a dep flips the feature.

Pattern: when a value is BOTH a convergent leaf base AND an authorization-window gate, split the concern — leaf keeps the convergent (possibly attacker-influenced-but-tamper-evident) base, gate adds a local non-backdatable floor via `max(...)`.
