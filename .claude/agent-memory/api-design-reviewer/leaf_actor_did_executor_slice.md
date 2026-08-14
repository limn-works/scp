---
name: leaf-actor-did-executor-slice
description: Review of fix/leaf-actor-did-convergence — system_actors consts, executor/initiator threading, WASM dispatch_ceiling_capability exhaustive match
metadata:
  type: project
---

Reviewed `git diff b5b0eb02c..HEAD` on branch fix/leaf-actor-did-convergence (Slices 4-6 of native↔WASM §9.9.3 leaf-byte convergence). Verdict: NEEDS REVISION (2 stale-doc blockers, rest clean/observations).

**What landed:**
- `scp_event_log::system_actors` new module: 4 `pub const &str` sentinels for system-minted leaf `actor_did` (SYSTEM_TIMER_ACTOR="system:timer", SYSTEM_CLOSE_ACTOR="system:close", SYSTEM_SAGA_ACTOR="system:saga", SYSTEM_CONSEQUENCE_ACTOR="system"). Single source of truth; both scp-runtime and scp-ffi-wasm depend on scp-event-log (ADR-034 permitted), so convergence is by-construction.
- Native `execute/dispatch/finalize_governance_action` now thread `executor_did: &DID` (committing member = quorum-crossing voter, or proposer on auto-execute). Previously stamped `proposal.proposer_did` on the GovernanceActionExecuted leaf — diverged from WASM whenever proposer != voter.
- WASM `execute_governance_action` gained a separate `executor_did` param alongside `initiator_did`; `dispatch_ceiling_capability(action) -> Option<&'static str>` is an EXHAUSTIVE match (no wildcard) mirroring native's 5 per-action `ceiling.contains(&Capability::X)` gates.

**Why:** §9.9.3 cross-bridge equivocation detection needs byte-identical Merkle leaves for the same logical event. actor_did is in the serialized Event, so a typo'd sentinel = silent false-positive equivocation.

**How to apply (recurring API patterns confirmed good here):**
- Exhaustive enum match returning Option (no `_ =>`) is the canonical misuse-resistant shape for "which capability/gate does this variant need" — a new variant becomes a compile error forcing explicit decision. This is exactly what CLAUDE.md's "closed by construction" guidance wants. Praise it.
- Cross-impl invariant constants (TTL windows, sentinels) belong on the const with a doc explaining the native lock-step partner, not in PR text.

**Sentinel-naming hazard (note for future reviews):** SYSTEM_CONSEQUENCE_ACTOR="system" breaks the `system:<class>` pattern of its 3 siblings. It's FORCED — wire-stable since PR #1606 + WarningCount trigger depends on it. Cannot rename. Flag any future "normalization" to system:consequence as a wire-break. Recommend the const doc state this explicitly.

**Stale-doc blockers found:** WASM `context_execute_governance` (context.rs ~701-705 doc + ~769-771 inline) still claims per-member execute-time capability check ("RemoveMember requires member:remove", "capability checked inside execute_governance_action") — that check was REMOVED this slice. initiator_did is now only the consequence subject (dispatch_consequences_for_subject). Public bridge doc describing removed auth model.

**Out of scope but live:** task #205 = known native-vs-WASM consequence-SUBJECT divergence (native proposer vs WASM executor). The asymmetric WASM signature (keeps initiator_did, native doesn't) is where that divergence surfaces.

**Tool gotcha confirmed:** Read tool returned a STALE line-numbered snapshot of manager.rs (showed bare "system" in finalize_close at a wrong line); `git show HEAD:` confirmed committed file uses SYSTEM_CLOSE_ACTOR. Always verify worktree findings against `git show HEAD:` before reporting. See backend agent's read-tool-staleness memory.
