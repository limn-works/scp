---
name: slice45-executor-did-threading
description: API review of executor_did threading through execute/dispatch/finalize_governance_action + native↔WASM system-leaf sentinel alignment (branch fix/leaf-actor-did-convergence)
metadata:
  type: project
---

Reviewed `git diff origin/main...HEAD` on branch fix/leaf-actor-did-convergence (HEAD d7216140b). APPROVED.

**What changed:** Threaded a new `executor_did: &DID` param through the three internal runtime fns `execute_governance_action` / `dispatch_governance_action` / `finalize_governance_action` (governance_helpers.rs). Aligned native↔WASM system-leaf actor_did sentinels.

**Why it's well-designed:**
- All 3 native call sites migrated consistently (governance_helpers.rs propose-auto-execute passes `proposer_did`; vote_on_proposal_inner passes `voter_did`; actor handler direct-execute passes `proposal.proposer_did`). No unmigrated callers remain.
- Param semantics ("committing member crossing quorum; proposer on auto-execute") documented at all 3 signatures citing ADR-031 §8/§7.3.1/ADR-051 §6.
- Critically: doc comment on finalize explicitly flags that `executor_did` is DISTINCT from `proposal.proposer_did`, which intentionally REMAINS the consequence SUBJECT + participation-record key (governance_helpers.rs consequence-eval block). This prevents a future caller from "fixing" the proposer references there.

**One API-design observation (non-blocking, noted to user):** convergence-critical actor_did sentinels (`"system:timer"`, `"system:close"`, `"system:saga"`, `"system"`) are duplicated as BARE STRING LITERALS across scp-runtime (ttl.rs:679/876, saga.rs:2110, governance_helpers.rs:334) and WASM (manager.rs:5153/6069/696). Their whole purpose is byte-identical cross-impl convergence, so literal duplication is latent drift risk. Precedent exists: `CONSEQUENCE_ACTOR_DID="system"` const in governance_logic.rs (but it's pub(super), unusable from WASM which can't dep on scp-core per ADR-034). Parity tests (consequence.rs cross_impl_*, ttl.rs CapturingEventLog) currently catch drift, which is why this is observation not blocker. Cross-bridge sentinel constants would need to live in scp-event-log (the shared crate both depend on).

**Cross-bridge param-shape asymmetry (pre-existing, not widened):** WASM execute_governance_action takes executor as positional `initiator_did: &str`; native takes typed `&DID`. This change does not widen it. Broader governance-execute FFI shape divergence (PyO3/UniFFI proposal_json vs NAPI action_json+proposer vs WASM initiator+proposal_id+action) tracked separately (tasks #205/#206).
