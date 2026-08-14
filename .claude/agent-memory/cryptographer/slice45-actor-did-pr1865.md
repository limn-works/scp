---
name: slice45-actor-did-pr1865
description: PR #1865 (slice45-actor-did) crypto/convergence review — system-leaf actor_did alignment + GovernanceActionExecuted executor stamp; SOUND, no blocking findings
metadata:
  type: project
---

PR #1865 (branch slice45-actor-did, HEAD d7216140b) — two commits reviewed under crypto/convergence lens. SOUND, no NEW blocking findings.

**Why:** native↔WASM Merkle-leaf byte-identity (§9.9.3 cross-bridge equivocation detection). Excluded by reviewer scope: #205 consequence-subject divergence, #206 per-action-leaf event-count divergence.

**How to apply:** treat these two leaf-actor conventions as load-bearing for cross-bridge KAT.

COMMIT 1 (428e130c5) — system-leaf actor_did alignment:
- WASM ContextExpired "" → "system:timer" (manager.rs:5137); WASM ContextClosed "system" → "system:close" (manager.rs:6054); native saga CrossContextDivergenceMarker "" → "system:saga" (saga.rs:2110, native-only leaf).
- Native producers ALREADY stamped system:timer (ttl.rs:876) / system:close (ttl.rs:679); WASM aligned UP to native reference.
- Leaf = SHA-256(0x00 ‖ rmp_serde(Event{event_type,actor_did,timestamp,seq=0,empty payload,GENESIS prev_hash,empty sig})). Byte-identical given identical timestamp.
- ContextExpired timestamp IS convergent: both stamp creation+ttl (convergent_ttl_deadline_secs; WASM manager.rs ~5128 mirrors native, no creation==0 guard, fail-safe shortening). SOUND.
- ContextClosed timestamp NOT proven convergent here: native finalize_close takes committer-convergent timestamp_secs PARAM (ttl.rs:651); WASM finalize_close uses crate::time::now_secs() (manager.rs:6058). PRE-EXISTING (comment "Convergent close instant" predates commit; only actor_did changed). WASM test pins parity by reading back landed ts — harness convenience, not cross-bridge proof of the ts source. NOT a new finding from this PR but the ContextClosed ts-source convergence is unverified.
- Tests: native ttl.rs CapturingEventLog asserts real producers; WASM cross_impl rebuilds native-reference single-leaf root via shared scp_event_log primitives + non-vacuity controls (pre-fix sentinel diverges). Strong.

COMMIT 2 (d7216140b) — GovernanceActionExecuted stamps EXECUTOR not proposer:
- Native: threaded executor_did:&DID through execute_/finalize_/dispatch_governance_action. finalize stamps it on leaf actor_did, event executor_did, ContextEvent.executor_did (governance_helpers.rs:4269/4292/4307). dispatch + sibling dispatch_context_governance_action stamp it on ALL per-action leaves (actor=executor_did, governance_helpers.rs:3976, callsite 4204). ts = proposal.created_at (convergent).
- 3 native callers, mutually exclusive, all correct: auto-execute(3121)→proposer (proposer==committer); quorum vote_on_proposal_inner(3437)→voter_did (the committer); direct ExecuteGovernanceAction handler(governance.rs:674)→proposer (no quorum voter, proposer==committer convention). NO missed caller.
- WASM: approve_governance_proposal quorum-execute passes voter_did (was proposer); REORDERED pending→resolved BEFORE execute so execute_governance_action resolves convergent leaf ts from proposal.created_at via pending-or-resolved lookup (manager.rs:2898). Previously removed-then-executed → tracked-guard rejected → leaf never minted. Fix correct + necessary. WASM stamps initiator_did(=voter) on leaf+executor_did, shared encode_payload, proposal_created_at ts (manager.rs:2985). Byte-identical preimage to native given same executor.

CONVERGENCE REALITY (the crux):
- GovernanceActionExecuted is COMMITTER-APPENDED-ONLY. Receive-side cross-member leaf replication is DORMANT (messaging_helpers.rs run_buffered_post_delivery: event_name=None for ALL received traffic; documented as the ADR-051 forward step). So honest members do NOT all stamp the same executor in their OWN logs — the quorum-crosser differs by local vote-arrival order. The PR's convergence claim is precisely cross-BRIDGE byte-identity of a SINGLE member's commit, NOT cross-member identical logs. Commit msg is honest about this scope.
- Within one member: executed_proposals guard (governance_helpers.rs:4510 / WASM:2901) prevents double-append per proposal. Leaf minted exactly once, by the local committer = the threaded executor. Deterministic given that member's observed commit.
- So "deterministic from commit order, same on all honest members" is TRUE only under the future ADR-051 replication; today it's per-committer. The fix is the correct precondition for that replication (executor is the spec-correct convergent author identity).

VERDICT: both commits SOUND for stated cross-bridge scope. No new blocking crypto findings. The two residual non-blocking observations (ContextClosed ts-source convergence unverified; cross-member executor non-convergence pending dormant replication) are pre-existing / out of this PR's scope.
