---
name: direct-execute-governance-byid
description: Review of direct-execute governance unification to (handle, identity_did, proposal_id_hex) across 4 bridges + 4 SDKs (commit c9db30486)
metadata:
  type: project
---

Direct-execute governance API redesigned (commit c9db30486, branch fix/1866-direct-execute-trust): `execute_governance_action` dropped caller-supplied `proposal_json` (action+status) for a by-id shape `(handle, identity_did, proposal_id_hex)`. Runtime resolves the authoritative proposal from the actor's own quorum-validated engine; action substitution is structurally impossible (no action param). Strong misuse-resistance win.

**Why:** closes a quorum-bypass / action-substitution vector that existed on every FFI bridge.

**How to apply (review findings to re-check on follow-ups):**
- HIGH: `identity_did` is SEMANTICALLY DIVERGENT. PyO3/NAPI/UniFFI DISCARD it (`let _ = &identity_did;`; payload carries only context_id+proposal_id). WASM USES it as the consequence-dispatch subject (`initiator_did` → `dispatch_consequences_for_subject`, manager.rs:3213). Same signature, different contract = violates agent-first "identical shape across bindings." Tracked internally as "native proposer vs WASM executor consequence-subject" (task #205).
- MEDIUM: `identity_did` validated only on PyO3 (context.rs:3041) + WASM (context.rs:735); NOT on NAPI/UniFFI. UniFFI doc comment FALSELY claims "validated."
- OBS: NAPI/TS within-bridge ordering clash — execute is DID-first `(handle, identity_did, proposal_id_hex)` but approve/reject/withdraw/propose are DID-last `(handle, proposal_id_hex, voter_did)`. PyO3 is DID-first everywhere (consistent). Swift/Kotlin immune (named args).
- OBS: NAPI name `contextExecuteGovernanceAction` breaks the `contextGovernance<Verb>` family (propose/approve/getProposal). Pre-existing.
- proposal_id_hex as String (not typed ProposalId) is the RIGHT call across FFI — siblings all use hex string; typed wrapper serializes to string anyway. Python .pyi types as `Any` (weak discoverability, pre-existing convention).
- Capability matrix `execute_action` notes (sdk-capability-matrix.json:785) are accurate re by-id shape + all 4 bridge fn names.

Related: [[batch4_1543_review]]
