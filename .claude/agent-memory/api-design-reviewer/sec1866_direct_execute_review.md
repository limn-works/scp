---
name: sec1866-direct-execute-review
description: SEC-1866 direct-execute governance API review — uniform (handle, proposal_id_hex) across 4 bridges + 4 SDKs; APPROVED
metadata:
  type: project
---

SEC-1866 fix reviewed (branch fix/1866-direct-execute-trust, a632c731a..abf28753b). Verdict: APPROVED (public API).

**What:** direct-execute governance unified to `(handle, proposal_id_hex)` BY ID across all bridges. `identity_did`/`proposal_json`/`action_json` fully removed from execute path (grep-verified zero remaining repo-wide). Executor + consequence subject resolved from tracked proposer inside runtime, never caller DID.

**Bridge export names diverge (pre-existing, alias-registry tracked, NOT a #1866 finding):**
- PyO3: `governance_execute(handle, proposal_id_hex)`
- UniFFI: `governance_execute(handle, proposal_id_hex)`
- NAPI: `contextExecuteGovernanceAction(handle, proposalIdHex)` (internal `_on` helper `context_execute_governance_action_on`)
- WASM: `context_execute_governance(handle, proposal_id_hex)`
- bridge-aliases.json maps all 4 → canonical `governance_execute`. Same divergence exists across whole governance family (propose/approve/etc).

**Arity/order/type genuinely identical** across all 4 bridges + all 4 SDK wrappers (Py governance_execute, TS contextExecuteGovernanceAction, Swift governanceExecute/executeGovernanceAction(proposalIdHex:), Kotlin governanceExecute(proposalIdHex)). All take exactly (handle, proposalIdHex:String)→String.

**CTX_2040 error surface uniform:** malformed proposal_id → CTX-2040 on all 4. PyO3 string-embedded "SCP-CTX-2040", NAPI/UniFFI `code` field, WASM via new `ScpWasmError::proposal_id()` helper (else would've been generic VALID-7000). New shared `validate_proposal_id_hex` in scp-ffi-common returns [u8;32].

**WASM strict hex on all 6 governance entry points** (execute@738, propose@810, approve@889, reject@936, withdraw@983, get_proposal@1020) via validate_proposal_id_hex→CTX_2040. Manager-level `parse_proposal_id_bytes` second strict gate for leaf preimage.

**Key security win:** WASM TS wrapper PREVIOUSLY called `generateProposalIdHex()` + re-proposed action (the quorum bypass). Now delegates by id. `generateProposalIdHex` still legitimately used by contextGovernancePropose only (fresh id for new proposal) — not dead.

**Minor observation (not a finding):** WASM contextGovernancePropose generates proposal id client-side (4-arg wasm call) vs NAPI runtime-derived (2-arg). Pre-existing propose-path divergence, outside #1866 execute scope.

AST enforcement assertion added in pipeline_wiring.rs: positive closed assertion `proposal_id: &ProposalId` must be present, `proposal: &GovernanceProposal` must be absent. Defense-in-depth over type-system (sig already takes id, not proposal).
