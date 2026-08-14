---
name: sec1866-direct-execute-quorum-bypass
description: SCP-1866 governance direct-execute quorum-bypass fix audit (a632c731a..3834898f0) — CLEAN, no findings
metadata:
  type: project
---

# SCP-1866 Direct-Execute Quorum-Bypass Fix — CLEAN (2026-06-23)

Audited `git diff a632c731a..3834898f0` (5 commits, branch fix/1866-direct-execute-trust). **Zero findings.** Quorum bypass CLOSED, no new authz/secrets/replay/provenance hole.

**Why:** Old governance direct-execute accepted a caller-supplied proposal/action/status (+ NAPI even generated a RANDOM proposal_id via OsRng.fill_bytes AND took action_json) — a caller could fabricate an Approved proposal or substitute an action. Fix moves the trust boundary to the engine.

**How to apply (the fix shape, for future governance reviews):**
- Native `execute_governance_action` (governance_helpers.rs:4519) now takes `proposal_id: &ProposalId` + `executor_did: Option<&DID>`. Resolves authoritative proposal via `state.governance.engine.get_proposal(proposal_id)` — action/status/context_id/proposer ALL from engine, never caller. `executor_did.unwrap_or(&proposal.proposer_did)` = direct path attributes to TRACKED proposer.
- Ordering: check_commit_fault → resolve proposal → resolve executor → status==Approved (engine's own) → context_id match → replay `executed_proposals.contains_key` → mark → dispatch → rollback-on-err → finalize. Replay keyed on engine-resolved id.
- `ExecuteGovernanceActionPayload` (actor/commands.rs) carries ONLY `proposal_id` (no proposal field). Actor handler passes `None` for executor.
- WASM manager.rs:3075 `execute_governance_action` dropped `action` param; action from tracked `pending_proposals`/`resolved_proposals`. Bridge context.rs:712 takes ONLY `(handle, proposal_id_hex)`, passes `proposal_proposer_did(...)` for BOTH initiator+executor.
- Consequence-subject parity: native dispatches for `proposal.proposer_did` (gh:4414); WASM for `initiator_did` (mgr:3242) = now the resolved proposer. Task #205 resolved by THIS diff.

**Strict hex validator (`validate_proposal_id_hex`, common/validate.rs:562):** single `hex::decode` + `try_into::<[u8;32]>` (one step does length+array). Cleanup commit 3834898f0 changed return `()` → `[u8;32]` (single-decode); NO error arm lost (try_into subsumes length check). Returns CTX-2040. Rejects odd/non-hex/short/long/empty. No leak (msg = decode err or byte count only), no DoS. All 6 WASM gov entrypoints call it at boundary via ScpWasmError::proposal_id → CTX-2040.

**4-bridge uniformity:** PyO3 parse_proposal_id (scp-ffi/src/context.rs:1400), NAPI parse_napi_proposal_id (napi:3100), UniFFI parse_uniffi_proposal_id (uniffi/bridge.rs:5431), WASM parse_proposal_id_bytes — all single-decode+try_into→CTX-2040, functionally identical. SDK wrappers (Py governance_execute, Swift executeGovernanceAction(proposalIdHex:), TS contextExecuteGovernanceAction, Kotlin) all dropped identity_did.

**Provenance:** old WASM unwrap_or_default()+zero-pad (executed-leaf + propose paths) replaced by strict parse — removes platform-divergent proposal_id on GovernanceActionExecuted leaf. native↔WASM reject identical forgeries (untracked→CTX-2041/PermissionDenied, malformed→CTX-2040, unapproved→PERM_3000).

**Test seam SAFE:** `TestInsertMember` is `#[cfg(feature="testing")]`-gated at command/dispatch/mod.rs-panic-arm/supervisor-method — unreachable from any FFI bridge.

**Enforcement:** pipeline_wiring.rs +114/-0 (added only); sdk-capability-matrix.json = documenting `notes` field, no downgrade. Nothing weakened.

**Observation (pre-existing, NOT this diff):** the 4 native bridge parsers each reimplement validate_proposal_id_hex logic. Sound + identical, no risk, but converging them would remove 4 copies. Minor hardening only.

NOTE: action_json still legitimately on the PROPOSE path (wasm context.rs:795, napi:3124, scp-ffi/src:3298) — that's correct (propose stores the tracked action, validated via validate_governance_action_strings). Execute path has NO action param anywhere.
