---
name: pr116-ffi-saga-export-1f84dd9a9
description: #116/PR-6b FFI export of §6.2.4 xctx-tool saga (3 native bridges + SCP-SAGA taxonomy + enforcement) @ 1f84dd9a9 — ALIGNED, 1 MINOR
metadata:
  type: project
---

# #116 / PR-6b — FFI saga export (§6.2.4 / ADR-049 §3a) @ `1f84dd9a9` (branch feat/116-ffi-saga-export, base origin/main) — ALIGNED, 1 MINOR

**Why:** discharges the ADR-049 §3a:94 *forward obligation* ("channel-authenticated caller_did binds with the wiring PR, not before"). Makes the §106 durable saga journal observably LIVE (per ADR-049:65). PR-6b slice of #105/PR-6 plan ([[project_pr105_xctx_saga_ffi]]); SDK wrappers = PR-6c (#117).

**How to apply:** This is the canonical example of a forward-obligation-discharging wiring PR done RIGHT. Verdict was ALIGNED, ship. Reuse the verification recipe below for the next saga/forward-obligation wiring slice.

## What the diff is (6 commits, +4232/-7)
3 native bridge exports of `tool_invoke_cross_context_saga` (PyO3 reference `tool_invoke_cross_context_saga`, NAPI `toolInvokeCrossContextSaga` js_name, UniFFI `tool_invoke_cross_context_saga`) + SCP-SAGA terminal mapping + enforcement (pipeline_wiring 41→44, ffi_conformance parity 105→106, bridge-aliases, capability-matrix). NO spec/ADR/sdk-common edits (artifact-flow clean — codes pre-registered upstream).

## ADR §3a / §6.2.4 mandates — ALL satisfied
- **Block-until-terminal**: producer `Supervisor::start_cross_context_tool_invocation_saga` (supervisor.rs:5478) is the pre-existing FSM (start_saga/run_saga); bridge `tokio_rt.block_on(...)` returns inline. ≤~95s.
- **SagaId minted-not-input**: bridge signature has NO saga_id param; reads `output.saga_id.0` from result. SagaId::new()/Uuid internal to core. By construction.
- **caller_did/caller_context principal-bound (THE forward obligation)**: `enforce_caller_principal_binding` runs BEFORE the saga on ALL 3 bridges — checks (a) caller_did hosted by THIS bridge instance (PyO3/NAPI `identity_registry_contains`; UniFFI per-SDK idiom `identity_custody_registry(bi).contains_key`) AND (b) `is_member(caller_context_id, caller_did)`. Mismatch ⇒ Rejected-flavored SagaAborted SCP-SAGA-13050 before saga observes caller. Pinned by 3 pipeline_wiring structural assertions (export→helper edge + helper-body checks).
- **SCP-SAGA taxonomy mapped STRUCTURALLY**: `map_saga_error` reads each datum off the `SagaError` variant (never re-parses message). Aborted→SagaAborted (retry_after_ms read off RateLimited as Option<u64>, None NEVER coerced to 0 — would re-trip hard limit; code = `SCP-SAGA-{numeric}`), NeedsRepair→13065 (carries saga_id), Busy→13066 (carries contended_context). NAPI uses message-suffix `(retry_after_ms=null)` convention (addon can't carry typed fields) but data still read structurally off variant. Codes 13050/13062/13065/13066/13067 all registered in sdk-common.md upstream; check-error-codes.sh covers 13000-13999.
- **ADR-056 keying chokepoint**: `context_id_to_bytes` (state.rs:2072, decode-64-hex-else-SHA256) used for id STRING→[u8;32]; raw re-hash would double-hash a 64-hex id → wrong actor → spurious ContextNotRegistered. Pinned in all 3 assertions.

## Scope CLEAN (#116 = bridges+taxonomy+enforcement ONLY)
- capability-matrix `invoke_cross_context_saga` ALL 4 SDKs `false` + per-SDK `exemptions` citing PR-6c. NO SDK wrapper code in diff. Correct.
- bridge-aliases adds ONLY pyo3/uniffi/napi (no SDK rows).
- #1937 GENUINELY FILED + OPEN: "No turn-key bridge op for §6.2.0.1 tool-interface establishment (callers must hand-build EstablishToolInterface + drive governance_propose)". DX gap correctly OUT of #116 — saga IS committable via governance path, PROVEN by e2e `xctx_saga_authenticated_caller_commits_via_governance_established_interface` (e2e_bridge.rs:1755): establishes interface via `governance_propose(EstablishToolInterface)` (action JSON approved_by_source+target), drives saga A→B to Committed, asserts receipt.is_some() + output sum==42/ok==1. Negative tests cover unhosted-caller/hosted-non-member/malformed-nonce/target-axis-gate rejections.

## FINDING — MINOR (issue-number-in-source-comment)
`bindings/typescript/tests/real-napi.test.ts:2024` — newly-added test-block comment "the per-instance handle-affinity guard (#1549 Phase 4)". Violates the no-`#NNNN`-in-source/comments/test-names rule ([[feedback_no_issue_refs_in_code]]). MINOR: matches a PRE-EXISTING non-conforming pattern already in this file (lines 48/119/138/174 all carry `#1549`); explanatory, not provenance-load-bearing. Scrub to "the per-instance handle-affinity guard (ADR-048 Phase 4)" or drop the paren. (Borderline sibling: `#116` in capability-matrix `notes` JSON field at line ~588 — a documentation/data field describing PR slicing, more defensible than a code comment, but same spirit; could drop "from the same #116 bundle".)

## LESSON
Forward-obligation-discharging wiring PR → verify: (1) the obligation's named binding actually runs BEFORE the protected core call on EVERY bridge (here principal-binding before saga) + is STRUCTURALLY pinned in pipeline_wiring (export→helper edge so a token can't be satisfied by a sibling substring); (2) the deferred slice (SDK wrappers) is marked deferred in capability-matrix with per-SDK exemptions, NOT silently absent; (3) the DX/scope gap is a FILED OPEN issue with an accurate title (#1937), AND its absence is non-blocking because the feature is reachable another way PROVEN BY AN E2E (committed terminal via governance path, not just the export-reached-gate negative tests); (4) NO spec/ADR/registry edits ride along (codes pre-registered upstream — code conforms to spec, never reshapes it); (5) per-SDK idiom divergence (UniFFI custody-registry vs PyO3/NAPI identity_registry_contains) is fine if same property + each pinned. Tell that this is done right: ratchets raised ADDITIVELY (41→44, 105→106) with "pure coverage expansion" rationale, structural assertions check DEFINITION-presence not name-match, None-not-0 discipline on retry_after_ms.
