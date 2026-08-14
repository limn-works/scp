---
name: ffi-saga-116-pr6b-review
description: PR-6b / #116 native FFI export of §6.2.4 cross-context tool-invoke saga @ 3afc30c6c — ALIGNED, 0 findings
metadata:
  type: project
---

# #116 / PR-6b — native FFI saga export @ `3afc30c6c` (worktree ffi-saga-116, base origin/main) — ALIGNED, ship, 0 findings

Exports pre-existing `Supervisor::start_cross_context_tool_invocation_saga` across PyO3/NAPI/UniFFI. PURE WIRING — producer, `CrossContextToolInvocationRequest`, `SagaSigningKeys` all pre-exist (0 hits in diff for their defs); NO `.docs/specs/**` or `.docs/adrs/**` touched.

**Why:** ADR-049 §3a deferred the FFI saga surface behind the per-set-gating mechanical gate (which already exists + untouched) + the §6.2.4 *Caller authentication* forward obligation (line 94). This PR lands the export + that binding.

**How to apply (alignment tells verified — reuse this checklist for FFI-export-of-deferred-saga PRs):**
- **block-until-terminal**: PyO3 `block_on` (tools.rs:1218), NAPI `Box::pin(...).await` (napi/tools.rs:986), UniFFI `spawn(...).await` (uniffi/bridge.rs:12455). No saga_state/poll.
- **supervisor-minted SagaId NEVER input**: all return `output.saga_id.0`; request struct has NO saga_id field.
- **SCP-SAGA taxonomy STRUCTURAL**: `scp_ffi_common::saga_errors::decompose_saga_error` reads retry_after_ms off `RateLimited`, saga_id off `NeedsRepair`, contended_context off `Busy` — never message-parse; `None`-never-`0` centralized+unit-tested ONCE (3 bridges can't drift). Codes in registered 13000-13999 band; 13050/13065/13066/13067 all in sdk-common.md. `Aborted` sub-code formatted inline `SCP-SAGA-{producer-numeric-discriminant}` (correct — band-partitioned model, named consts pin only 2 fixed terminals + caller-axis 13050).
- **caller-principal binding ENFORCED in wiring PR**: `enforce_caller_principal_binding` BEFORE saga on all 3 bridges, two axes (a) hosted-by-instance (b) member-of-caller-ctx → `SagaAborted{13050}`. Pinned by 3 NEW pipeline_wiring.rs assertions (`{pyo3,napi,uniffi}_saga_export_wires_binding_chokepoint_and_producer`).
- **scope native-only**: SDK wrappers ALL `false` in capability-matrix w/ per-SDK exemptions citing #1939 (REAL open issue, detailed per-lang scope).
- **enforcement ADDITIVE only**: MIN_ACTIVE_PIPELINE_ASSERTIONS 41→44, MIN_PARITY_OPERATIONS 105→106. Nothing weakened.
- **NO #NNNN in source/comments/test-names** (diff-scanned). Issue refs only in capability-matrix JSON (correct home) + #1939.
- **threat-model doc-comments ACCURATE**: co-resident single-tenant trust boundary (tools.rs:1869-1894) honestly scopes "hosted-here = authenticated principal" to single-tenant co-resident + ties multi-tenant/cross-node gap to ADR-049 §3a forward obligation (matches spec §6.2.4 *Forward obligation* verbatim-in-spirit). Signer-auth (§6.2.4) deferred downstream to receipt consumer — correct.
- **HEAD commit 3afc30c6c is alignment-POSITIVE**: removes a PHANTOM comment (e2e_bridge [[test]] block claimed `testing` enables a saga-gating helper test `test_reserve_saga_context_set` that DOESN'T EXIST); empirically dropped `testing`, kept only `allow_in_memory_custody`. dd16fa4eb scrubbed "#116 bundle" prose → #1939 filed-issue ref.
- **tests mutation-resistant NOT gamed**: e2e_bridge.rs:1306 unhosted-caller / 1360 hosted-non-member (asserts BRIDGE-UNIQUE substring "is hosted by this bridge but is not a member of" so producer gate-1's identical 13050 can't mask a deleted bridge check) / 1427 chokepoint reaches target-axis 13062 (proves ADR-056 digest keyed right actor, not double-hashed→ContextNotRegistered) / 1764 full Committed-via-governance asserts handler's real output (sum=42). No `let _ =`, no `#[ignore]` gaming.

LESSON: FFI-export-of-deferred-saga alignment review → confirm producer/types PRE-EXIST (pure wiring, 0 def-hits in diff) + NO spec/ADR touched + block-until-terminal + minted-id-never-input + typed-error read STRUCTURALLY off variant (not message-parse) + codes in registered band + the ADR's named forward-obligation (caller-principal binding) ENFORCED in THIS PR + pinned by NEW mechanical assertions + deferred slice is a FILED issue + enforcement edits ADDITIVE + behavioral tests assert BRIDGE-UNIQUE substrings to survive producer-message masking. A phantom-comment SCRUB in the HEAD commit is alignment-positive, not a regression.
