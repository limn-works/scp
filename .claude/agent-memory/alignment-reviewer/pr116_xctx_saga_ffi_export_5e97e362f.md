---
name: pr116-xctx-saga-ffi-export
description: PR #116/PR-6b — FFI export of §6.2.4 cross-context tool-invoke saga across 3 native bridges; ALIGNED, 0 findings @ 5e97e362f
metadata:
  type: project
---

# PR #116 / PR-6b — §6.2.4 xctx-tool-invoke saga FFI export — ALIGNED, 0 findings @ `5e97e362f` (base 191ae8fc8, worktree ffi-saga-116)

Scope: native-bridges-only (PyO3 `tool_invoke_cross_context_saga` / NAPI `toolInvokeCrossContextSaga` js_name / UniFFI `tool_invoke_cross_context_saga`). SDK wrappers genuinely deferred to #1939 (OPEN, "PR-6c: SDK wrappers...") — capability-matrix 4 cells `false` + exemptions cite #1939. NO public wrapper in any `bindings/*/src/` (TS change is test-only `tests/real-napi.test.ts` hitting raw NAPI).

**Why:** Makes the §6.2.4 saga producer (`Supervisor::start_cross_context_tool_invocation_saga`, already existed pre-PR) LIVE through FFI; journal becomes observably live per ADR-049:65.
**How to apply:** This is the wiring PR where ADR-049 §3a's **caller-principal forward obligation** (line 94) lands — verify it's actually implemented, not deferred again.

## Mandates verified (all PASS)
- **block-until-terminal**: `block_on(start_..._saga(...))` → `Committed`→SagaResult, else typed error. No async/poll/saga_state. ✓
- **SagaId supervisor-minted, never input**: `SagaResult.saga_id = output.saga_id.0`; not a param on any bridge signature. ✓
- **SCP-SAGA taxonomy**: decomposition lives ONCE in `common/src/saga_errors.rs::decompose_saga_error` (structural read off variant, NEVER string-parse; `None`-never-coerced-to-`0`; `SCP-SAGA-{code}` format). 3 bridges are thin tails (only `message:`/`msg:` label diff). Codes 13050/13065/13066 already registered in sdk-common.md (13065/66 pre-existed from typed-SagaError PR). check-error-codes.sh PASS (band 13000-13999). ✓
- **Caller-principal forward obligation (§3a:94 + §6.2.4:274)**: `enforce_caller_principal_binding` in ALL 3 bridges enforces BOTH axes: (a) `identity_registry_contains` (caller_did hosted by THIS instance = co-resident channel-auth principal) AND (b) `supervisor.is_member(caller_ctx, caller_did)`. Runs BEFORE saga. Mismatch ⇒ Rejected-flavored SagaAborted/13050. ✓ This is THE load-bearing piece — membership-alone is necessary-not-sufficient; axis (a) is the added auth.
- **§3a hard-prereq (per-set gating before FFI surface)**: check-saga-gating-granularity.sh PASS, explicitly notes "start_*_saga FFI export present; negative assertion load-bearing and passes (no instance-wide guard)". ✓
- **Target axis**: producer gate 2 (supervisor.rs:5518, BLACK-624-02) = "no established interface" ⇒ SCP-SAGA-13062. PyO3 relies on this (no handle pre-check); NAPI/UniFFI ALSO have instance-affine handle pre-check (`check_handle`/`napi_check_handle!` ⇒ SCP-PERM-3030). Threat-doc claim accurate.

## Threat-model doc-comments (commit 5e97e362f, doc-only +74/-0)
Added "# Trust boundary (co-resident single-tenant only)" to all 3 export methods. ACCURATE, well-calibrated: (a) names the multi-tenant overclaim risk ("registry cannot distinguish which tenant") + says future cross-node "cannot reuse 'is hosted here' as authenticated-principal proof" (correctly frames §3a forward obligation as NOT-yet-satisfied for cross-node, satisfied co-resident by construction); (b) per-bridge axis-enforcement difference stated correctly (PyO3 supervisor-gates vs NAPI/UniFFI handle pre-check, "equivalent authorization, less pre-flight defense-in-depth"); (c) signer-authorization correctly deferred to DOWNSTREAM receipt-consumer per §6.2.4:300. No over/under-claim.

## Prior MINOR (#1549 in test comment) — RESOLVED
commit dd16fa4eb scrubbed `#1549` from the saga test-block comment in real-napi.test.ts (now "the per-instance handle-affinity guard" no ref). The OTHER 4 pre-existing #1549 refs (lines 48/119/138/174, ADR-048-Phase-4 context) correctly LEFT untouched (out of scope). Same commit fixed capability-matrix: exemptions now cite #1939 (real OPEN tracker) + dropped self-referential "#116 bundle" phrasing. Verified #1939 OPEN, #117 is CLOSED+unrelated ("sync/offline spec").

## Hygiene
- NO spec/ADR reshaped (`.docs/specs/`+`.docs/adrs/` zero changes; only sdk-capability-matrix.json = downstream standard). Artifact flow respected. ✓
- NO `#NNNN` introduced into source/tests by diff. ✓
- pipeline_wiring 41→44 (binding+chokepoint+producer pinned per bridge, PLUS binding checks identity_registry_contains AND is_member). ffi_conformance MIN_PARITY 105→106 (additive=permitted enforcement edit). bridge-aliases.json adds canonical entry. ✓
- e2e_bridge.rs: substantive differential tests — unhosted→13050, hosted-non-member→13050, authenticated→reaches 13062 asserting NOT 13050 (real differential, not string-game), full Committed via governance-EstablishToolInterface asserting receipt+output bytes. Cargo.toml `testing` feature added for SagaBusy reservation helper (justified). ✓

LESSON: a "wiring PR that lands a forward obligation" → verify the obligation is ACTUALLY implemented (grep enforce_caller_principal_binding CALLED in each bridge body, both axes), the §3a ordering gate still PASSES with exports present (run it — negative assertion is now load-bearing), and the threat-doc neither overclaims co-resident auth as cross-node-ready nor underclaims it. Differential test that asserts error is NOT the earlier-gate code proves the gate was passed, not short-circuited.
