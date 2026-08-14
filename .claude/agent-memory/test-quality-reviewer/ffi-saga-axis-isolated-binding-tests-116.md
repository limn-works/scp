---
name: ffi-saga-axis-isolated-binding-tests-116
description: Exemplary axis-isolation test pattern — proving ONE of two same-error-code guards fired via member-but-unhosted setup + mutation experiment
metadata:
  type: project
---

# #116 axis-isolated caller-principal-binding tests (xctx §6.2.4 saga)

Branch `feat/116-ffi-saga-export` HEAD 9611159f6. Commit added 3 tests (PyO3 e2e_bridge.rs:1436, NAPI tools.rs:2269, UniFFI bridge.rs:21382) named `xctx_saga_member_but_unhosted_caller_*`.

**The problem they solve (worth replicating):** `enforce_caller_principal_binding` has TWO guards that BOTH emit the SAME error code (SCP-SAGA-13050): axis-a (hosted-on-this-instance: `identity_registry_contains` / `identity_custody_registry.contains_key`) and axis-b (membership: `supervisor.is_member`). Code alone can't tell which fired. The pre-existing tests had callers that were BOTH unhosted AND non-members, so they couldn't prove axis-a specifically guards anything (axis-b or producer gate-1 would also reject). These new tests isolate axis-a by making the caller a GENUINE member (so axis-b passes) but unhosted (so only axis-a can reject).

**Three things that make these tests sound (the checklist for "is one of N same-code guards actually proven"):**
1. Discriminating substring: axis-a msg = `"is not an identity hosted by this bridge instance"`, axis-b msg = `"is hosted by this bridge but is not a member of"`. Asserting the axis-a substring (not just the shared code) is what makes them axis-specific.
2. Real precondition (no vacuous pass): asserts `is_member(ctx,caller)==true` AND `!registry.contains(caller)` BEFORE invoking. `is_member` is a real fail-closed actor-mailbox query, not a stub.
3. Membership injection vehicle: `Supervisor::test_insert_member` (`#[cfg(feature="testing")]` at every layer — supervisor method, `MessagingCommand::TestInsertMember` variant, dispatch arm, handler). Writes REAL role state (`members_mut().insert` + `system_assign_role` + `membership_class_c_mut().add_member`) — same fields an executed AddMember governs — bypassing only the MLS Welcome a non-hosted DID can't complete. NOT a production leak. PyO3 variant uses creator-is-member instead of injection (also valid).

**Mutation experiment (I ran it):** neutering axis-a (`if false && !registry.contains...`) made ALL THREE fail closed:
- PyO3 → caller passes axis-b, then IDENT-1001 (no signing key for unhosted DID) → fails `SagaAbortedError` type assertion.
- NAPI/UniFFI → caller passes axis-b AND producer gate-1, caught by producer gate-2 `has_established_tool_interface` = SCP-SAGA-**13062** (distinct from axis-a 13050) → fails code/substring assertion.
This simultaneously proves (a) axis-b genuinely passes (injection worked), (b) producer backstop 13062 ≠ axis-a 13050, (c) tests discriminate correctly. Verdict: SHIP, zero findings.

Enforcement raised monotonically (legitimate): ffi_conformance MIN_PARITY 105→106, pipeline_wiring MIN_ACTIVE 41→44. retry_after_ms None-never-coerced-to-0 pinned in scp-ffi/common/src/saga_errors.rs test `rate_limited_none_is_never_coerced_to_zero`. Commit tests reach REAL Committed asserting decoded handler output (sum==42/ok==1), not is_some().
