---
name: saga-caller-binding-redundant-gate
description: §6.2.4 xctx-saga bridge caller-binding negative tests don't mutation-detect the bridge check because the supervisor's own gate-1 emits the same SCP-SAGA-13050
metadata:
  type: project
---

The UniFFI/PyO3 §6.2.4 cross-context tool-invocation saga bridge adds `enforce_caller_principal_binding` (two axes: (a) caller_did in per-instance identity_custody_registry = "hosted/channel-authenticated", (b) `supervisor.is_member`). Both axes abort with `SCP-SAGA-13050`.

**Why the negative tests are weak (mutation resistance gap):** the SUPERVISOR's own authorize-before-reserve gate-1 (`crates/scp-runtime/src/context/supervisor/supervisor.rs:5504`) ALSO rejects a non-member caller with `code: 13050` (`SagaAbortReason::Rejected`). So:
- axis-a test (unhosted caller_did): the unhosted DID is also NOT a member of the caller context → if the bridge axis-a check is deleted, the saga reaches the supervisor and gate-1 emits 13050 anyway. Test still passes. Does NOT detect removal of the bridge axis-a check.
- axis-b test (hosted non-member): identical — bridge axis-b and supervisor gate-1 both `is_member`→13050.

**Fix:** strengthen the negative tests to assert the bridge-specific `msg` substring (axis-a: "is not an identity hosted by this bridge instance"; axis-b: "is hosted by this bridge but is not a member"), which the supervisor's gate-1 message ("is not a member of caller context") does NOT contain. Code-only assertion can't distinguish the bridge seam from the supervisor's redundant safety net.

**Lesson (general):** when a bridge/wrapper layer re-checks a property the core ALSO checks with the SAME observable error code, code-only assertions can't prove the wrapper's check is load-bearing. Pin the layer-unique message, or construct an input the core gate cannot reject (hard when the core gate is a superset).

Gate ordering in `tool_invoke_cross_context_saga` (uniffi bridge.rs): check_handle(PERM-3030) → validate_context_id/did/tool_id → decode_asserted_nonce(VALID-7001) → parse input JSON(TOOL-6002) → enforce_caller_principal_binding(SAGA-13050) → chokepoint/signing-keys → supervisor. The negative tests correctly choose inputs passing every EARLIER gate (valid did:dht: form, [a-z0-9_-] tool id, 32-hex nonce, valid JSON) so an earlier gate isn't the rejecter — that part is solid; the problem is the LATER supervisor gate.

**RESOLVED at commit d6baa211e (2026-06-29).** Both negative tests now pin the bridge-unique `msg` substring (axis-a: "is not an identity hosted by this bridge instance"; axis-b: "is hosted by this bridge but is not a member of"). I VERIFIED the supervisor gate-1 (supervisor.rs:5503-5519) emits a DIFFERENT message ("...is not a member of caller context '{hex}' — not authorized to initiate over it") with the same code 13050. MUTATION-PROVEN: neutering `enforce_caller_principal_binding` to `return Ok(())` makes BOTH negative tests FAIL (saga falls to supervisor gate-1, substring assert catches it). Axis-b is the strong case — neutered bridge lets the hosted stranger reach the supervisor, which still rejects (defense-in-depth), but the test fails because it pins the bridge layer's message. Gap fully closed.
