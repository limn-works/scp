---
name: app-bound-unbound-event-log-pr2235
description: Completeness review of PR #2235 §8.4 AppBound/AppUnbound durable event-log appends across 3 bridges + 4 SDKs
metadata:
  type: project
---

PR #2235 `feat/app-bound-unbound-event-log` — §8.4 app_bind/app_unbind (event log tags 74/75).

**Verdict: INCOMPLETE — solely because of missing behavioral tests at bridge + SDK layers.**
Wiring/implementation is otherwise complete across every layer.

**What IS complete (verified):**
- Runtime shared fns `bind_app`/`unbind_app` in `crates/scp-runtime/src/context/app_sandbox.rs`
  (capabilities.sort_unstable() Merkle-determinism fix at ~876; 6 runtime unit tests 2485-2701).
- All 3 bridges route through them: PyO3 `app_bind`/`app_unbind` (scp-ffi/src/context.rs 6147/6247),
  NAPI `app_bind_on`/`app_unbind_on` (napi/src/context.rs 5055/5149, exposed as appBind/appUnbind in
  scp.rs 2837/2854), UniFFI `app_bind`/`app_unbind` (uniffi/src/bridge.rs 15724/15870).
- was-bound check present in ALL 3 bridges (CTX_2059) using ephemeral in-process bridge state
  (`bound_apps` map / UniFFI `bound_apps_registry`) — NOT reconstructed from durable log.
- 4 SDK wrappers: Python `context_app_bind` (scp.py 1393), TS `contextAppBind` (scp.ts 4616),
  Swift `contextAppBind` (Scp.swift 566 — NOT Context.swift), Kotlin `contextAppBind` (Scp.kt 755).
- Error codes CTX_2056-2059 defined in common/src/error_codes.rs 379-385, used symmetrically.
- Enforcement: pipeline_wiring.rs 2 new #[test] structural assertions (MIN 55→57);
  ffi_conformance MIN_PARITY_OPERATIONS 106→111 (+3 streaming-saga from other work, +2 this PR —
  ratchet comment accurate); bridge-aliases.json app_bind/app_unbind for all 3; capability matrix
  app_bind/app_unbind = python/ts/kotlin/swift all true.

**The gap:** ZERO behavioral tests at bridge (PyO3/NAPI/UniFFI) and SDK (Py/TS/Swift/Kotlin) layers.
Only runtime unit tests + structural source-string assertions + parity count exist. No test actually
CALLS app_bind through a bridge/SDK and asserts an AppBound event lands or CTX_2059 fires. Violates
"a wrapper without tests is half-done" / "no untested code ships".

**Traps in the review prompt:**
- Swift wrapper is in `Scp.swift`, NOT `Context.swift` (prompt pointed at Context.swift — empty there).
- `agent_binding_pipeline_tests.rs` is ADR-039 #agent-persona (NOT app-binding); modified in this PR
  only as ADR-049 actor-migration collateral (build_encrypted_envelope→_actor). Has 13 tests but none
  for app_bind. Unrelated-change bundling — atomicity WARNING.

**Scope note:** PR delivers only the event-log/auditability slice of §8.4 (§8.4.2 pt 5 + Auditability).
Scoped-handle runtime enforcement (§8.4.2 pts 2-4: capability-scoped handle return, per-call rejection
of undeclared caps, no-escalation) is NOT in this diff — verify separate tracked story.
WASM/browser correctly N/A (scp-client-wasm is separate ADR-057 path; no browser matrix cell).
