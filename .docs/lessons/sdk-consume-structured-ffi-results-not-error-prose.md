# SDKs Consume Structured FFI Results, Never Error Prose, and Validate Against a Real Capability URI

Governing artifacts: ADR-059 (`.docs/adrs/phase-2.md`) and spec §7.2.4 of
`07-trust-validation-and-capabilities.md`, which make the structured result normative. This
lesson records the failure modes behind them.

## Consuming results

- **Read the structured record, never guess it back from a message.** Capability validation
  crosses the FFI as `CapabilityValidation`, six per-stage booleans. Matching
  `[SCP-PERM-3001] permission error: …` prose to decide which stage failed couples every SDK
  to Rust's wording, and its safe failure mode (all-false on an unrecognized message) turns a
  reworded message into a silent regression.
- **Prose-emitting mocks hide state bugs.** In the C3c rebuild, mocks that reported
  `nonce_valid` unconditionally masked a multi-attestation nonce defect. A mock of a stateful
  operation models the state the real one observes: `ucan_evaluate` probes the nonce
  read-only, so re-evaluating keeps `nonce_valid: true`, while `ucan_validate` records it, so
  a second call rejects.
- **Classify a thrown error by its `[SCP-CAT-NNNN]` code, in one mapping function** (TypeScript
  `mapBridgeError`) applied once per dispatch surface. That function passes an already-typed
  error through untouched, since re-deriving a code from its message can only downgrade it,
  and a test covers the pass-through.

## Validating a capability

- **Never call `ucanValidate(handle, token, "*")`.** The enforcing path needs a full
  `scp:ctx:{contextId}/{resource}:{action}` URI; the bridge rejects `"*"` at parse time, and
  the caller receives an all-false verdict that reads as a result rather than an error.
- **Pass the DID of the participant under assessment, and never let it default**, or the
  audience check collapses into `aud == aud`.
- **An intrinsic evaluation (`ucan_evaluate` with no challenge capability) is a diagnostic,
  not an authorization.** It skips the grant match and does not consume the nonce, so the
  token stays replayable against the enforcing path.
- **Absorb by enumeration and propagate by default.** An absorbed error becomes a trust
  verdict. `evaluate_trust` absorbs exactly one code, `SCP-CTX-2076` (no participation facts
  for the subject), and re-throws the rest.
- **Match the code to the failure class.** A context-state fault is `SCP-CTX-2023` so the SDK
  re-throws it; `SCP-PERM-3001` is a real pipeline failure; `SCP-PERM-3030`, handle-affinity
  misuse, re-throws. Collapsing a fault into the protocol-failure code launders it into a
  verdict.
- **Evaluate every declared capability, not `att[0]` alone**, and never infer which stages
  passed from a hardcoded pipeline order.

## Where these rules are still broken

`SCP.evaluateTrust` in `bindings/typescript/src/scp.ts`, `evaluate_trust` in
`bindings/python/scp_sdk/trust.py`, and `evaluateTrust` in `bindings/swift/Sources/SCP/Trust.swift`
call `ucanEvaluate` and read the six booleans. The module-level `evaluateTrust` that
`bindings/typescript/src/index.ts` re-exports from `bindings/typescript/src/trust.ts` still runs
the superseded path: `validateOneCapUri` classifies bridge errors by prefix-matching the
`Display` message (with `REVOCATION_PREFIXES`), `__PASSED_BEFORE` hardcodes the stage order,
and `evaluateLayer1` sends only the `att[0].with` that `__extractFirstCapabilityUri` returns.
