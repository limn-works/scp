# UCAN Validation Requires a Real Capability URI — Never Pass `"*"`

**Source**: ADR-059, structured capability and trust validation across the FFI
(`.docs/adrs/phase-2.md`), and spec §7.2.4 of `07-trust-validation-and-capabilities.md`.

## Rules

- **Never call `ucanValidate(handle, token, "*")`.** The enforcing path — the one that
  consumes the nonce and gates an action — requires a fully-qualified
  `scp:ctx:{contextId}/{resource}:{action}` URI. The bridge rejects a bare `"*"` at
  URI-parse time, before any cryptographic check runs, so the caller receives an all-false
  verdict that reads as a legitimate result rather than an error.
- **Pass the DID of the participant under assessment, and never let it default.** The
  bridge rejects an empty or absent `presenting_agent_did` / `subject_did`, which is what
  keeps the audience check from collapsing into `aud == aud`.
- **A read-only capability evaluation measures self-consistency, not authorization.**
  Intrinsic mode — `ucan_evaluate` with no challenge capability — answers whether the token
  parses, carries valid signatures and a valid delegation chain, sits within the context
  ceiling, and is unexpired and unrevoked, measured against the token's own declared
  capability set. It skips the invoked-capability grant-match, and it probes the nonce
  without consuming it, so the evaluated token stays replayable against the enforcing path.
  A green `CapabilityValidation` is a diagnostic; treating it as "the agent may do X" is a
  security error. To verify authority for a specific operation, pass the concrete capability
  URI.
- **Enumerate what you absorb, and default to propagate.** Error absorption is the security
  boundary of a trust layer: an absorbed error becomes a partial or all-false trust verdict,
  and a re-thrown error surfaces a fault. Enumerating what to re-throw and absorbing by
  default puts every unmodeled fault into the "absorb" branch, which turns it into a false
  verdict.
- **Match the error code to the failure class, not to the convenient catch block.** A
  validation entrypoint has at least two failure classes: the token failed the protocol, and
  the infrastructure failed to evaluate the token. They carry distinct codes because a
  downstream absorber keys on the code to decide between a visible fault and a trust
  verdict. Collapsing a context-state fault into the protocol-failure code launders the
  fault into a verdict.
- **Return typed results across the FFI; never classify a failure by prefix-matching a
  Display message.** A prose classifier couples every SDK to Rust's message text, and the
  safe failure mode — all-false on an unrecognized message — makes a reworded message a
  silent regression rather than a loud one.
- **Never infer "every earlier stage passed" from a hardcoded pipeline order.** A classifier
  that maps a failing stage to a list of stages it assumes ran first reports wrong `true`
  fields the moment someone reorders the pipeline, and the reorder produces no failing test.
- **Evaluate every declared capability, not the first one.** A token whose `att[0]` sits
  within the ceiling and whose `att[1]` does not reports `withinCeiling: true` to a caller
  that reads only `att[0]`.

## See also

- `.docs/lessons/typescript-node-only-globals-break-browser.md` — a Node-only decode inside
  a token-parsing helper broke cross-environment evaluation the same silent way.
- `.docs/lessons/delegation-chain-full-validation.md` — every link in a delegation chain
  needs the full pipeline, not just structural checks.
- `.docs/lessons/sdk-consume-structured-ffi-results-not-error-prose.md` — the typed-result
  rule as it binds every bridge, not only this one.
