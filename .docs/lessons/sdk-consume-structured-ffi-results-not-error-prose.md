# SDK consumers consume structured FFI results — never reverse-engineer outcomes from error prose

**Source:** ADR-057 (`.docs/adrs/phase-2.md`), spec §7.2.4
(`.docs/specs/07-trust-validation-and-capabilities.md`), the C3c trust/capability
SDK rebuild (PRD SCP-302).

## The rule

When a Rust core operation already returns a **structured** result across the FFI
(a typed record of explicit fields), the SDK MUST consume that record directly. It
MUST NOT discard the structured truth and then guess it back by string-matching the
human-readable prose of an error message.

The canonical example: capability/trust validation crosses the FFI as
`CapabilityValidation` — six explicit per-stage booleans (`tokens_valid`,
`signatures_valid`, `within_ceiling`, `nonce_valid`, `not_revoked`,
`time_bounds_valid`). A caller wanting the per-check breakdown reads those fields.
Reconstructing *which* check failed by matching `[SCP-PERM-3001] permission error: …`
prose is forbidden.

## Why prose-parsing is wrong on two independent grounds

1. **Brittle by construction.** It couples the SDK to the exact wording of error
   messages — a denylist of prose spellings that grows every time the core rephrases
   a message, and silently mis-classifies the moment the wording drifts. A structured
   truth flattened to a string and guessed back is a lossy projection.
2. **It masks real defects (the mock-fidelity corollary).** Test mocks that emit
   prose without modeling the state the real op observes will pass while the real op
   is broken. In C3c this masked a multi-attestation **nonce** bug: the mocks emitted
   a string that reported `nonce_valid` unconditionally, so the suite never exercised
   the path where the nonce check actually consumes/observes state across attestations.
   A typed result whose mocks must populate real per-stage outcomes — including nonce
   state — would have surfaced it.

## The mock-fidelity corollary

**Typed mocks must model the state the real operation observes.** A mock for a
read-only diagnostic (`ucan_evaluate`) must distinguish itself from the throwing
gate (`ucan_validate`): the diagnostic probes the nonce read-only and records
NOTHING, so re-evaluating the same token keeps `nonce_valid: true`; the gate records
the nonce, so a second call would reject. A mock that returns the same canned record
regardless of prior calls is a tautology that proves nothing about the state machine.

## Error *typing* still derives from codes, through one chokepoint

Where an SDK must classify a thrown gate error into a typed SDK error, it maps on the
structured `[SCP-CAT-NNNN]` error **code** the bridge attaches, through a **single
mapping function** (one chokepoint — e.g. TS `mapBridgeError`) applied at one site per
dispatch surface (e.g. a `wrapBridgeErrors` Proxy over the bridge factories, plus the
SDK-class methods that dispatch through the raw addon directly), not with a try/catch
ladder of `message.contains(...)` at each call site. Scattered string classification is
the same brittle denylist this lesson retires, in a second location. The mapping
function must also pass already-typed errors through untouched — re-deriving a code from
the message of an error that already carries a structured `.code` can only lose
information (it downgrades a precise subclass to a generic error). That pass-through is
security-load-bearing and must be covered by a test, or a future deletion silently
re-opens the downgrade.

## How to catch this when reviewing

- Any SDK code path that `catch`es an error and branches on `.message`,
  `.includes(...)`, `.startsWith(...)`, or `.match()` against message text to infer an
  outcome: that is prose-parsing — replace it with the structured result.
- Any FFI op with a structured return type whose SDK wrapper ignores the record and
  re-parses an error: a finding.
- Any test mock for a stateful op (nonce, replay, revocation) that returns a constant
  record regardless of call history or arguments: it cannot catch state bugs.

## Related

- ADR-057 Rejected Alternatives (prose-parsing; overloading the throwing gate).
- `.docs/lessons/per-sdk-idiom-not-cross-language-dogma.md` — the structured record
  shape is identical across bindings (only field casing differs); the wrapper is
  per-SDK idiomatic.
- The `evaluate`/`evaluateTrust` wrappers landed in all four SDKs together
  (Python, TypeScript, Kotlin, Swift), as ADR-057 §Decision-5 mandates: they consume
  the existing `CapabilityValidationRecord` the UniFFI bridge already exports — they
  must NOT re-introduce prose-parsing.
