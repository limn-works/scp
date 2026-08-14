---
name: pr6c-saga-sdk-wrapper-convergence
description: PR-6c §6.2.4 saga SDK wrappers (TS done, Kotlin/Swift pending #1939) — mapSagaError string-parse is CONVERGENT, not the non-convergent gate class
metadata:
  type: project
---

PR-6c adds per-SDK wrappers for the §6.2.4 cross-context tool-invocation saga (ADR-049 §3a). TS slice (`SCP.toolInvokeCrossContextSaga` + `mapSagaError` + 3 typed error classes) reviewed CONVERGENT/SHIP on branch pr6c-ts. Kotlin/Swift wrappers still pending under #1939 — the same parse pattern will recur there.

**Why the string-parse exists (do NOT re-flag as TS over-abstraction):** napi collapses the typed Rust `SagaError`/`ScpNapiError` to a single `Error` carrying only the Display string, so the TS SDK reverse-engineers the structured datum out of the suffix. Python's PyO3 bridge preserves typed attributes, so Python reads them structurally (`_saga_terminal_from_bridge`) — no parse needed. The "structured-error-as-prose" collapse is a TRACKED BRIDGE-LAYER follow-up, not the SDK slice's concern. Within today's napi constraint, string parsing is the only available path.

**Why `mapSagaError` is CONVERGENT (closed-by-construction, not the denylist class):**
- The phrase set is exactly 3 (`saga aborted` / `saga needs repair` / `saga busy`), FIXED by the Rust enum `#[error(...)]` Display (crates/scp-ffi/napi/src/error.rs ~127-170). A 4th terminal requires changing the Rust enum + napi Display + the TS switch in LOCKSTEP — they co-evolve. Not an open denylist chasing "one more spelling."
- Three anchoring disciplines are all load-bearing vs adversarial `{message}`: start-anchored code (`/^\s*\[(SCP-SAGA-\d+)\]/`), prefix-anchored phrase, end-anchored datum (`\s*$`). A prior pass fixed unanchored→anchored — a CORRECTNESS fix, not case-chasing growth.
- Two-stage (code-present → "is a saga, don't delegate to mapBridgeError"; phrase → classify; unknown phrase → `default` ToolError, no silent drop) is deliberate; unifying the regexes would break the valid-code/unknown-phrase branch.

**Residual (Observation, inherent to the tracked bridge concern, not introduced here):** TS regexes hardcode the Rust Display format with NO shared/generated fixture — a Rust-side format change (`saga aborted:`→other) would silently mis-route (fall to ToolError / drop datum) and TS tests (independent literals) would NOT catch it. Mitigated only by co-located Rust Display tests. The cross-layer KAT is the bridge follow-up's job.

Distinct from [[project_pr116_saga_export_consolidation]] (that was the Rust BRIDGE `map_saga_error` thin-match; this is the SDK-WRAPPER parse). TS wrapper mirrors the Python reference wrapper exactly (same SCP-VALID-7002 codes, same validation shape, same SagaResult fields) — parity, not duplication.
