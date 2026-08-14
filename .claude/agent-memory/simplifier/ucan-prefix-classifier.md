---
name: ucan-prefix-classifier
description: The string-prefix UCAN error classifier is an established Python-SDK pattern; TS ports it verbatim — judge as parity, not new over-engineering
metadata:
  type: project
---

`evaluate_trust` (Python `scp_sdk/trust.py`, ported to TS `bindings/typescript/src/trust.ts`) classifies UCAN validation failures into Layer-1 `CapabilityValidation` fields by **string-prefix matching** on the bridge error Display text (`_TOKEN_PARSE_PREFIXES`, `_SIGNATURE_CHAIN_PREFIXES`, etc.) plus a `_PASSED_BEFORE` map keyed by the 11-step validate.rs pipeline stage.

This is brittle by nature (it parses human-readable error strings and will silently mis-classify if Rust error wording changes), and the prefix lists have grown to chase specific `malformed token: ...` spellings the Rust bridge emits — a denylist-shaped enumeration. BUT it is a **pre-existing, established pattern in the reference (Python) SDK**, not introduced by any single TS PR.

**Why:** The four-layer trust model returns *data not verdicts*; Layer 1 wants per-check booleans but the bridge only surfaces a single classified error. Absent a structured error code enum across the FFI boundary, prefix-matching is the chosen bridge.

**How to apply:** When a TS PR ports this, judge it as *parity* — verify the TS prefix lists match the Python ones verbatim (divergence is a real bug), don't re-flag the approach as novel over-engineering. The *root* improvement (a structured/typed UCAN failure category crossing the FFI boundary instead of stringly-typed Display text) is a legitimate observation to surface, but it belongs upstream in the bridge/Rust layer and affects all SDKs, not this TS port.
