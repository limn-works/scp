---
name: c3c-ts-capabilityvalidation-optional-cap
description: c3c-ts branch APPROVED — six-bool CapabilityValidation parity Py/TS, optional capability uniform across 4 bridges, diagnostic vs gate distinct, all_valid/allValid accessor parallel
metadata:
  type: project
---

Branch `c3c-ts` (ADR-055, spec §7.2.4) — structured CapabilityValidation FFI consumption. VERDICT: APPROVED (no blocking findings).

**What shipped:** `evaluate_ucan` `required_capability` mandatory→`Option`; bridge `ucan_evaluate` `capability` arg mandatory→optional across all 4 (PyO3 `capability=None`, NAPI/WASM/UniFFI `Option<String>`); empty/whitespace normalized to "no challenge" uniformly. New all-valid accessor: Python `CapabilityValidation.all_valid` @property + TS `allValid(v)` helper exported from index.ts. Enforcing gate `ucan_validate` UNCHANGED (mandatory capability).

**Why sound (evidence):**
- Six-field record identical in all 6 bindings; casing only differs (snake Rust/PyO3; `#[napi(object)]` auto-camelCase; WASM `rename_all=camelCase`; UniFFI `CapabilityValidationRecord` snake). Field set+meaning identical.
- all_valid/allValid compute same six-way AND, same order, mirrored doc-comments ("the one obvious correct happy-path call"). TS doc explicitly says "Mirrors Python".
- Optional capability is NOT a silent-security-default: optionality lives ONLY on non-enforcing diagnostic; gate stays mandatory. Core doc spells out None vs Some(c) + fail-closed guarantee. Diagnostic doc cross-refs gate everywhere.
- Six bools (not enum) is correct: independent orthogonal facts, not mutually-exclusive states. `#[allow(struct_excessive_bools)]` comment justifies (enum would break flat named-field shape per Agent-first tenet).

**Correctly out of scope (NOT gaps):** Swift/Kotlin idiomatic wrappers + their all_valid accessor — ADR-055 explicitly tracks separately; matrix exemptions cite "ADR-055 Decision-5 + per-SDK-idiom lesson". UniFFI CapabilityValidationRecord already has the 6 fields so future wrappers inherit parity.

**Pre-existing divergence (noted, not introduced/not blocking):** WASM `ucan_evaluate` takes `expected_aud_did: String` (required, differently named) vs `presenting_agent_did: Option` in other 3 bridges. Predates this PR; TS SDK normalizes it so it doesn't reach dev surface. Flag for eventual WASM-parity sweep.

Relates to [[c3c_structured_capability_validation.md]] (the C3c structured validation review).
