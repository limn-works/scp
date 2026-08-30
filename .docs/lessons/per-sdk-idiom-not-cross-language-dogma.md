# Per-SDK idiom — language constraints stay local

> **ADR-055 (2026-06-29):** the WASM bridge was removed; references below to a fourth WASM/wasm-bindgen bridge are historical. SCP now ships four language SDKs (Python, TypeScript, Swift, Kotlin) over three FFI bridges (PyO3, NAPI, UniFFI); the browser is a remote thin client. The per-SDK-idiom rule below remains evergreen.

## Principle

> "I don't want optimizations or constraints for one language to dictate what
> happens in another's SDK. That's bad dogma."
> — Alec, 2026-04-25

SCP ships SDKs in four languages (Python, TypeScript, Swift, Kotlin)
over three FFI bridges (PyO3, NAPI, UniFFI). Each binding tool
has its own constraints. **Those constraints must not propagate across
languages.** When a binding tool in language A forces an API shape, that
shape is local to A — it does not become the universal shape for B, C, D.

## What triggered the lesson

ADR-048 §7 originally claimed *"There is one class, one surface, one entry
point"* across all SDKs and tabulated method counts as if convergence on a
single shape was a deliberate architectural goal. It wasn't. The shape came
from Kotlin: `CoroutineBridge` requires object-bound coroutine scope, which
made free-function APIs awkward to compose with structured concurrency.
Python and TypeScript inherited Kotlin's shape without independent
justification; Swift (UniFFI generator) opted out
because it couldn't implement it. The "one surface" claim was Kotlin's
idiom dressed up as a project-wide architectural decision.

## The rules

**FFI Rust layer (`crates/scp-ffi/*/src/*`)** is governed by [ADR-048 §1](../adrs/ADR-048-scp-multi-instance.md#1-scp-is-the-first-class-sdk-level-opaque-object-in-all-four-language-sdks):
pure protocol helpers (hashing, encoding, shape validators) stay as free
functions. No `&self` parameters that go unused. No `_bi: &BridgeInstance`
underscore-elision. No "for symmetry with [other bridge]" arguments.

**SDK wrapper layer (`bindings/{python,typescript,swift,kotlin}/`)** is
governed by [ADR-048 §7](../adrs/ADR-048-scp-multi-instance.md#7-per-sdk-idiomatic-shape--language-constraints-stay-local).
Each SDK's shape is a local choice. See §7 for the per-language table —
do not duplicate it here.

When in doubt, ask: "Is this constraint rooted in this language/bridge's
own semantics, or am I propagating it from elsewhere?" If propagating, stop.

## Permanent guidance

- **The ADR is the reference, not the implementation.** When a cross-bridge
  audit flags an op as "missing in X but present in Y," do not assume Y is
  the reference. Both may be wrong. Read §1 and §7 first, then prescribe.

- **Audit scripts measure code state, not intent.** Code drifts from ADRs.
  §7 of ADR-048, SCP multi-instance, arrived with one framing, and the
  per-SDK amendment landed days later, so a script reading only the code
  saw neither. Letting an audit script's view of code redefine the
  architecture reverses the artifact-flow invariant in CLAUDE.md.

- **Review-agent unanimity is weak evidence when the prompt converges
  agents.** If you ask "should this function be a method or a free fn?",
  agents will cite §1 in unison without arbitrating §1-vs-§7
  contradictions in the same ADR. To force arbitration the prompt must
  surface the conflict explicitly.

## Related artifacts

- [ADR-048 §1](../adrs/ADR-048-scp-multi-instance.md#1-scp-is-the-first-class-sdk-level-opaque-object-in-all-four-language-sdks) — FFI layer rule.
- [ADR-048 §7](../adrs/ADR-048-scp-multi-instance.md#7-per-sdk-idiomatic-shape--language-constraints-stay-local) — per-SDK shape table.
- CLAUDE.md → artifact-flow invariant (plans → specs → ADRs → code).
