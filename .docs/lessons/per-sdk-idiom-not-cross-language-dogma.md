# Per-SDK idiom — language constraints stay local

## Principle

> "I don't want optimizations or constraints for one language to dictate what
> happens in another's SDK. That's bad dogma."
> — Alec, 2026-04-25

The SCP project ships SDKs in five languages (Python, TypeScript, Swift, Kotlin,
WASM) over four FFI bridges (PyO3, NAPI, UniFFI, wasm-bindgen). Each binding
tool has its own constraints — some structural, some ergonomic, some historical.
**Those constraints must not propagate across languages.** When a binding tool
in language A forces a particular API shape, that shape is local to language A.
It does not become the universal shape for B, C, D.

## What "bad dogma" looks like

The failure mode this lesson exists to prevent: an architectural decision in
one binding gets enshrined as a project-wide rule because "we want consistency
across SDKs." Then every future change is forced to match that one binding's
constraints, even when the other languages have no equivalent constraint and
would naturally express the API differently.

Concrete example — what triggered this lesson:

ADR-048 §7 originally claimed *"There is one class, one surface, one entry
point"* across all SDKs. It tabulated method counts (Python 162, TypeScript
181, Kotlin 137) as if the convergence on a single shape was a goal achieved
through deliberate design.

It wasn't. The shape came from Kotlin: Kotlin's `CoroutineBridge` requires
object-bound coroutine scope for cancellation/inheritance, which made
free-function APIs awkward to compose with structured concurrency. So Kotlin
went method-on-`SCP`, and Python and TypeScript inherited the shape without
independent justification. UniFFI/Swift opted out (UniFFI generator can't
collapse `#[uniffi::Object]` into methods on an outer class). WASM stayed as
free functions.

**Result**: Python and TypeScript carried Kotlin's constraint without ever
needing it, while Swift and WASM ignored the rule because they couldn't
implement it. The "one surface" claim was Kotlin's idiom dressed up as a
project-wide architectural decision.

## The correction

ADR-048 §1 reasserts itself at the FFI Rust layer:

> Pure protocol helpers that touch no registry (hashing, encoding, validation
> of shape-only inputs) stay as free functions.

This governs `crates/scp-ffi/*/src/*` — the Rust-side FFI surface. PyO3, NAPI,
UniFFI, WASM all expose pure helpers as free `#[pyfunction]` / `#[napi]` /
`pub fn` / `#[wasm_bindgen] pub fn`. The compiler's `&self` signature is honest
only when `&self` is actually read.

ADR-048 §7 governs the SDK wrapper layer. Each SDK chooses its idiom locally:

- **Kotlin**: methods on `SCP` for `CoroutineBridge` scope inheritance. Pure
  helpers also live as methods because Kotlin's coroutine semantics make
  module-level functions awkward to compose with structured concurrency.
- **Python**: stateful operations are methods on `scp_sdk.SCP`. Pure protocol
  helpers stay as module-level functions (`scp_sdk.context.template_get_params`
  etc.). Python idiom favors module-level functions for pure operations.
- **TypeScript**: stateful operations are methods on the `SCP` class. Pure
  helpers may be exposed as `SCP` methods that route to module-level NAPI
  exports, or as module-level imports — TS-local ergonomic choice.
- **Swift**: per-object UniFFI-generated wrappers. Pure helpers and per-object
  methods are both free `pub fn` at the FFI layer — UniFFI generator constraints.
- **WASM**: free functions at module scope.

## How this lesson applies to future decisions

When you encounter an apparent cross-language asymmetry:

1. **Identify the constraint's origin.** Is the asymmetry forced by a binding
   tool's structural rules (UniFFI generator, napi-rs limitations,
   `wasm_bindgen` constraints)? Is it forced by a language's runtime semantics
   (Kotlin's CoroutineBridge, Python's GIL, TypeScript's async/Promise model)?
   Or is it just a maintainer preference?

2. **Bound the constraint to its source.** Constraints rooted in language
   semantics or binding-tool structure stay in that language/bridge. They do
   not propagate. Don't ask "should X follow Y's pattern" — ask "is there a
   reason in X's own language/binding to use this pattern?"

3. **Audit the matrix against the spec, not the implementation.** When a
   cross-bridge consistency audit flags an op as "missing in bridge A but
   present in bridge B," do not assume B is the reference. The reference is
   the ADR. Both A and B may be right or wrong. Read the ADR before
   prescribing a "catch-up."

4. **Never use audit scripts to redefine architecture.** Audit scripts measure
   code state. Code state can drift from ADRs. The ADR governs (CLAUDE.md
   artifact-flow invariant: plans → specs → ADRs → stories → source code).
   Letting code state define the new pattern reverses the flow and creates
   phantom provenance.

## How this lesson applies to ADR review

When reading or amending an ADR:

1. **Survey the full ADR.** Later sections can supersede or qualify earlier
   ones. Don't cite §N as authoritative without checking §N+1...§final.

2. **Trace clauses to their source commits.** ADR-048's §1 was drafted
   2026-04-18 (commit `5c4b4b62d`). §7 was added 2026-04-25 (commit
   `efc58ecfd` — Phase 4 PR 5). The §7 universalism reflected the §7 commit's
   PR scope (Kotlin parity), not a reconsideration of §1.

3. **Distinguish architectural claims from implementation snapshots.**
   "There is one class, one surface, one entry point" is an architectural
   claim that the SDKs converge on a single shape. "Python: 162 methods,
   TypeScript: 181 methods, Kotlin: 137 methods" is an implementation
   snapshot. Snapshots become wrong with the next refactor; only the
   architectural claim stays load-bearing. ADRs should make architectural
   claims, not record snapshots.

## How this lesson applies to review-agent workflows

When dispatching multiple review agents to evaluate an architectural choice:

1. **The prompt is part of the experiment.** A prompt that frames the question
   narrowly (e.g., "should this function be a method or a free function?") will
   get narrow answers. Agents may unanimously cite the same clause without ever
   arbitrating a clause-vs-clause contradiction in the same ADR.

2. **Unanimity is weak evidence when the prompt converges agents.** Two
   agents agreeing on §1 because the prompt asked about pure helpers doesn't
   tell you whether §1 or §7 governs. To force arbitration, the prompt must
   surface the contradiction explicitly or ask "which clause governs?" rather
   than "what's the right pattern?"

3. **Validate review-agent verdicts against the actual ADR before acting.**
   Even when agents converge with high confidence, read the ADR yourself and
   confirm they engaged with the relevant sections. Agents skim ADRs the same
   way humans do.

## Permanent guidance

- The FFI Rust layer (`crates/scp-ffi/*/src/*`) is governed by ADR-048 §1: pure
  protocol helpers are free functions. Period. No `&self` parameters that
  go unused. No `_bi: &BridgeInstance` underscore-elision. No "for symmetry
  with [other bridge]" arguments.

- The SDK wrapper layer (`bindings/{python,typescript,swift,kotlin}/`) is
  governed by per-language idiom. Each SDK's shape is a local choice, not a
  project-wide rule.

- ADR-048 §7 has been amended (2026-04-25) to reflect this. Do not re-litigate
  the universalism question without engaging with this lesson and the
  amendment commit.

- When in doubt, ask: "Is this constraint rooted in [this language/bridge]'s
  own semantics, or am I propagating it from elsewhere?" If propagating, stop.

## Related artifacts

- `.docs/adrs/ADR-048-scp-multi-instance.md` §1 (FFI layer rule), §7 (per-SDK
  idiom)
- `crates/scp-ffi/src/*` — PyO3 free functions
- `crates/scp-ffi/napi/src/context.rs` — NAPI free functions for pure helpers
- `crates/scp-ffi/uniffi/src/bridge.rs` — UniFFI free functions
- `bindings/python/scp_sdk/{context,discovery}.py` — Python module-level exports
- `bindings/kotlin/scp-kt/...` — Kotlin SCP methods (CoroutineBridge constraint)
- CLAUDE.md → artifact-flow invariant (plans → specs → ADRs → code)
