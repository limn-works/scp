# Per-SDK Idiom: One Language's Constraints Stay in That Language

> "I don't want optimizations or constraints for one language to dictate what
> happens in another's SDK. That's bad dogma."
> — Alec, 2026-04-25

SCP ships four language SDKs over three FFI bridges, and each binding tool imposes its own
constraints. A shape that one binding tool forces stays local to that language.

**What triggered the rule**: §7 of ADR-048, SCP multi-instance, first claimed "one class, one
surface, one entry point" across all SDKs. The shape came from Kotlin, whose `CoroutineBridge`
needs an object-bound coroutine scope; Python and TypeScript inherited it without their own
justification, and Swift could not implement it.

## Where each rule lives

- The FFI Rust layer (`crates/scp-ffi/*/src/*`) follows ADR-048 §1: pure protocol helpers
  stay free functions, with no unused `&self`, no `_bi: &BridgeInstance`, and no argument
  added "for symmetry with another bridge".
- The SDK wrapper layer (`bindings/*/`) follows ADR-048 §7, whose table gives each language's
  shape.
- The construction surface is the exception: `.docs/standards/construction.md` requires one
  flat config object with an identical shape in every binding.

## Guidance

- When a cross-bridge audit reports an operation "missing in X but present in Y", do not take
  Y as the reference; both may be wrong. Read ADR-048 §1 and §7 first.
- An audit script measures code state, not intent. Letting its view of the code redefine the
  architecture reverses the artifact flow.
- Review agents agree in unison when a prompt leads them to one section. To make them
  arbitrate between ADR-048 §1 and §7, name the conflict in the prompt.
