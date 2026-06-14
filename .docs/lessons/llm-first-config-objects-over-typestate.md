# LLM-first construction — flat config objects, not typestate builders

## Principle

> The SDK's primary author is an LLM. First-pass LLM authorability — correct code
> from the type signature plus one example, with no compile-retry loop — is *the*
> design criterion for the public construction surface, not idiomatic-Rust-for-its-
> own-sake.

This is the **Agent-first API design** builder tenet (CLAUDE.md), enacted by
`.docs/standards/construction.md` and decided in **ADR-051 (Unified Construction
Pattern)**. The lesson here is the *why* — so future sessions do not re-derive it,
and do not drift back toward "but typestate is safer" or "but each language should
follow its own idiom."

## Why typestate builders are LLM-hostile

The `ApplicationNodeBuilder` (`scp-node`) used a typestate pattern: generic phantom
markers (`HasDomain`/`HasNoDomain`/`HasIdentity`), ~25 `.with_*` methods, and a
`.build()` terminator. For a *human* author with an IDE, this gives compile-time
guidance: the type system refuses `.build()` until required steps are present.

For an *LLM* author, the same mechanism is a trap:

1. **Phantom required-ordering is invisible.** The required steps are encoded in
   the type state, not in any field the model can read. The model cannot see, from
   the type signature, that `domain` is required-XOR-absent and `identity` is
   mandatory. It guesses, the compiler rejects, and it enters a **compile-retry
   loop** — exactly the failure the tenet measures against.
2. **It does not translate.** Four of five SDK languages (Python, TypeScript,
   Swift, Kotlin) have no typestate. A builder shape that only exists in Rust forces
   a *different* construction shape in every other binding — and the same operation
   then reads differently depending on language, which is itself an authorability
   tax (a model that learned the Python shape cannot transfer it to Swift).

## Why flat config objects are LLM-optimal

One flat config object + one entry function (`Thing::start(config)`):

- **Every parameter is a named field.** The model reads names, not positions or
  call ordering. There is nothing to "track."
- **Required choices are required fields** — usually enums (`Reach`,
  `IdentitySource`, `ContextCreation`). The compiler still enforces them (omitting a
  non-`Option` field is a compile error), but the requirement is *legible*: it is
  right there in the struct definition.
- **The shape is identical in all five languages** (Rust struct+enum ↔ Python
  dataclass+sum ↔ TS interface+discriminated-union ↔ Swift struct+assoc-enum ↔
  Kotlin data-class+sealed-class). The `StorageConfig` FFI mapping already proves
  this works across all four bridges.

The compile-time safety the typestate markers provided is **fully recovered** by
required enum fields — without the retry loop and without the per-language
divergence. Nothing is lost; legibility is gained.

## The two constraints that bound the pattern

"Flatten everything" is not literal. Two hard constraints shape the edges, and both
must be preserved:

1. **Providers stay typed enum-selectors — never `dyn`.** `KeyCustody`, `Storage`,
   and `DidMethod` use return-position `impl Trait` in trait (RPITIT) and are **not
   object-safe**: `Arc<dyn Storage>` does not compile. The config object carries
   providers as enum-selectors or concrete types, never trait objects. Boxing them
   would also put `async-trait` allocation on storage-read/sign hot paths,
   regressing the ADR-049 lock-free-read invariant. If a future session "simplifies"
   by reaching for `Arc<dyn Storage>`, the compiler will reject it — that rejection
   is the constraint, not a bug to work around.

2. **The `EncryptedStorage` seal stays a compile-time guarantee.** `EncryptedStorage`
   is a sealed trait; production construction requires `S: EncryptedStorage`, and the
   testing path is feature-gated to accept any `Storage`. This is "production cannot
   persist plaintext," enforced at compile time (not by convention). The unified
   pattern preserves it as the `start` / `start_for_testing` **trait-bound split** —
   the *one* allowed exception to "one greppable constructor" (M5). It is backed by a
   structural test that the unencrypted path is unreachable from the production
   constructor. Demoting this seal to a runtime check to get a single unconditional
   `start()` is explicitly rejected (ADR-051 Rejected Alternatives): flatness never
   buys down a compile-time security guarantee.

## How to apply

- New developer-facing construction entry point? One flat config object, one entry
  function, identical across all five languages. Follow `construction.md` M1–M5.
- Tempted to reach for a `*Builder` or a typestate marker "for safety"? Encode the
  requirement as a required enum field instead. Typestate the model can't track is a
  defect, not a safety feature.
- Tempted to give one language a special construction shape "because it's idiomatic"?
  Don't — the shape is identical across bindings by design. (This does **not** contradict
  the per-SDK idiom lesson: that lesson is about *internal FFI helper* placement and
  *wrapper-layer* method shape, not about diverging the construction surface. See
  `per-sdk-idiom-not-cross-language-dogma.md`.)
- Tempted to flatten the provider generics with `dyn`, or to collapse the
  `start`/`start_for_testing` split into one runtime-checked `start()`? Both are
  rejected for the reasons above.

## Related artifacts

- **ADR-051 (Unified Construction Pattern)** — `.docs/adrs/phase-2.md`. The decision,
  rationale, and full rejected-alternatives list.
- **`.docs/standards/construction.md`** — the enforced standard (M1–M5, target
  shapes, five-language equivalence).
- **CLAUDE.md → Agent-first API design** (builder tenet) — the principle.
- **ADR-032 §AC-6** — the superseded `ApplicationNode` builder mandate.
- **ADR-049 (lock-free-read invariant)** — why providers stay enum-selectors.
- **architecture.md §2.5** — injection-through-initializers; the config object is the
  initializer, preserved.
- **`per-sdk-idiom-not-cross-language-dogma.md`** — the complementary lesson on where
  per-language divergence *is* correct (FFI helpers, wrapper method shape) vs. where
  it is not (the construction surface).
