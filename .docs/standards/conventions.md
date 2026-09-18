# Conventions

Naming, structure, and git conventions for all SCP development. Language-specific casing and file naming rules are in `.docs/scaffold/shared.md`, which carries the cross-language naming table and the per-language casing table, and in each language's standards file.

## File Naming Per Language

| Language | Source files | Test files | Modules/Packages |
|----------|-------------|------------|-------------------|
| Rust | `snake_case.rs` | `snake_case.rs` (in `tests/` or `#[cfg(test)]`) | `snake_case/` |
| Python | `snake_case.py` | `test_snake_case.py` | `snake_case/` |
| TypeScript | `kebab-case.ts` | `kebab-case.test.ts` | `kebab-case/` |
| Swift | `PascalCase.swift` | `PascalCaseTests.swift` | `PascalCase/` |
| Kotlin | `PascalCase.kt` | `PascalCaseTest.kt` | `lowercase/` |
| Go | `snake_case.go` | `snake_case_test.go` | `lowercase/` |
| C# | `PascalCase.cs` | `PascalCaseTests.cs` | `PascalCase/` |
| Java | `PascalCase.java` | `PascalCaseTest.java` | `lowercase/` |

### General rules

- One primary type per file, file named after the type (adapted to language casing)
- Tests adjacent to source or in dedicated `tests/` directory per language convention
- Extensions/mixins: `Type+Extension` pattern where supported (Swift, Kotlin)
- Configuration files: lowercase with dots (`pyproject.toml`, `Cargo.toml`, `package.json`)

## Folder Structure

- Group by feature/module first, then by type within module
- Shared code lives in `core/`, `common/`, or `shared/` directories
- Feature-specific code lives in `features/` or `modules/` directories
- Language bindings follow the monorepo topology defined in `sdk-common.md`

## Casing Rules

See `.docs/scaffold/shared.md` for the full cross-language casing table. Summary of universal rules:

- **Type names** are `PascalCase` in every language
- **Constants** are `SCREAMING_SNAKE_CASE` in most languages (except Swift: `camelCase`, C#: `PascalCase`)
- **Acronyms** follow language convention: `URLString` vs `urlString` — see per-language standards
- **A name-bound enumeration's variants take the spelling the specification gives them, verbatim, in every language.** `09-security-model.md` §9.7.4.2's definitions state the criterion that decides which enumerations the rule reaches, and this table is where the mapping lives.

<!-- scp:include id="name-binding-criterion" from=".docs/specs/09-security-model.md" -->**An enumeration this design defines is name-bound — its type name and every variant name identical in every SDK binding — where a binding surfaces it to callers or where it serializes on the wire, and a name is bound as the spec spells it, PascalCase, which every binding carries verbatim.** No binding recases a variant and no rule splits one on word boundaries, so a shared conformance fixture comparing a variant across languages compares one string.<!-- scp:end id="name-binding-criterion" -->

**Each row below states the criterion in full — the spec's spelling, verbatim, which is PascalCase — rather than the spelling clause alone**, because a row reading "the spec's spelling, verbatim" beside a spec sentence asserting PascalCase left a binding author two instructions and no test for which governs.

| Language | Enum variant spelling | Example, from the spec's `WitnessRead` |
|---|---|---|
| Rust | the spec's spelling, verbatim: PascalCase | `HeadProvenance::WitnessRead` |
| Python | the spec's spelling, verbatim: PascalCase, not `SCREAMING_SNAKE_CASE` | `HeadProvenance.WitnessRead` |
| TypeScript | the spec's spelling, verbatim: PascalCase | `HeadProvenance.WitnessRead` |
| Swift | the spec's spelling, verbatim: PascalCase, not `lowerCamelCase` | `HeadProvenance.WitnessRead` |
| Kotlin | the spec's spelling, verbatim: PascalCase | `HeadProvenance.WitnessRead` |
| Every other language | the spec's spelling, verbatim: PascalCase | `HeadProvenance.WitnessRead` |

**No binding recases a variant, and no rule splits one on word boundaries**, so a fixture comparing a variant across languages compares one string. The rule overrides a language's own enum convention wherever the two differ, Python's `SCREAMING_SNAKE_CASE` and Swift's `lowerCamelCase` included: a split-and-recase rule spells `Fido2Token`, `EcdsaP256Sha256`, `Rank1Terminal`, `Rank2Terminal` and `Rank3Pending` two or three defensible ways each, which is the choice a binding author must not be left to make. The rule reaches every language, so a language this table does not name needs no row of its own

## Git Commits

**Format:**
```
<type>(<scope>): <subject>

[optional body]
```

**Types:**
- `feat` — New feature
- `fix` — Bug fix
- `refactor` — Code change that neither fixes nor adds
- `docs` — Documentation only
- `test` — Adding or updating tests
- `chore` — Maintenance, dependencies, config

**Scope:** Module, crate, or language binding affected (e.g., `scp-core`, `python`, `transport`).

**Subject:**
- Imperative mood ("add" not "added")
- Lowercase, no period
- Under 50 characters

**Scope guidelines:**
- **Atomic commits**: Each commit is one logical concern that can be independently reverted
- Each commit should build and pass tests
- Don't mix refactoring with feature work
- When a task produces changes across multiple concerns, break them into structured commits ordered by dependency (foundations first, then layers that build on them)

## Branch Naming

```
<type>/<short-description>
```

**Examples:**
```
feat/user-profiles
fix/mls-epoch-rollover
refactor/transport-trait
feat/python-sdk
```

## Import/Dependency Order

All languages follow the same grouping order, separated by blank lines:

1. Standard library / language built-ins
2. Platform/framework imports
3. Third-party dependencies
4. Local/project modules

See per-language standards files for specific syntax and examples.

## Code Organization Within Files

Universal ordering within a file:

1. Type/class declaration
2. Properties/fields (public, then private)
3. Initialization/constructors
4. Public methods
5. Private methods
6. Protocol/interface conformances (extensions where supported)

Language-specific patterns (e.g., Swift `MARK` comments, Rust `mod` blocks, Python `__all__`) are in per-language standards.

## Method naming: per-identity capability axis (Rust core)

Per-identity methods in `scp-runtime`'s `context/supervisor` layer encode their **capability axis** in the name, so a mis-placed operation reads as wrong on sight (ADR-049 §5 placement invariant):

- **`my_*` prefix** = actor-internal own-identity accessor. It reaches only the identity that owns the calling actor — e.g. `my_wrapping_public_key`, `my_key_package_store`. This holds even when the return is public data; the prefix marks caller-isolation, not data-sensitivity.
- **Plain verbs** = bridge-external node bootstraps. Take a bare identifier, with local-identity custody enforced at the FFI bridge — e.g. `create_context`, `spawn_actor_from_welcome`, `reserve_key_package`.

So a `my_`-prefixed method taking an identifier, or a plain-verb method reaching the owning identity, is a naming/axis violation. See `.docs/lessons/per-identity-op-placement-two-axes.md`.
