# Contributing to SCP

Guidelines for contributing to the Shared Context Protocol.

---

## Getting Started

1. **Set up your environment.** Follow [GETTING-STARTED.md](GETTING-STARTED.md) for prerequisites, toolchain setup (mise), and building the workspace.
2. **Run the tests.** Follow [TESTING.md](TESTING.md) for running tests across all languages, including required environment variables and CI feature flags.

---

## Branch Naming

```
<type>/<short-description>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`. Include source IDs (story, issue number) when available.

Examples:

```
feat/user-profiles
fix/mls-epoch-rollover
refactor/transport-trait
```

Full conventions: [`.docs/standards/conventions.md`](.docs/standards/conventions.md).

---

## Commit Conventions

SCP uses [Conventional Commits](https://www.conventionalcommits.org/).

```
<type>(<scope>): <subject>

[optional body]
```

- **Types:** `feat`, `fix`, `refactor`, `docs`, `test`, `chore`
- **Scope:** the crate, module, or binding affected (e.g., `scp-core`, `python`, `transport`)
- **Subject:** imperative mood, lowercase, no period, under 50 characters
- Reference artifacts and source IDs in the body when applicable (ADRs, spec sections, story IDs)

Each commit must be atomic (one logical concern), independently revertable, and must build and pass tests. Do not mix refactoring with feature work.

---

## Pull Requests

- **Title:** conventional commit format (e.g., `feat(transport): streaming BlobStore API`)
- **Description:** describe scope, impact, and any linked issues or stories
- **Closing keywords:** use `closes #42`, `fixes #42`, etc. to auto-close issues on merge
- **Review:** all PRs require review. Reviewers check correctness, spec conformance, and completeness. Review findings are acted on, not acknowledged and ignored.
- **CI must pass** before merge (see [CI](#ci) below)
- **Linear history:** keep history clean and linear

---

## Code Standards

Each language has its own standards file. Read and follow the relevant one before writing code.

| Language | Standards | Key rules |
|----------|-----------|-----------|
| Rust | [`.docs/standards/rust.md`](.docs/standards/rust.md) | `#![forbid(unsafe_code)]`, no `unwrap()`/`expect()`/`panic!()` in lib code, `thiserror` for errors, `tracing` instead of `println!()`, `tokio::sync::Mutex` not `std::sync::Mutex` |
| Python | [`.docs/standards/python.md`](.docs/standards/python.md) | ruff for lint and format |
| TypeScript | [`.docs/standards/typescript.md`](.docs/standards/typescript.md) | biome for lint and format, bun only (never npm/npx) |
| Kotlin | [`.docs/standards/kotlin.md`](.docs/standards/kotlin.md) | detekt for lint |
| All | [`.docs/standards/sdk-common.md`](.docs/standards/sdk-common.md) | Shared error hierarchy, async patterns, stub policy, resource lifecycle |
| All | [`.docs/standards/conventions.md`](.docs/standards/conventions.md) | File naming, git, import order, code organization |

---

## Stub Policy

Code that does not fully implement its documented contract is a stub. Stubs are tracked and enforced:

1. **Every stub must reference a PRD story ID** (e.g., `// Stub -- see SCP-217`).
2. **No silent stubs.** A function returning a placeholder without documenting the gap is a bug.
3. **Stories marked "done" must have zero stubs** against their acceptance criteria.

Enforcement is mechanical: Rust (`clippy::todo/unimplemented = "deny"`), Kotlin (detekt `ForbiddenComment`), Python (ruff `FIX`), Swift (SwiftLint `todo`), TypeScript (ESLint `no-warning-comments`).

Full policy: [`.docs/standards/sdk-common.md`](.docs/standards/sdk-common.md), section "Stub and Placeholder Policy".

---

## CI

All CI checks must pass before a PR can merge. CI is defined in `.github/workflows/ci.yml`.

**What must pass (Tier 1 -- every PR push):**

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing -- -D warnings`
- `cargo nextest run --workspace --features scp-ffi-uniffi/allow_in_memory_custody,scp-core/testing`
- `cargo test --workspace --doc`
- `cargo deny check`
- Python: `ruff format --check .` + `ruff check .` + `pytest tests/ -v`
- TypeScript: `bun run check` + `bun run lint` + `bun test`
- Kotlin: `./gradlew test`

**Always run CI checks locally before pushing.** See [TESTING.md](TESTING.md) for full commands, environment setup, and details on Tier 2 (merge gate) and Tier 3 (nightly) checks.

---

## Documentation

**When to add docs:**

- Public APIs and their contracts
- Non-obvious architectural decisions (use an ADR)
- Complex algorithms or business logic
- Module boundaries and responsibilities
- Anything requiring "learning" to use correctly

**When to skip:** obvious getters/setters, standard CRUD, self-explanatory one-liners, code following established patterns.

Use the language's standard doc-comment syntax. Focus on **why** and **how to use**, not **what**.

Full standards: [`.docs/standards/documentation.md`](.docs/standards/documentation.md).

### Architecture Decision Records (ADRs)

Significant architectural decisions are recorded as ADRs in [`.docs/adrs/`](.docs/adrs/). When proposing a change that affects protocol design, crate boundaries, or cross-cutting concerns, write an ADR first. ADRs document the decision, rationale, and rejected alternatives. Code references ADRs; ADRs do not reference code.

### Artifact flow

The flow is strictly one-way: **plans -> specs -> ADRs -> stories -> source code.** Upstream artifacts govern downstream artifacts. If code reveals that a spec is wrong, fix the spec first, then update downstream artifacts, then resume implementation.
