# Contributing

## Before You Start

Read the relevant coding standard in `.docs/standards/` for your language:

- `rust.md`, `python.md`, `typescript.md`, `kotlin.md`, `swift.md`
- `sdk-common.md` -- cross-language error hierarchy, async patterns, naming
- `conventions.md` -- git conventions, file naming, import order

Read `.docs/architecture.md` for system overview and `.docs/specs/` for protocol details.

## Development Workflow

1. **Read the provenance chain.** Every change traces to a spec, ADR, or story. Read the actual artifacts before writing code.
2. **Use a worktree** for non-trivial changes:
   ```bash
   git worktree add .worktrees/<branch-name> -b <type>/<description>
   ```
3. **Write code.** Follow the standards for your language. No stubs, no partial implementations.
4. **Run a quick local check** before pushing: `cargo fmt --all`, `cargo clippy` with the CI feature set scoped to the crates your change touches, the tests of those crates, and the gate scripts your change affects. For example, a change to `scp-runtime` alone runs:
   ```bash
   cargo fmt --all
   cargo clippy -p scp-runtime --all-targets \
     --features scp-runtime/testing,scp-runtime/saga-witness-test-mint \
     -- -D warnings
   cargo nextest run -p scp-runtime \
     --features scp-runtime/testing,scp-runtime/saga-witness-test-mint
   ```
5. **Commit atomically** with conventional commit messages.
6. **Push and open a PR.** CI runs the full gate set on the pushed head. Fix every failing job before the PR merges.

## Commits

Format: `<type>(<scope>): <subject>`

- **Types**: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`
- **Scope**: crate or module affected (`scp-core`, `python`, `transport`)
- **Subject**: imperative mood, lowercase, no period

```
feat(scp-core): add context garbage collection
fix(transport): handle relay disconnection during subscribe
docs(specs): add OuterEnvelope wire format table to SS9.5
```

Each commit should be independently revertible. Never bundle unrelated changes.

## Pull Requests

- **Title**: short, descriptive, under 70 characters
- **Description**: what changed, why, and linked issues/stories (use `closes #N`)
- **CI must pass** before merge
- **Address all review feedback** with actual fixes, not acknowledgments

## Code Style

### Rust

- `clippy::todo` and `clippy::unimplemented` are denied -- no stubs
- `clippy::expect_used` is denied -- use `.map_err()?` instead
- `clippy::unwrap_used` is denied in library code
- No `#[allow(clippy::...)]` for bad-practice lints -- refactor instead
- `unsafe` is forbidden (`#![forbid(unsafe_code)]`)

### Python

- Python 3.12, which mise installs, for development (never system python3, which is Xcode 3.9); the SDK's supported floor is CPython 3.10, and the release wheels cover CPython 3.10-3.13
- async-first with sync wrappers where needed
- Type hints on all public APIs

### TypeScript

- Bun only (never npm/npx)
- Strict TypeScript (`noExplicitAny`, no non-null assertions)
- Biome for both lint and format

### Kotlin

- Kotlin 2.x, JDK 17 via mise (`eval "$(mise env)"` before Gradle commands)
- Coroutine-first, JUnit 5 for tests

### Swift

- Swift 6.2, SwiftLint + SwiftFormat both required
- No force unwraps, actor-based concurrency

## Stubs

Every stub must reference a PRD story: `// Stub -- see SCP-NNN`. Stories marked "done" must have zero stubs. CI enforces this across all languages.

## Artifact Flow

Specs govern code, never the reverse:

```
plans -> specs -> ADRs -> stories -> source code
```

If code reveals a spec is wrong, **stop writing code**. Fix the spec first, then update downstream artifacts, then resume implementation.

## PRD Stories

Before creating or editing stories in `.docs/prds/`:

1. Read `.docs/standards/prd.md` in full
2. Every field required, every acceptance criterion machine-verifiable
3. Run `python3.12 scripts/validate-prd.py` before committing
