# CI Workflows

Overview of all GitHub Actions workflows in this repository.

## Workflow Map

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| [`ci.yml`](ci.yml) | Push to `main`, PRs to `main` | Lint, build, and test the Rust workspace |
| [`ci-fix.yml`](ci-fix.yml) | After `CI` workflow completes | Auto-fix CI failures (formatting, etc.) |
| [`docs.yml`](docs.yml) | Release tags (`scp-core@*`), PRs touching `bindings/` or `crates/scp-core/src/` or `crates/scp-ffi/` | Generate and publish SDK API reference docs |
| [`build-matrix.yml`](build-matrix.yml) | Release tags (`scp-*@*`), called by `release.yml` | Build platform-specific release artifacts for all SDKs |
| [`release.yml`](release.yml) | Release tags (`scp-core@*`) | 7-step release pipeline: conformance, changelog, build, sign, publish |
| [`pr-review.yml`](pr-review.yml) | PRs touching `crates/` or `Cargo.*` | Automated PR review |
| [`spec-drift.yml`](spec-drift.yml) | PRs touching `crates/`, `Cargo.*`, or `bindings/` | Detect drift between specs and implementation |
| [`artifact-review.yml`](artifact-review.yml) | Daily at 3am ET, manual | Health review of project artifacts |
| [`issue-triage.yml`](issue-triage.yml) | New issues opened | Auto-triage and label new issues |
| [`issue-dedup.yml`](issue-dedup.yml) | New issues opened | Detect duplicate issues |
| [`claude.yml`](claude.yml) | Issue comments, PR review comments, issues opened/assigned | Claude Code integration for automated responses |

## SDK Documentation Generation

**Story:** SCP-139 | **Source:** `.docs/scaffold/shared.md` "SDK Documentation Requirements", `.docs/specs/21-documentation.md` &sect;21.10

API reference docs are generated for all 5 language SDKs. Most generators run from source alone in `docs.yml`. Swift DocC is the exception -- it requires a compiled binary and runs in `build-matrix.yml` instead.

### Where each language's docs are generated

| Language | Generator | Workflow | Job | Artifact | Runner |
|----------|-----------|----------|-----|----------|--------|
| Rust | rustdoc | `docs.yml` | `rust-docs` | `docs-rust` | `ubuntu-latest` |
| Python | Sphinx (autodoc + napoleon) | `docs.yml` | `python-docs` | `docs-python` | `ubuntu-latest` |
| TypeScript | typedoc | `docs.yml` | `typescript-docs` | `docs-typescript` | `ubuntu-latest` |
| Swift | DocC | `build-matrix.yml` | `swift-xcframework` | `docs-swift` | `macos-26` |
| Kotlin | Dokka | `docs.yml` | `kotlin-docs` | `docs-kotlin` | `ubuntu-latest` |

### Why Swift DocC lives in build-matrix.yml

DocC generates documentation from a resolved Swift package. The `SCP` package depends on `ScpFFI`, a binary target backed by `ScpFFI.xcframework`. That XCFramework is built by cross-compiling Rust for all Apple targets (macOS, iOS, iOS Simulator) -- it is not checked into the repo.

The `swift-xcframework` job in `build-matrix.yml` already performs this full cross-compilation. DocC runs as a post-step after the XCFramework is built, when SPM can resolve successfully. Running DocC standalone in `docs.yml` would require duplicating the entire Rust cross-compilation pipeline.

The `docs-swift` artifact name is the same regardless of which workflow produces it. The `publish-docs` job in `docs.yml` downloads by pattern (`docs-*`), so Swift docs are included when both workflows run on the same release tag. On PRs, Swift docs are simply absent (tolerated via `if-no-files-found: ignore`).

### Runner pinning

The `swift-xcframework` job and (formerly) the `swift-docs` job are pinned to `macos-26`. This is required because `Package.swift` declares `swift-tools-version: 6.2`, which needs Swift 6.2. The `macos-latest` runner (macOS 15) only ships Swift 6.1.

### Publishing

The `publish-docs` job in `docs.yml` runs only on release tags (`scp-core@*`). It:

1. Downloads all `docs-*` artifacts from the workflow run
2. Generates an index page linking to each language's docs
3. Deploys to GitHub Pages

Swift docs (`docs-swift`) come from `build-matrix.yml` running on the same tag. Because `publish-docs` downloads by artifact name pattern, cross-workflow artifacts from the same commit are collected automatically.

### Local generation

Most doc generators can be run locally:

```bash
# Rust
cargo doc --workspace --no-deps --document-private-items

# Python (requires sphinx, furo, sphinx-autodoc-typehints)
cd bindings/python && sphinx-build -b html docs docs/_build/html

# TypeScript (requires typedoc, typescript)
cd bindings/typescript && npx typedoc

# Swift (requires ScpFFI.xcframework to be present)
cd bindings/swift && swift package generate-documentation --target SCP --output-path docs

# Kotlin (requires Gradle project)
cd bindings/kotlin && ./gradlew dokkaHtml
```

For Swift, you must first build the XCFramework (see `bindings/swift/build-xcframework.sh`) or download it from a CI artifact.

## Build Matrix

**Story:** SCP-136 | **Source:** `.docs/scaffold/shared.md` "Build matrix"

The `build-matrix.yml` workflow builds release artifacts for all SDK targets:

| Job | What it builds | Platforms |
|-----|---------------|-----------|
| `rust` | `libscp_core`, `libscp_ffi` | Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64) |
| `python-wheels` | maturin-built wheels | Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64) |
| `python-sdist` | Source distribution | Platform-independent |
| `typescript-wasm` | wasm-pack WASM bundle | Platform-independent |
| `typescript-napi` | napi-rs native addon | Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64) |
| `swift-xcframework` | XCFramework + DocC docs | macOS universal2, iOS arm64, iOS Simulator |
| `kotlin-aar` | AAR with bundled `.so` | Android (arm64, armv7, x86_64, x86) |
| `cbindgen` | C ABI shared library | Linux, macOS, Windows (same as Rust) |
| `aggregate` | Combined release bundle | All of the above |

## Release Pipeline

**Source:** `.docs/scaffold/shared.md` "Release Pipeline"

The `release.yml` workflow enforces a 7-step checklist:

1. Conformance tests pass (100% -- hard gate)
2. Changelog updated with version bump
3. Version tags created (`scp-core@{version}`, per-SDK tags)
4. Build all artifacts via `build-matrix.yml` (workflow_call)
5. Sign artifacts per platform requirements
6. Publish to registries (crates.io, PyPI, npm, SPM, Maven Central)
7. GitHub Release with binary attachments
