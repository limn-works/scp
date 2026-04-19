---
name: SCP Phase 4 PR 1 SDK wrappers landed (#1549, ADR-048)
description: SCP class + deprecation scaffold landed across Python/TS/Swift/Kotlin SDKs in commit 0040d67d9 on refactor/scp-multi-instance
type: project
---

Commit `0040d67d9` on `refactor/scp-multi-instance` ships the SDK-level `SCP` class for all 4 language SDKs, plus a deprecation scaffold on the default-instance free-function façade.

**Why:** #1549 Phase 4 PR 1 needs the SDK wrappers to make the multi-instance `BridgeInstance` refactor reachable from user code. The Rust per-bridge `SCP` classes (PyO3 `PyScp`, napi `Scp`, UniFFI `Scp`) landed in prior commits (c92d19a3f, 58c2850df, etc.); this commit wraps them into SDK-idiomatic `SCP` classes and annotates the existing free-function façade as deprecated.

**How to apply:** When Phase 4 PR 2 lands (migrating remaining singletons + migrating methods onto `SCP`), the free-function façade stays but gets removed two release cycles after Phase 4 merge per ADR-048. The existing free-function calls delegate to `SCP.default()` under the hood.

**Notable state:**
- Swift `Internal/ScpBindings.swift` is a committed artifact generated before Phase 4 PR 1 FFI changes — hosted CI regenerates it before `swift build`. Don't try to `swift build` locally unless you've regenerated.
- Kotlin UniFFI bindings (`src/main/kotlin/works/limn/scp/internal/`) are gitignored and regenerated at build time via `./gradlew :scp-kt:generateUniffiBindings`. Baseline Kotlin compile fails without regeneration — this predates my changes.
- TypeScript `src/index.d.ts` is a hand-written declaration file that tsup bundles verbatim. Must be updated when adding new exports to surface type information; don't rely on tsup's auto-DTS generation alone.
- TS tests in `bindings/typescript/tests/lifecycle.test.ts` have 2 pre-existing failures locally because the platform napi binary isn't published to `@limn-works/scp-ts-napi-darwin-arm64`. Not caused by this commit.
