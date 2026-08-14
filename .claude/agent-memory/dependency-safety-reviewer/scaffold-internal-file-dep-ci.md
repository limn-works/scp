---
name: scaffold-internal-file-dep-ci
description: Vetted pattern for repo-internal scaffolds depending on an unpublished workspace package via a file: link, and how CI must gate them (ADR-057 #1951).
metadata:
  type: reference
---

# Repo-internal scaffold `file:` dependency + CI gate (ADR-057, PR #1951)

`scaffolds/typescript-web/` (browser scaffold) depends on unpublished
`@limn-works/scp-ts-wasm` via `"@limn-works/scp-ts-wasm": "file:../../bindings/typescript-wasm"`.
Reviewed 2026-08-01 — sound. Tag: dependency-safety.

**Why the pattern is safe here:**
- Package name in `file:` link must match the depended package's `package.json` `name`. Confirmed match.
- The `file:` target resolves against `dist/` (package `main`/`module`/`types` → `./dist/...`), so the dep's `dist/` must be BUILT FIRST. bun resolves `file:` by path; the `0.1.0` version is nominal (no drift risk).
- Scaffold is `"private": true` → cannot accidentally publish. Only prod dep is the internal file: package; no third-party runtime deps (minimal supply-chain surface). devDeps: biome pinned exact, typescript/vite caret (acceptable for a scaffold devtool).
- No committed `bun.lock` — consistent with repo convention (NO bun.lock committed anywhere; all `bindings/*/.gitignore` ignore it).

**CI gate requirements (to actually gate, mirror `typescript-wasm-check`):**
1. Path filter closure must include BOTH `scaffolds/<name>/**` AND the dep `bindings/typescript-wasm/**`, so a dep-surface change re-runs the scaffold job.
2. Job must build the dep FIRST (`cd bindings/typescript-wasm && bun install && bun run build`) before `bun install` + check/lint/build in the scaffold — else the file: link resolves against a missing `dist/`.
3. Wire into the required `ci` aggregation in TWO places: the `needs:` list AND the `results[]` roll-up array. Roll-up treats only `failure`/`cancelled` as fatal; `skipped` (path-filter false) passes — correct.
4. Same pinned toolchain as the dep's job: `wasm-pack@0.14.0`, setup-bun@v2, rust stable + wasm32 target, rust-cache, free-disk-space step (dep build compiles Rust).

**Known shared scope boundary (not a new gap):** neither `typescript-wasm-check`
nor the scaffold job path-filters on `crates/**`, so a pure Rust change that alters
the wasm surface won't trigger either. Pre-existing, consistent — flag only if the
wasm job's filter is ever widened.
