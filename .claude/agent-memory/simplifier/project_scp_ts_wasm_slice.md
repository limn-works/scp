---
name: scp-ts-wasm-slice
description: ADR-057 Slice 3 @limn-works/scp-ts-wasm packaging — shared-core via tsconfig path alias, not the bun workspace
metadata:
  type: project
---

`@limn-works/scp-ts-wasm` (bindings/typescript-wasm, ADR-057 Slice 3, PR #2183) single-sources its cross-SDK error hierarchy from the sibling `@limn-works/scp-ts` via a **tsconfig `paths` alias** `@scp-core/errors` → `../typescript/src/errors` (relative FS path), bundled in by tsup/esbuild. No package-level `import` of `@limn-works/scp-ts` exists anywhere in src/tests/scripts.

**Why:** The `bindings/package.json` bun workspace root (new in this PR) is justified in its own description by "so scp-ts-wasm can take a workspace-source dependency on scp-ts" — but that devDep was removed in the same PR (commit 3c8eb2b7c). CI runs `bun install` inside `bindings/typescript-wasm`, not at `bindings/`. Neither member has a `workspace:` protocol dep. So the workspace root is non-load-bearing for the source-share.

**How to apply:** If reviewing/refactoring this area, the workspace root is a removal candidate (or needs its description corrected to the real reason). The load-bearing link is the tsconfig path alias — that must survive any change. Release-profile invariant (ADR-057 Prereq-4) lives in `scripts/wasm-build.ts` `buildArgs()`; the `--release` build is what compiles out openmls's decrypt `debug_assert!`.
