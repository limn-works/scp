# dependency-safety-reviewer memory

- [CI aggregation gate pattern](ci-aggregation-gate-pattern.md) — new ci.yml jobs must be added to the roll-up's `needs:` + `results` array or they run non-blocking (a gate that doesn't gate).
- [Worktree vs main-repo cwd trap](worktree-cwd-trap.md) — Bash cwd resets between calls; `cd`-ing to the main repo path reviews the WRONG branch. Operate in the named worktree path; verify `git rev-parse --abbrev-ref HEAD`.
- [scp-ts-wasm pkg vetted](scp-ts-wasm-pkg.md) — @limn-works/scp-ts-wasm (ADR-057, PR #2183) APPROVED. Vetted deps, publish hygiene, CI gate + path-filter closure.
- [Optional SDK tier pattern](optional-sdk-tier-pattern.md) — add SDK column to `sdks` iteration set but NOT `expected_sdks` = subset tier, additive, non-weakening enforcement edit.
- [Scaffold internal file: dep + CI gate](scaffold-internal-file-dep-ci.md) — ADR-057 #1951 vetted: `scaffolds/typescript-web` depends on unpublished `@limn-works/scp-ts-wasm` via `file:`; build dep dist/ first, path-filter dep closure, wire into `ci` needs+roll-up.
