---
name: ts-sdk-failclosed-parity
description: TypeScript SDK fail-closed/parity audit — the test seam is genuinely tree-shaken out of the published bundle, but check-sdk-coverage.py accepts a TYPE name as proof of a runtime capability.
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` @ 6f4ba65ff.

**Primary defense sound — the test seam is tree-shaken out of the published bundle.**
`__setBridgeForTests` / `assertTestEnvironment` / `isTestEnvironment` are not re-exported from `index.ts`;
with `tsup entry=[index.ts]` and `splitting: false`, esbuild removes all three (grep count 0 in the bundle).
Only `_evaluateTestEnv` survives internally and is not in the export clause. `files: ["dist/"]` excludes
`src/`, and the `exports` map only declares `"."`, so deep subpath imports throw
`ERR_PACKAGE_PATH_NOT_EXPORTED`. The runtime test-guard is defense-in-depth, not the boundary.

**UCAN regex anchoring sound.** `/^\[SCP-PERM-\d+\]/` — a leading newline or space defeats `^`, so the
message is rethrown (fail-closed). `extractCore` marker / em-dash injection is inert (`indexOf` finds the
FIRST marker; the prefix is fixed by Rust). Misclassifying as UCAN always lands `unknown`, which leaves all
six `CapabilityValidation` fields false.

**Residual (low).** `BUN_TEST=0` and `BUN_TEST=false` leave the seam open (the guard checks `length > 0`
only). Moot post-bundle since the seam is unreachable; a falsey-value guard would still be correct.

**FINDING — gate soundness: `check-sdk-coverage.py` accepts a TYPE name as proof of runtime capability.**
`_extract_typescript_symbols` folds interface and type-alias names into the same set as runtime functions,
and `_to_pascal(op)` then matches a type. Proven: `Governance/member_role` matches the `MemberRole` *type*,
not `SCP.contextMemberRole`; `MCP/connect_client` matches the `McpClient` *interface* (the alias also lists
the deleted `connectMcp`; the real impls are `mcpClientConnectStdio`/`Sse`). The gate stays green after
deleting every runtime implementation as long as a same-named type survives. 2 of 184 TS ops affected —
a softer re-introduction of the suffix-match gap the PR claims to have closed.

**Note:** `scripts/check-sdk-coverage.py` is in CLAUDE.md's enforcement allowlist — report this, never
self-edit the file.
