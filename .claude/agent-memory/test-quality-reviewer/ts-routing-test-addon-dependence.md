---
name: ts-routing-test-addon-dependence
description: TS SDK "routing" tests that depend on NAPI addon ABSENCE invert under CI (addon present) — must inject via __setBridgeForTests
metadata:
  type: feedback
---

TS SDK lifecycle wrappers (`SCP.identityRotateKey/Migrate/AddAgentKey/...`) route
through `getBridge(this)` which reads the `_nativeBridgeForScp` WeakMap, NOT the
`#native` handle. `mountMockScp()` populates only `#native` (via
`__constructScpWithNativeForTests`), so it does NOT mock what `getBridge` returns.

**Anti-pattern:** A "routes through the bridge (not a fabricated Scp method)" test
that mounts a mock SCP, builds a bare `{did, custodyType}` handle, calls the wrapper,
and asserts `threwTypeError === false`. This passes ONLY when the NAPI addon is
ABSENT (getBridge → loadNativeAddon throws a clean TransportError). When the addon is
PRESENT, getBridge returns the REAL bridge, which calls `handle.rotateKey()` on the
plain object → `undefined is not a function` → TypeError → the assertion the test
claims to guard against fires as a false positive.

**Why this matters for CI:** the `typescript-check` job in `.github/workflows/ci.yml`
BUILDS the addon with `allow_in_memory_custody` and wires `index.node` into
node_modules BEFORE `bun test`. So addon-present is the CI reality → these tests
HARD-FAIL CI. They only "pass" in an addon-absent dev checkout.

**Correct pattern (already used in bridge-trust.test.ts / trust.test.ts):**
inject the bridge with `__setBridgeForTests(scp, spyBridge)` (sets the
`_nativeBridgeForScp` WeakMap that `getBridge` actually reads), spy on the bridge
method, and assert it was called with `identity._rawHandle`. That tests routing
deterministically, addon-independent.

**Local gotcha:** a worktree's prebuilt `index.node` may be stale (built without
`allow_in_memory_custody`) → "Real NAPI" tests fail with SCP-IDENT-1008 locally even
though they'd pass in CI. Distinguish that artifact from the real routing-test defect.
Always check `node_modules/@limn-works/scp-ts-napi-*/index.node` presence + build date.
