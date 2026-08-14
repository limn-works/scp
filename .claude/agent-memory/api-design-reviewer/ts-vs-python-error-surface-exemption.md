---
name: ts-vs-python-error-surface-exemption
description: RESOLVED in PR #1867 @614f0eb17 — TS no longer exempts ucanValidate/eventLogQuery; both now wrap mapBridgeError, classification moved to prefix-regex. Historical record below.
metadata:
  type: project
---

**RESOLVED (PR #1867, commit `614f0eb17`, 2026-06-22):** the exemption described below was the recommended fix and was applied. `ucanValidate`/`eventLogQuery` now wrap `mapBridgeError` (scp.ts:2390, 2461); `evaluateLayer1`/`evaluateTrust` classify on the preserved `[SCP-...]` prefix in `.message` and re-raise PERM-3030 by prefix-regex (trust.ts:478-485, 576). 203/203 wrapped, parity with Python restored. Original analysis kept below for provenance.

---


The TypeScript SDK's public `SCP` class (exported from `index.ts`) wraps all but
two methods in `mapBridgeError` (→ typed `ScpError` subclasses). The two
exemptions are `ucanValidate` and `eventLogQuery` (scp.ts:2372, 2455), carved out
so `evaluateTrust` (trust.ts) can classify the raw `[SCP-...]` code prefix and
re-throw PERM-3030 by object identity.

**Why this is an API-design concern:** Python's `ucan_validate`/`event_log_query`
DO surface typed errors — the PyO3 bridge raises `bridge.UcanError`/`ContextError`
natively, and Python's `evaluate_trust` catches them as typed (trust.py:763, 801).
So the same two public operations have *different error contracts* in TS vs Python,
violating the "identical shape across all language bindings" tenet (CLAUDE.md
agent-first API design).

**The exemption is broader than required.** `ScpError` preserves `.message`
(super(message)) and `.code`, so trust.ts's regex-over-message classification works
on typed errors too. Only the `expect(thrown).toBe(raw)` by-identity re-throw needs
rawness — and that can be done by re-throwing the typed error by identity
(`if (err instanceof ScpError && err.code === "SCP-PERM-3030") throw err`).

**How to apply:** When reviewing TS SDK error-handling changes, the superior design
is to classify over the typed error and wrap uniformly (203/203), eliminating the
carve-out. See [[cross-sdk-shape-parity]] and [[ts-python-trust-parity]]. Observed
on branch fix/sdk-coverage-fail-closed-and-parity (2026-06-22).
