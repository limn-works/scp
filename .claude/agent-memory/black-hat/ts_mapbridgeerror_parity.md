---
name: ts-mapbridgeerror-parity
description: Black-hat analysis of TS SDK mapBridgeError wrapping of ucanValidate/eventLogQuery (branch fix/sdk-coverage-fail-closed-and-parity); why the prefix-classification path resists message injection
metadata:
  type: project
---

# TS SDK error-typing parity (branch fix/sdk-coverage-fail-closed-and-parity @614f0eb17)

Change: `scp.ucanValidate` + `scp.eventLogQuery` NOW route through `mapBridgeError`
(previously deliberately exempted with a security NOTE). trust.ts `evaluateTrust`
classifies on `.message` prefix, not subclass.

## Why it resists attack (verified empirically, all 3 probes pass)

**Two-regex asymmetry is the key defense:**
- `mapBridgeError` (errors.ts:263): UNANCHORED leftmost `/\[([A-Z]+-[A-Z]+-\d+)\]/`
- trust.ts (lines 458/462/513): ANCHORED `^\[SCP-PERM-\d+\]` / `^\[SCP-CTX-\d+\]`

NAPI bridge format = `[{code}] {category} error: {message}` — real code ALWAYS leading.
mapBridgeError leftmost-match → always picks leading real code even if attacker embeds
`[SCP-CTX-2001]` inside a DID/cap URI. trust.ts anchored → attacker cannot inject a
later `[SCP-PERM-]` to force UCAN classification.

**Field-inflation attack fails:** `__classifyUcanError` uses `core.startsWith(prefix)`.
core begins with the FIXED UcanError variant prefix (e.g. `capability outside ceiling:`).
Attacker controls only the `{0}` tail (cap URI, DID, nonce — see UcanError variants in
crates/scp-protocol/src/crypto/ucan/mod.rs). Tail cannot move the leading prefix, so a
real early-stage failure can never be classified as a later stage with more
`__PASSED_BEFORE` fields=true. Verified: injecting `token expired` into a ceiling cap
URI still classifies as `ceiling`, not `expiry`.

**Subclass mismatch is irrelevant to trust:** trust.ts re-classifies on .message, never
uses instanceof. mapBridgeError preserves .message verbatim (errors.ts:260, all ctors
pass message through). So even a wrong subclass doesn't affect the trust verdict.

**PERM-3030 re-throw:** object-identity test (toBe) replaced by instanceof+code+message.
Still safe — trust.ts `throw error` re-throws the (now mapped) caught object; propagation
intact, no swallow.

## check-sdk-coverage.py fail-closed
Change is DOCSTRING-ONLY. `unmatched_true` exit-1 logic predates the branch (4 refs in
fc0b53543^). Gate is a closed allowlist (ALIASES + domain-prefixed exact match; substring
matching removed). all-exempted check prevents prose-bypass. Sound.

## Residual nits (LOW, not vulns)
- nativeFreeFn lookup outside try (e.g. scp.ts:964): throws ValidationError SCP-VALID-7005
  if addon stale — already a typed ScpError, so no escape from typing. Benign.
- mapBridgeError unanchored regex is theoretically loose but the leftmost+leading-code
  invariant makes it safe in practice. If bridge format ever changed to put code
  non-leading, this would break — note for future.
