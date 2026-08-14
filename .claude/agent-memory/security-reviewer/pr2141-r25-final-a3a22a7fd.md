---
name: pr2141-r25-final-a3a22a7fd
description: PR #2141 R25 final security review (a3a22a7fd) — coverage-gate private-symbol exclusion + trust structured path + mapBridgeError; zero blockers
metadata:
  type: project
---

# PR #2141 R25 final (a3a22a7fd) — SECURE, 0 BLOCKER / 0 SHOULD-FIX

**Why:** 156-commit main absorption; verify surviving delta security posture.
**How to apply:** Reuse for any future re-review of fix/sdk-coverage-fail-closed-and-parity.

## check-sdk-coverage.py private-symbol exclusion (5 Python sites)
- `not name.startswith("_")` at: methods-from-block (fn + decorated), class-name skip, top-level fn, top-level decorated fn. Monotonic FAIL-CLOSED: shrinks available-symbol set → `_check_operation_in_sdk` can only return False more often → MORE errors, never fewer. Cannot open a bypass by construction.
- Verified NO ALIASES entry targets a `_`-prefixed symbol (grep empty) → drops zero real matrix symbols. Edge cases sound: empty name (falsy → skipped via `name and ...`), dunder/`_`/`__` excluded, class private-name skip. Over-restriction is CI-availability risk only, not a security hole.
- Minor doc imprecision: claims "parity with TS export-keyword" but TS extractor does NOT filter `_`-prefixed exports, so an `export function _foo` would still satisfy a TS cell while Python `_foo` won't. Name-existence bookkeeping only, not enforcement. Observation.

## trust.py structured path (ADR-059)
- evaluate_trust now routes each token through `instance.ucan_evaluate(context_id, token, None, subject_did)` and reads 6 structured bools (tokens/signatures/within_ceiling/nonce/not_revoked/time_bounds), AND-combined across tokens. `structured_to_capability_validation` reads all 6; `all_valid` ANDs all 6. Default (no tokens) = all-False FAIL-SAFE. Token raise → propagates (no absorption).
- **Item-4 answer:** the OLD PERM-3001/PERM-3030 prose classification is GONE from Python — replaced entirely by structured booleans. This file's ONLY error absorption is Layer-2 `except ContextError: if exc.code != "SCP-CTX-2076": raise` (empty participation facts → zeroed record; everything else propagates). Strictly SAFER than prose classification. PERM-3030 distinction now lives only in trust.ts (not in this PR's 3 focus files).
- SECURITY docstring (all_valid) loudly warns: DIAGNOSTIC not authorization; intrinsic mode (capability=None) SKIPS step-6 grant-match; nonce probed-not-consumed (replayable). Honest + correct. presenting_agent_did=subject_did passed fail-closed (bridge rejects empty rather than defaulting to token aud → prevents audience tautology / trust inflation). Depends on scp-ffi/src/ucan.rs enforcing it (asserted, not in diff).
- No injection (json.dumps only, no shell/SQL/interp). No secrets.

## errors.ts mapBridgeError
- Handles non-Error throws: `error instanceof Error ? error.message : String(error)`. Passes already-typed ScpError through untouched (preserves code + stack). Fail-safe fallback SCP-UNKNOWN-0000 → generic ScpError.
- CONSIDER (defense-in-depth, non-blocking): code regex `/\[([A-Z]+-[A-Z]+-\d+)\]/` is UNANCHORED (first match anywhere), unlike sibling mapSagaError which start-anchors `/^\s*\[.../ ` precisely to stop a code embedded in {message} from masquerading. Impact of a spoofed code is only SDK error-CLASS selection (instanceof) — NOT an auth decision (enforcement is in Rust core) — and the bridge format puts the real code at position 0, so exploit needs a non-bridge-formatted attacker-controlled message. Low. Recommend mirroring mapSagaError anchoring for consistency.
- CONSIDER: constructs new ErrorClass without `{ cause: error }` → original bridge stack lost. Debuggability, not security.
