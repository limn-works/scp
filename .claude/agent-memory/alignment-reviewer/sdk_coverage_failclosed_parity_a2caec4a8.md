---
name: sdk-coverage-failclosed-parity-a2caec4a8
description: APPROVED final cert of fix/sdk-coverage-fail-closed-and-parity @ a2caec4a8 — gate bare-name bypass removed, 108 aliases sound, prior LOW closed
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ `a2caec4a8` (2026-06-21) — APPROVED, 0 findings

4 commits past `ae8a306aa` (prior APPROVED HEAD). The 4 new commits:

**9346e3da3** PERM-3030 TS test (mirrors Python `test_evaluate_trust_reraises_perm_3030_handle_affinity_error`) + test-guard comment fix (bun sets NODE_ENV=test not BUN_TEST). **c1fb5e042** removed the three retained `#1549` refs in native.ts — CLOSES my prior-round LOW carry-note (the one retained #1549 at the time). **1679a75ac** the substantive change: gate `_check_operation_in_sdk` drops bare-name candidates (op_name/camel/pascal), now requires domain-prefixed forms (`domain_op_name`, `domainOpName`, `Domain.op_name`, `Domain.opName`) OR an explicit ALIASES entry; replaced 263 bare-matched cells with 108 ALIASES entries. **a2caec4a8** Python DiscoveryResult Literal narrowing + Bridge/register alias fix.

**Why APPROVED:**
- Gate matching is SOUND: aliases still require `if alias in sdk_symbols` (tree-sitter-extracted set) — an alias CANNOT fabricate a symbol, only point at a real one. Removing bare candidates closes the substring/common-verb collision class the §coverage-gates lesson warns about. Self-tests 9/9 pass via pytest; gate EXIT 0 (222 ops, 0 err, 1 legit kotlin addRelay exemption). CI now runs self-tests BEFORE gate (ci.yml +2). check-sdk-coverage.py added to CLAUDE.md NEVER-MODIFY list. Both additive.
- Spot-checked the riskiest alias `Bridge/register`→python `["register"]`: NOT a collision — `bindings/python/scp_sdk/bridge.py:57` `def register(` is the real public bridge fn (multi-line sig, so `def register\b` grep misses it; gate extracts it correctly). kotlin/swift match via auto `bridgeRegister`; TS=false w/ exemption (internal bridge interface). Verified end-to-end with a probe importing the gate module.
- DiscoveryResult Literal narrowing (a2caec4a8): `layer`/`kind` str→Literal EXACTLY matches Rust source-of-truth `crates/scp-protocol/src/discovery/addressing.rs` enums (TrustLevel 6 variants, ResolutionLayer 5) AND the TS discriminated unions in types.ts:900/915. No fabricated values. Real typed-surface parity win.
- PERM-3030 guards consistent: Python trust.py:762 `startswith("[SCP-PERM-3030]")` raise BEFORE classify; TS trust.ts:461 `/^\[SCP-PERM-3030\]/ throw` BEFORE classify. Sound per-SDK-idiom asymmetry: TS has extra :457 guard re-raising ANY non-`[SCP-PERM-\d+]` error (NAPI throws plain Error); Python scopes via `except bridge.UcanError` so non-UCAN propagate naturally. Same end state.
- §9.12 boundary preserved: DID-CHANGING migrate paths cite `spec §9.12, ADR-003 §4b`; DID-PRESERVING custody paths correctly RETAIN §3.2.1 (scp.py:639, napi scp.rs:1242, wasm `#active` two-key/§4a rotation). `git grep "step 4b"`=NONE. All crates/*/identity.rs + uniffi bridge.rs changes COMMENT-ONLY; provider.rs COMMENT-ONLY.
- ADR-051 Status: Proposed; ZERO impl symbols (`PreRotationCustodyProvider`/`import_seed_bytes`/`CallbackPreRotationCustody`) leaked into source — only in the ADR .md + review-note .md files. Correct spec-before-code artifact flow.

**Pre-existing NON-finding (informational):** ~80 `#NNNN` issue refs (#559/#621/#615/#632/#1549 etc.) live across `bindings/` source — violates feedback_no_issue_refs_in_code, but PRE-EXISTING and untouched by this branch (not chartered for a repo-wide sweep). The 4 lines git attributes as "added" containing #632/#1549 are existing comments where only the adjacent §citation was edited (e.g. `§9.12, §3.2.1`→`§9.12`); the branch adds NO net-new issue refs. Not a regression. This branch's removal of the 3 native.ts #1549 refs is the canonical inconsistency (removes some, edited files retain others) but is strictly an improvement.
