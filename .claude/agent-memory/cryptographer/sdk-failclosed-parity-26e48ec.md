---
name: sdk-failclosed-parity-26e48ec
description: Crypto review of fix/sdk-coverage-fail-closed-and-parity — UCAN classification, BridgeTrustLevel, ADR-051, §9.12 citations, coverage gate. Tracks 26e48ec78 → 1679a75ac.
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity (independent crypto review)

No crypto-construction defects in any revision — branch is doc-comments, error-classification, typed enum, design ADR, CI/coverage-gate + test-guard hardening. Nothing touches key/nonce/sig/hash material.

## @ 1679a75ac (latest, 2026-06-21) — APPROVED, no blocking findings
- Both prior findings (Python PERM-3030 HIGH, WASM §9.12 MED) are FIXED here.
- Python trust.py:757-763 now re-raises `[SCP-PERM-3030]` before classification — parity with TS trust.ts:461. Confirmed PyO3 error.rs:730 maps HandleAffinityError→UcanError, Display `[{code}] permission error:` so prefix is byte-0. startswith / `^\[` both anchor correctly.
- §9.12 citation sweep complete: every new-DID migrate path (migrate_identity / DidRotationEvent distribution) cites `§9.12, ADR-003 §4b`; malformed `§9.12 step 4b` form eliminated. All residual `§3.2.1` are same-DID/two-key-invariant contexts (correct per 03-identity.md:20-28: §3.2.1 case-2 Identity-Key migration DELEGATES to §9.12/ADR-003 §4b). WASM identity.rs:2446 migrate header now §9.12 — prior MED stale.
- Coverage gate (check-sdk-coverage.py:1416 _check_operation_in_sdk): bare op_name/camel/pascal candidates REMOVED; only domain-prefixed forms + explicit ALIASES; matching is exact set-membership (`candidate in sdk_symbols`, line 1465), NOT substring. Sound-by-construction positive whitelist; +108 ALIASES replace 263 bare-matched cells. Bare names still in extracted symbol set but unreachable since no candidate is bare. Convergent.
- BridgeTrustLevel `0|1|2|3` (bridge.ts:38) MATCHES Rust provenance.rs:48-67 (ShadowBridged=0, ClaimedBridged=1, NativeBridged=2, NativeNative=3). doc comment ordering correct.
- NON-BLOCKING (ADR-051 LOW, carried): proposed PreRotationCustodyProvider `public_key()`/`consume()` duplicate existing trait methods `reveal_public_key()`/`destroy_after_migration()` (scp-platform traits.rs:771,783). ADR impact table only flags generate()+import_seed_bytes as new — should reconcile naming at impl time. Also `import_seed_bytes(seed)` drops the `public_key` arg that `store_committed_pre_rotation_key(public_key, private_key)` carries → loses commitment-binding defense-in-depth (CommitmentMismatch check). generate() genuinely new and correct (in-substrate keygen, mandatory for HSM/SE).

## Historical @ 26e48ec78 — had 1 HIGH + 1 MED (both since FIXED above)
- HIGH was: Python evaluate_trust swallowed PERM-3030 into all-false verdict (no re-raise). FIXED at trust.py:757.
- MED was: WASM identity.rs kept §3.2.1 on migrate path. FIXED — now §9.12.
