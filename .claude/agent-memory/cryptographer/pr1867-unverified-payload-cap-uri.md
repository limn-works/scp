---
name: pr1867-unverified-payload-cap-uri
description: PR #1867 fix/sdk-coverage-fail-closed-and-parity — unverified JWT payload read for cap URI is SOUND (fail-closed, no oracle); MLS+identity diffs comment-only; ADR-053 doc-only
metadata:
  type: project
---

# PR #1867 cryptographic review @ b712f94ae (base 1f1ea7cd2)

**Verdict: cryptographically APPROVE. No CRITICAL/HIGH/MEDIUM.**

## Central finding — reading UNVERIFIED JWT payload to pick cap URI is SOUND
trust.ts `__extractCapabilityUri` (308-322) / trust.py (771-792): split on `.`, base64url-decode parts[1], read `att[0].with` from UNVERIFIED payload, pass as `capability` to ucanValidate.
- **Why safe:** Ed25519 sig covers exactly `header.payload` (validate.rs:748-760, signing_input=encoded[..last '.']). Only ONE payload segment; SDK decode == Rust parse_ucan URL_SAFE_NO_PAD decode of same bytes. No second copy to diverge → no TOCTOU/forgery.
- Step 6 (validate.rs:562-577) re-parses VERIFIED token.payload.att, check_capability_match(granted, required). required==token's own att[0].with → step 6 becomes tautology BUT that's fine: evaluateTrust reports "does token validate on own terms," not "authorized for action X". Steps 2(sig)/8(ceiling)/9(nonce)/10(revoke)/11(expiry) all still enforced.
- **Fail-closed:** any SDK misread only makes step 6 return CapabilityNotGranted → Layer1 less-valid. Can NEVER make invalid token report valid. No oracle.
- **Genuine fix:** prior hardcoded `"*"` arg always failed CapabilityUri::from_str (capability.rs:218 needs scp:ctx: prefix) → unknown → all-false for EVERY token. Reading real att[0].with makes Layer1 actually run pipeline.

## Python base64 padding CORRECT
`padding=4-len%4; "="*(padding%4)` handles len%4 in {0,2,3}; outer %4 maps 0-case to 0 pads. TS↔Py parity on happy+fail-closed.

## MLS provider.rs (67 lines) — COMMENT-ONLY
`git diff|grep -vE "///|//"` empty. Removed stale trait-era "default impl/MUST override" docs (methods now inherent on MlsCryptoProvider); ContextManager→actor/receive-handler rename (ADR-049). verify-after-decrypt invariant (1629-1633,1755-1758) preserved verbatim. Zero crypto impact.

## Identity FFI (napi/src/wasm identity.rs, uniffi bridge.rs) — CITATION-ONLY
§3.2.1 step 4b → §9.12, ADR-003 §4b (new-DID migration path; §9.12 correct vs §3.2.1=DID-preserving custody). DOMAIN_MIGRATION_V1 + length-prefixed proof untouched.

## ADR-053 — SOUND design, Proposed, NO impl code in PR
Doc-only (ADR-051→053 renumber). consume handle-invalidate-in-Rust-regardless-of-foreign (line49) closes dup-handle leak; import_seed_bytes Zeroizing reveal-inverse (48/51) ordering sound; separate provider structurally enforces §9.7.4.1 §3 (line107 rejects combined). LOW: future impl — consume()->Zeroizing crossing FFI to JS Array<number> not zeroizable on JS heap (cf scp.ts:708).

## Cargo.lock — quinn-proto 0.11.14→0.11.15 (RUSTSEC-2026-0185), checksum-pinned, no API change.

## LOW findings (non-blocking)
- L1: ADR-053 JS-heap residue at impl time.
- L2: both SDKs reflect only FIRST token's verdict (return/break on first malformed/failing) — pre-existing, parity-consistent.
