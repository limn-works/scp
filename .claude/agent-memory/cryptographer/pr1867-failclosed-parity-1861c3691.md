---
name: pr1867-failclosed-parity-1861c3691
description: PR #1867 fresh review @1861c3691 — fail-closed/parity; trust.ts att[0] extract, WASM ucan error-type refactor, ADR-053 doc, quinn bump. No blocking crypto findings.
metadata:
  type: project
---

# PR #1867 cryptographic review @1861c3691 (fix/sdk-coverage-fail-closed-and-parity)

Fresh independent review. **No blocking crypto findings.** Base 1f1ea7cd2..HEAD.

**Why:** continuation of the #1867 line (prior memory entry covered @b712f94ae). This commit renames extract helper + exports evaluate_trust from Python root + the big check-sdk-coverage.py fail-closed rewrite.

**How to apply:** if asked to re-review #1867 or its successors, the crypto-touching surfaces are narrow — focus only on these 5.

1. **trust.ts `__extractFirstCapabilityUri` (renamed from `__extractAllCapabilityUris`)** reads att[0].with from UNVERIFIED JWT payload → passes to ucanValidate. SOUND/fail-closed: selection-only, verifier re-parses + re-checks required_capability against signed att; divergence only yields self-inflicted false-negative; null → ALL_LAYER1_FIELDS_FALSE, bridge not called. att[0]-only is coverage limit not soundness. trust.ts:320-334, 457, 547-551.
2. **Nonce tracking** — one ucanValidate per token per Layer1 (single validateOneCapUri trust.ts:553); split-phase intact. LOW: lesson file `ucan-validate-needs-real-capability-uri.md` lines 19+54 still reference pre-rename `__extractAllCapabilityUris` (STALE); also doesn't state second-pass→NonceReused consequence. Doc drift only, code sound.
3. **ADR-053** = NEW doc-only (Status Proposed, 115 lines). NO consume/import_seed_bytes code in this PR. Design of adapter-level single-use handle invalidation (Rust invalidates handle after consume regardless of foreign success/fail → HandleNotFound) is SOUND against key-duplication. CAVEAT for impl PR: "destroy-and-export atomically" is NOT atomic across FFI — must order destroy-LAST (export+retain → import → verify → destroy), else process-death after substrate-destroy-before-import loses backstop. Pre-rotation key is Ed25519 SEED not AEAD nonce — "nonce reuse" mis-framing; deterministic Ed25519 has no nonce-reuse catastrophe; real risks = duplication + destroy-before-import. Require cryptographer sign-off on implementation PR.
4. **Cargo.lock** — only quinn-proto 0.11.14→0.11.15 (QUIC state machine, RUSTSEC-2026-0185 routine bump). NO core-crypto crate changed (rustls/ring/dalek/sha2/aes-gcm/openmls/argon2/zeroize all unchanged). No finding.
5. **WASM run_validate_ucan (ucan.rs:323-392)** — ALL 11 STEPS INTACT. Change = error-type refactor Result<(),String>→Result<(),UcanError> only; validate_ucan call line 381 byte-identical w/ full ValidationContext. Classification now routes through ucan_errors::ucan_error_code → WASM emits [SCP-PERM-3001] like other 3 bridges (STRENGTHENING — makes trust.ts:473 closed-allowlist reachable on WASM path). validate_tool_ucan_wasm now Some(code) all branches (unwrap_or PERM_3000 dead).

Adjacent clean: provider.rs 67-line diff COMMENT-ONLY (verify-after-decrypt preserved, "deferred to receive handler"); test-guard.ts fail-closed (frozen at load, Object.hasOwn anti-proto-pollution); identity.rs all 4 bridges citation-only §3.2.1→§9.12 ADR-003 §4b; phase-3/4.md PermissionError→UcanPermissionError rename only.
