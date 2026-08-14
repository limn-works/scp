---
name: sdk-coverage-failclosed-parity-e992bd53f
description: fix/sdk-coverage-fail-closed-and-parity REBASED clean onto main dabf13364 — ALIGNED, 1 LOW (Python §3 vs TS §3.2.1 citation drift)
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ e992bd53f (2026-06-20) — ALIGNED, REBASED CLEAN

**CRITICAL CONTEXT FLIP from prior reviews:** branch is NOW REBASED. merge-base == origin/main == dabf13364. Two-dot `git diff origin/main..HEAD` is clean (26 source files), NO phantom deletions. The stale-base trap (see [[feedback-two-dot-diff-stale-base-trap]]) that plagued reviews at ad51633f3/44eaf5d05 is RESOLVED. Verified branch touches NOTHING in scp-event-log or scp-runtime/src/actor; reconnect/heartbeat code still live on branch (export_import.rs, standing_helpers.rs, lifecycle_helpers.rs).

**Re-verified 5 focus areas, all ALIGNED:**
1. evaluateTrust parity TS↔py: all 6 UCAN prefix lists byte-identical (incl 19-entry SIGNATURE_CHAIN), _PASSED_BEFORE/__PASSED_BEFORE maps match, classify order matches (sig→ceiling→parse→nonce→revoked→expiry). TS dispatches by Context handle, py by context_id — documented per-SDK NAPI idiom, not a bug.
2. Identity lifecycle: identityRotateKey=same DID (ADR-003 §4a, "DID does NOT change" phase-1.md:363), identityMigrate=NEW DID + rotationEventJson (ADR-003 §4b migrate_identity returns DidRotationEvent, phase-1.md:375). Spec §3.2.1 case-1=Active-key rotate (same DID), case-2=Identity Key migration ("creates a new DID", 03-identity.md:28). Tests assert both + #agent drop on migrate.
3. ADR-051 (Proposed, 2026-06-14): grounded in §9.7.4.1 §3-§6 + §9.12 + ADR-003 §4b. Cites real code: PyO3 InMemoryPreRotationCustody identity.rs:824/922/1052 (ADR says :819-824/:919-922/:1047-1052, within drift), UniFFI generate_ephemeral_ed25519_seed:676/import_ed25519_signing_key:714/"callback custody cannot import":736 — all real.
4. Matrix: rotate_key exemption CORRECTED ("UniFFI bridge exports rotate_key" — bridge.rs:2178 `pub async fn rotate_key` confirms; old text "does not export" was a factual error). add_relay_url coverage_exemptions[kotlin] cites tree-sitter-kotlin grammar gap for generated backtick @Throws override methods — plausible.
5. Gate fail-closed: check-sdk-coverage.py null-safe (`node.text or b""` :547), coverage_exemptions reasons validated non-empty (:1131-1138), all-exempted guard (:1205-1217) requires ≥1 statically-verified SDK — bounded by construction. Gate RUNS: 0 errors, 1 coverage-exempt, 0 all-exempted-ops. Self-test 7 passed. Now wired in ci.yml (self-test step BEFORE gate). CLAUDE.md adds check-sdk-coverage.py to enforcement-files list (strengthening, legitimate).

**Bonus (not in prompt, verified clean):** economy_verify_payment_receipts added py+TS symmetric; PaymentReceiptVerificationResult mirrors verification_results_to_json (receipt.rs:169 confirmed). provider.rs doc removes stale "default impl/trait override" language (inherent methods, no crypto trait) + ADR-049 actor concurrency note. Python __exit__ `del exc_type,exc,tb` (ruff unused-arg).

**1 LOW:** scp.py:720 identityMigrate docstring now cites bare `§3, ADR-003 §4b`; identity.ts cites precise `§3.2.1 (Identity Key migration)`; identity-lifecycle.test.ts:218 cites `§3.2.1`. The most precise anchor is §3.2.1 case-2. Python `§3` is correct-but-coarser → cross-SDK citation drift. Old py `§3.2.1 step 4b` was wrong (no such step; §3.2.1 case-1 has steps 1-5) so the change was a net improvement, just under-precise. Non-blocking.
