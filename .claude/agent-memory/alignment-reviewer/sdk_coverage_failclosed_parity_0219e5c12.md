---
name: sdk-coverage-failclosed-parity-0219e5c12
description: Final ALIGNED review of fix/sdk-coverage-fail-closed-and-parity at HEAD 0219e5c12 — rebase-clean, 0 blocking
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ 0219e5c12 (2026-06-20) — ALIGNED, 0 HIGH/MED, REBASE-CLEAN

HEAD 0219e5c12 (3 past ed14e6c77). **Rebase-clean**: merge-base == origin/main == dabf13364, 33 ahead / 0 behind. No phantom deletions possible (clean merge-base; the ad51633f3 stale-base illusion gone for good).

**Why:** Cross-SDK parity (TS gains identityRotateKey/identityMigrate/identityAddAgentKey/identityRemoveAgentKey + evaluateTrust to match py) + fail-closed coverage gate rewrite + ADR-051 (pre-rotation custody substrate) + matrix exemption corrections.

**How to apply:** This is the canonical clean final state. Same logical work as 44eaf5d05/ed14e6c77, advanced 3 commits (BUN_TEST truthy, UCAN prefix-anchor regex, dead py_prefixed gate branch removed, economy.py dead TYPE_CHECKING cleanup, stale ALIASES point at runtime methods).

## Verified live (not memory text)
- **Migrate disambiguation CORRECT**: spec `03-identity.md` §3.2.1 is "Key Custody Migration Protocol" with TWO cases — case 1 Active-Signing-Key (same DID, rotate_active_key), case 2 "Identity Key migration (rare)" which explicitly "creates a new DID" via pre-rotation mechanism (ADR-003 §4b, §9.12). Live `scp.ts:755 identityMigrate` doc cites §9.12 + ADR-003 §4b (new-DID path) — correct. internal/bridge.ts:666 cites "§3.2.1 (Identity Key migration)" = §3.2.1 case 2, accurate.
- **evaluateTrust** cites §7.2–7.5 four-layer model (trust.ts:91,391) — correct; remaining §9.3 refs in types.ts:49/69 are Consequence-rules/automated-governance (ADR-017), a genuinely different subsystem, correctly cited. No leftover §9.3 trust miscitation.
- **Coverage gate has teeth**: ran it — 222 ops, 0 errors (0 unmatched-true, 0 false-w/o-exempt, 0 all-exempted), EXIT 0. Self-tests 9/9 pass. ci.yml adds gate self-test step (strengthening). CLAUDE.md adds check-sdk-coverage.py to enforcement-files list (strengthening).
- **Matrix changes honesty-improving not weakening**: rotate_key exemption text corrected from false "UniFFI does not export rotate_key" → honest "exports it; no SDK wrapper yet" (entries already false on main). add_relay_url Kotlin coverage_exemption documents real tree-sitter-kotlin grammar limitation (backtick-quoted @Throws generated override not a clean function_declaration node) — tool gap not real gap.
- **ADR-051** Proposed / Phase 6 — correct artifact-flow (downstream proposed record, not reshaping specs upstream).
- **provider.rs** = doc-only (zero non-comment lines changed); ADR-049 actor doc cleanup.
- **#632 issue refs** in wasm.ts/native.ts/bridge.ts are PRE-EXISTING on main; branch adds ZERO #632 lines (no [[feedback_no_issue_refs_in_code]] violation introduced).
- Parity methods are real implementations, not stubs.

See [[two-dot-diff-stale-base-trap]].
