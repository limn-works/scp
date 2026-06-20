---
name: sdk-coverage-failclosed-parity-ed14e6c77
description: ALIGNED final review of fix/sdk-coverage-fail-closed-and-parity at ed14e6c77 — freshly rebased, migrate §9.12 disambiguation correct, ADR-051 coherent
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ ed14e6c77 (2026-06-20) — ALIGNED, 0 blocking

**Rebase sanity NOW CLEAN.** merge-base == origin/main == dabf13364; HEAD ed14e6c77; 31 ahead / 0 behind. The stale-base trap flagged at ad51633f3 (see [[two-dot-diff-stale-base-trap]]) is RESOLVED — branch was rebased. No phantom deletions. Two BIG-DELETE files (integration.test.ts -51, check-sdk-coverage.py -206) are net-positive rewrites, not regressions. provider.rs is -67 but PURELY doc-comment updates (ContextManager→ADR-049 actor language; remove "default implementation" trait-language for inherent methods) — no code-logic deletion.

**Core alignment fix verified: §9.12 vs §3.2.1 disambiguation.** Codebase has TWO distinct migration ops:
- `identity_execute_custody_migration` → §3.2.1 (custody migration, PRESERVES DID) — correctly cited scp.py:639.
- `identity_migrate` → §9.12 + ADR-003 §4b (identity-key migration, NEW DID) — scp.py:724-728. The fix REMOVED the wrong old `§3.2.1 step 4b` citation (that's custody-migration) and the spurious `4c` (§4c = verify_migration, a verifier not the caller-facing migrate op). ADR-003 §4b (phase-1.md:375-387) confirms migrate_identity returns NEW DID + DidRotationEvent + publishes both docs. TS identity.ts/scp.ts say "creates an identity with a **NEW DID**" + distinguishes from identityRotateKey (same DID). 03-identity.md:28 confirms "This creates a new DID."

**ADR-051 (pre-rotation custody substrate isolation) coherent + correctly placed.** Standalone file .docs/adrs/adr-051-pre-rotation-custody-substrate-isolation.md, Status: Proposed, Phase 6. All citations VERIFIED live: §9.7.4.1 exists (09-security-model.md:655), honest UniFFI substrate-isolation comment exists (bridge.rs:689 "Substrate isolation is NOT yet satisfied"), fail-closed import_ed25519_signing_key block exists (bridge.rs:736 "callback custody cannot import pre-rotation seed bytes"). Problem statement (§9.7.4.1 §3-§5 substrate reqs + migration-reveal gap) is real and accurately described. Artifact-flow respected (design before code; open questions flagged incl. "does §9.7.4.1 need a callback-custody sub-clause").

**Matrix changes are honesty-improving, NOT weakening.** rotate_key kotlin/swift=false is PRE-EXISTING on main (verified via `git show origin/main:matrix`); branch only corrects the FALSE exemption text "UniFFI bridge does not export rotate_key" → accurate "bridge exports it; no SDK wrapper yet." The false state is unchanged. add_relay_url gains coverage_exemption documenting tree-sitter-kotlin grammar gap (backtick-quoted @Throws override not surfaced as function_declaration node). CLAUDE.md adds check-sdk-coverage.py to protected enforcement list (appropriate — branch makes it fail-closed).

**evaluateTrust cites §7.2–7.5 + ADR-017 (four-layer), NOT §9.3 Sybil.** No residual miscitation. types.ts:49,69 §9.3 refs are for Consequence rules (legit ADR-017 §9.3), not trust eval. Genuinely mirrors Python trust.py four-layer. test-guard.ts uses POSITIVE allowlist (NODE_ENV test|development | BUN_TEST set), Object.hasOwn prototype-pollution defense, fails closed. Coverage gate: node.text null-safe `(node.text or b"")` decode, coverage_exemptions non-empty validation, exit 1 fail-closed. Sound + bounded per CLAUDE.md.

Verdict: APPROVED. This is the same body of work as 44eaf5d05 (see [[sdk_coverage_failclosed_parity_44eaf5d05]]) now rebased clean onto current main. All 4 task questions resolved positively.
