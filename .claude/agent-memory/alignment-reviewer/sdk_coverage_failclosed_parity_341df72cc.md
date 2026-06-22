---
name: sdk-coverage-failclosed-parity-341df72cc
description: ALIGNED review of fix/sdk-coverage-fail-closed-and-parity at HEAD 341df72cc — rebased onto 1f1ea7cd2, ADR-051→ADR-053 rename, 0 blocking
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ 341df72cc (2026-06-22) — ALIGNED, 0 blocking

HEAD 341df72cc. **Rebase-clean**: merge-base == origin/main == 1f1ea7cd2, 59 ahead / 0 behind. No phantom deletions. Successor to 0219e5c12 (prior ALIGNED at base dabf13364), now rebased onto newer main.

**Key delta since 0219e5c12:** ADR-051 (pre-rotation custody) RENAMED to **ADR-053** because ADR-051 was claimed by causal-dag application-event-ordering on current main (`.docs/adrs/ADR-051-causal-dag-application-event-ordering.md`). Rename is COMPLETE and clean:
- pre-rotation-custody ADR is wholly `.docs/adrs/adr-053-pre-rotation-custody-substrate-isolation.md`; file does NOT reference ADR-051 anywhere; "Related" line correctly omits ADR-051.
- All residual `ADR-051` refs in source/specs are the causal-dag ADR (PaymentReceipt anchoring, frontierRoot, event-log convergence) — pre-existing, untouched, correct. Branch touches NEITHER ADR-051 causal-dag file NOR phase-2/specs 07/09/19. Disjoint subsystems — no conflict possible.

## Verified live (not memory text)
- **§9.12 vs §3.2.1 split CORRECT, cross-SDK parity**: `identity_migrate`/`identityMigrate` (NEW DID via pre-rotation reveal, returns DidRotationEvent) cites **§9.12 + ADR-003 §4b**; `identity_execute_custody_migration` (DID-PRESERVED custody swap) cites **§3.2.1**. py scp.py:639(custody→§3.2.1)/672(recovery→§9.12), TS bridge.ts:666 rotationEventJson→§9.12, WASM §3.2.1 only on two-key invariant + rotate_active_key. Anchors verified: §9.12="Compromise Recovery Protocol" @09-security-model.md:1150; §9.7.4.1="Pre-Rotation Key Custody" @655; §3.2.1="Key Custody Migration Protocol" @03-identity.md:20. Lesson identity-migration-cite-9.12-not-3.2.1.md ACCURATE.
- **Fail-closed gate has teeth**: ran it — 223 ops, 0 errors, EXIT 0. Self-tests 11 passed (pytest). Sound by construction: true+no-symbol+no-exemption→ERROR exit1 (line 1583); unexpected cell value→ERROR (1602); all-exempted-ops guard requires ≥1 statically-verified SDK per op (1619) — bounds the coverage_exemptions escape hatch; over-capture is the safe extractor failure mode (1226). Positive ALIASES whitelist, no suffix/substring. Aligns with "enforce mechanically" tenet. Strengthening: ci.yml runs self-tests BEFORE gate; CLAUDE.md adds check-sdk-coverage.py to NEVER-modify enforcement list. Lesson coverage-gates-must-fail-closed.md ACCURATE vs code.
- **PERM-3030 re-raise**: py trust.py:770 + TS trust.ts:461 both re-raise `[SCP-PERM-3030]` from ucan_validate instead of absorbing into false all-False trust verdict. ADR-048 §4 "Handle affinity enforced via instance_id:u64" (ADR-048-scp-multi-instance.md:80-90) defines PERM-3030 as cross-instance handle misuse = caller programming error. Re-raising surfaces the bug per §4 "handle misuse caught at boundary, not corrupting silently" (line 235). Correct + at parity.
- **ADR-053 artifact-flow CLEAN**: Status Proposed, Phase 6, downstream record citing upstream (§9.7.4.1, §9.12, ADR-003 §4b, ADR-021, ADR-025). Explicit "design fixed in ADR before any code changes" + "spec change lands before code, per artifact flow". Does not reshape upstream. Open-questions section defers spec-clause decision upstream.
- **Matrix changes honesty-improving**: rotate_key exemption text corrected false→honest (cells stay false, no false claim); register TS true→false w/ reason (gate's exact-match caught prior false-positive — bridgeRegister is internal); add_relay_url kotlin coverage_exemption = real tree-sitter-kotlin grammar gap w/ verify cmd.
- **provider.rs** doc-only (0 non-comment lines). No scope creep.
- **Issue-refs NET-REDUCED** (improving [[feedback_no_issue_refs_in_code]]): removed 16 (#1294×1,#1531×5,#1549×6,#632×4), added 4 (#1549×1,#632×3) — added are reflows of pre-existing comments; bridge.ts #632 count dropped 1→0. No net-new violations.

Verdict ALIGNED, 0 blocking, 0 material. See [[sdk-coverage-failclosed-parity-0219e5c12]], [[two-dot-diff-stale-base-trap]].
