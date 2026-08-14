---
name: sdk-coverage-failclosed-parity-e807b3f9c
description: Alignment review of fix/sdk-coverage-fail-closed-and-parity at HEAD e807b3f9c — source_id NotRequired→str|None fix; CONDITIONAL on ADR-053:49 §9.12→§9.7.4.1 citation fix (chronicler-caught, I missed)
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ e807b3f9c (2026-06-22) — APPROVED, 0 findings

HEAD `e807b3f9c` = exactly ONE commit past previously-APPROVED `6bc9dfead`. merge-base = `1f1ea7cd2`; origin/main has since advanced to `b5b0eb02c` (5 commits ahead of base = the #1857/#1858/#1859 convergence slices + node-participant work, all DISJOINT surfaces — diff by merge-base three-dot or by SHA, not bare main).

**The delta (`git diff --stat 6bc9dfead e807b3f9c`) is 1 file +2/-2: `bindings/python/scp_sdk/discovery.py` ONLY.** Changes `ResolutionPathDict.source_id` from `NotRequired[str | None]` → `str | None` + docstring "or None for non-HandleRegistry layers".

**Why correct:** PyO3 bridge `crates/scp-ffi/src/discovery.rs:236` does `resolution_path.set_item("source_id", resolution_source_id)?` UNCONDITIONALLY for every path; `resolution_source_id` is an Option → Python None. Key is ALWAYS present, value `str|None`. `NotRequired` (key-may-be-absent) was factually wrong. Bridge tests confirm both arms: line 1412 `source_id=="disc-ctx-1"` (HandleRegistry), lines 1431/1450 `is_null()` (other layers). `map_discovery_source` lives in `crates/scp-ffi/common/src/discovery.rs` (NOT scp-ffi-common dir — it's crates/scp-ffi/common/).

**Literal sets verified** against Rust PascalCase emission in crates/scp-ffi/common/src/discovery.rs: trust kind = DomainVerified/HandleRegistryVerified/DirectExchange (emitted) + full §22.7 set in TypedDict; layer = Domain/HandleRegistry (emitted) + full §22.11.3 set. TypedDict mirrors full discriminated union for forward-completeness (bridge emits subset today) — matches TS union, not a gap.

**6 checks** (1-4,6 PASS; 5 = ONE FINDING): (1) PERM-3030 re-raise trust.py:769/770 `startswith("[SCP-PERM-3030]")`→raise mirrors trust.ts:461 regex; (2) §9.12(DID-changing)/§3.2.1(DID-preserving) correct, DidRotationEvent doc flipped right on bridge.ts:668, both kept on dual-purpose block:524; (3) TrustLevelDict 6-kind/ResolutionPathDict 5-layer Literals match Rust PascalCase wire + TS union; (4) source_id=THE FIX (always-present nullable, correct); (6) check-sdk-coverage.py in CLAUDE.md NEVER-MODIFY list = CI-wired ci.yml:147 fail-closed, additive, accurate.

(5) ADR-053 FINDING — chronicler-caught, I MISSED it on TWO passes of this HEAD: §3/§4/§5/item-6 quotes are VERBATIM-accurate (spec:665/671-676/678-684/686), code refs exist (identity.rs:824/922/1052, uniffi:676/714/736), ZERO impl leaked. BUT **ADR-053 line 49 mis-attributes the "Partial-publish recovery" paragraph to §9.12**. That paragraph is at 09-security-model.md:696, structurally UNDER §9.7.4.1 (heading :655, next section §9.8 at :698 — verified via `grep '^### |^## '` boundaries). ADR's OWN line 86 cites it correctly as §9.7.4.1 → self-contradiction = phantom-provenance defect (broken provenance is a bug per artifact-flow invariant). FIX: line 49 §9.12 → §9.7.4.1. VERDICT = CONDITIONAL APPROVE (fix line 49 to clear).

LESSON 1: single-commit delta past APPROVED HEAD → `git diff --stat <prev> <HEAD>` to scope, deep-verify the one file, re-confirm prior checks. LESSON 2 (from the miss): when validating an ADR's spec citations, verifying the QUOTED TEXT is verbatim is NOT enough — ALSO confirm each in-line cross-reference (`§X.Y "Named Paragraph"`) points at the section that STRUCTURALLY CONTAINS that paragraph. grep `^### |^## ` to bracket the paragraph's owning heading. A named-paragraph reference to the wrong § is phantom provenance even when every quoted clause is accurate. The chronicler caught a §9.12-vs-§9.7.4.1 mis-cite I passed over twice.
