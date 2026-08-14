---
name: sdk-coverage-failclosed-parity-1ed31cd8c
description: Review of fix/sdk-coverage-fail-closed-and-parity @ 1ed31cd8c — gate fail-closed + TS/Python parity + §9.12 citation + ADR-051
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ `1ed31cd8c` (2026-06-20) — NEEDS DISCUSSION (1 LOW + observations)

5 commits past origin/main. Builds on prior-round work (f6caeb5dd etc). Verdict: aligned in substance; 1 LOW citation-precision finding.

**Why:** Verifies citation correctness, cross-SDK shape parity, fail-closed gate hardening, ADR sequencing.
**How to apply:** Reuse the §9.12/§3.2.1/ADR-003-§4b distinction; the "step 4b" malformation pattern.

## Confirmed ALIGNED
- **BridgeTrustLevel** Python `Literal[0,1,2,3]` docstring (ShadowBridged=0…NativeNative=3) matches Rust `provenance.rs:43` enum EXACTLY. Rust documents under §12.5+ADR-023 crit6; Python says "§12" (less precise, within §12, not wrong).
- **discover_contexts(query)** Python takes NO scp arg — CORRECT: `py_context_discover` is a module-level `#[pyfunction](query)` (discovery.rs:285), no per-instance state. TS `discoverContexts(scp,query)` differs only because TS dispatches via getBridge(scp). Legitimate per-SDK difference, well-documented.
- **DiscoveryResult TypedDict** mirrors TS shape (snake_case). Docstring `kind`/`layer` values `HandleRegistry`/`HandleRegistryVerified`/`DomainVerified`/`DirectExchange` ACCURATELY describe what Rust `map_discovery_source` (scp-ffi/common/src/discovery.rs:18) emits + what TS types.test.ts asserts.
- **behavioralRecord null / contexts_participated removal**: old code hardcoded `contexts_participated=1` — a FABRICATION (data didn't exist). Removing to honest default 0 + explanatory comment is CORRECT per completeness tenet (honest 0 > fabricated 1). §7.3.2 frames participation record as cross-context AGGREGATE; SDK queries single context + defers to "full trust engine." TS+Python now parity (both 0, both null behavioralRecord on query fail). tool_invocations correctly populated via ToolInvoked events (§7.3.2 step 2).
- **trust.ts §9.3→§7.2-7.5 FIXED**: prior-round MED (trust.ts citing §9.3 Sybil for 4-layer model) is RESOLVED — now correctly `§7.2–7.5, ADR-017`.
- **ADR-051** standalone file, Status **Proposed**, 2026-06-14, cites §9.7.4.1+§9.12+ADR-003§4b, accurately diagnoses pre-rotation substrate-isolation gap on callback-custody path. No code ships (design artifact) — correct spec-before-code sequencing. NOTE: ADR-049/051 are STANDALONE files (not `## ADR-NNN` in phase-N.md) — both patterns coexist in this repo.
- **provider.rs**: 100% COMMENT-ONLY (verified: non-comment diff empty). Corrects stale "default impl/mock providers/override this" rustdoc (MlsCryptoProvider is inherent methods, no crypto trait) + ContextManager→context-actor(ADR-049). Honest provenance cleanup.
- **Gate fail-closed** (check-sdk-coverage.py): unmatched-true WARNING→ERROR (real teeth). Escape = `coverage_exemptions` closed-allowlist citing symbol. `_node_text` null-safety = safe fail-closed mode. NEW all-exempted check (line 1220): op where ALL coverage-claiming SDKs exempted + none statically-verified = ERROR — closes the exempt-everything bypass; ≥1 SDK must be confirmed. Bounded/sound shape. RAN gate on branch: 0 errors, 1 legit coverage-exempt (kotlin addRelay tree-sitter grammar limit), 0 all-exempted. Self-tests 9 passed.
- **Matrix rotate_key exemption text CORRECTED**: old "UniFFI does not export rotate_key" was FALSE (ScpBindings.swift has rotateKey()); new text honest "bridge exports it, no SDK wrapper yet." Honest gap-doc > false claim.
- **CLAUDE.md** adds check-sdk-coverage.py to enforcement-files list; **CI** adds gate self-tests before gate. Both expand coverage. Aligned.

## LOW-1: "§9.12 step 4b" is a malformed citation (inconsistently fixed within the PR)
The DidRotationEvent-distribution obligation traces to **ADR-003 §4b** (the "§4b" is ALWAYS an ADR-003 subsection id). Spec-level mandate lives in §9.5 (09-security-model.md:619 "When an Identity Key migrates (ADR-003 §4b), the agent MUST send a DidRotationEvent in every active context") + §3.2.1 case-2 (03-identity.md:28). **Neither §9.12 (steps 1-6, no 4b) NOR §3.2.1 (steps 1-5) has a "step 4b".** So "§9.12 step 4b" attaches a real ADR subsection number to the wrong artifact (a spec §). The PR IMPROVED section selection (§3.2.1 DID-PRESERVING custody migration → §9.12 Identity Key Migration, the right topic for a DID-CHANGING migrate) but kept the spurious "step" suffix. INCONSISTENT within PR: scp.py:724-727 fixed to clean "(spec §9.12, ADR-003 §4b)" — CORRECT form — but identity.py:113, Kotlin Identity.kt:88/285/301/316/480, Swift ScpBindings.swift:924/1216 still say "§9.12 step 4b". Pre-existing pattern (not PR-originated) but commit 72b7ea1cc propagated it. Fix: drop "step", say "ADR-003 §4b" (optionally "(spec §9.12 / §9.5, ADR-003 §4b)").

## OBSERVATION (pre-existing, NOT a PR finding)
Spec §22 internal inconsistency: §22.7 `ResolutionPath.layer` enum literals `"DiscoveryContext"` + `TrustLevel::DiscoveryContextVerified` (22:551/564) vs §22.11.6 wire table + Rust impl emit `HandleRegistry`/`HandleRegistryVerified` (22:1133, map_discovery_source). Impl/TS/Python-docstring all agree on HandleRegistry*; only §22.7's two literals diverge. Python docstring correctly mirrors impl. Spec §22.7 should be reconciled to HandleRegistry* OR impl renamed — separate spec-fix workstream.

## Correct §-distinction (REUSABLE)
- §3.2.1 = Key Custody Migration Protocol — DID-PRESERVING (correct for identity_execute_custody_migration; scp.py:639 cites it correctly).
- §9.12 = Compromise Recovery Protocol / Identity Key Migration — DID-CHANGING (correct for identity_migrate/rotate_key/rotation_event/identity_execute_recovery scp.py:672).
- ADR-003 §4a = rotate_active_key (DID unchanged); §4b = migrate_identity (new DID). "4a/4b" are ADR subsection ids, never spec "steps".
