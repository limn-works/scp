---
name: adr057-c3c-trust-ffi-shape
description: Verdicts on the ADR-057/C3c trust-FFI change set — free-fn/method split is governed (sound); JSON-string SDK input is a systemic asymmetry; check_capability_requirements is exported-but-unreachable (#1988)
metadata:
  type: project
---

Interrogated the trust/capability FFI change set (branch feat/actor-2c-xctx-tool-saga,
HEAD c9c956739; ADR-057 + spec §7.2.4/§7.3.2.1 + lesson sdk-consume-structured-ffi-results).

**Why:** distinguishes governed per-SDK divergence from unexamined drift on the trust surface.

**How to apply — premise verdicts (re-verify against current code before relying):**
- `verify_participation_requirements` free-fn-vs-method split (Python/Swift free fn; TS/Kotlin
  method) is NOT accidental status quo. It is the faithful, per-language application of
  **ADR-048 §1 (pure helpers stay free `pub fn` at FFI Rust layer) + §7 (SDK wrapper idiom is
  per-language)** — `.docs/adrs/ADR-048-scp-multi-instance.md` lines 40–52, 123–157. The fn is
  pure (NAPI `_bi` unused). SOUND — do not "unify" it; §7 explicitly permits the split.
- void+throw (dropped an always-`Ok(true)`, always-discarded `bool`) and the arg reorder
  (bridge was `(profile_json, requirements_json)` — REVERSED vs core `(requirements, statements)`;
  now `(expected_subject, requirements_json, profile_json)`) both REMOVE accidental mismatches and
  mirror core `Result<(), E>`. SOUND anti-drift.
- Empty-subject guard: core `if expected_subject.is_empty()` is the trust-boundary invariant;
  bridges' `validate_did` is a SUPERSET (full DID hygiene) that also catches empty. Different
  properties, layered — NOT the weaker-form redundancy CLAUDE.md warns against. SOUND
  defense-in-depth.

**Open finding — JSON-string SDK INPUT asymmetry (systemic, pre-existing, QUESTION):**
Python SDK wraps the whole trust surface with typed objects + `_to_bridge_dict()` + `json.dumps`
(participation_record, aggregate_trust_input, verify_participation_requirements). TS/Swift/Kotlin
expose raw `...Json: string` params — even though TS already defines typed `RequireParticipation`
/`ParticipationProfile` (types.ts:1159/1203). This is NOT §7 idiom (that governs structural shape,
not input typing) and reincarnates ADR-057's stringly-typed brittleness on the INPUT side in 3 of
4 SDKs, against the Agent-first "identical shape / authorable from the type signature" tenet. Fix
is achievable with zero FFI change (serialize typed→same JSON, as Python does). Needs an artifact
decision on the canonical SDK input convention.

**check_capability_requirements — exported-but-unreachable (see [[adr057-check-capability-1988]]):**
pub in scp-protocol, re-exported by scp-core, hardened this change set (empty-subject + subject
binding + verify-on-use) but ZERO FFI export, ZERO production callers — while its identical-shape
sibling verify_participation_requirements is wired through all 3 bridges + 4 SDKs. #1988
(wire-or-remove, needs spec answer) was filed by a prior inquisitor pass and is CORRECTLY
root-caused. Hardening is only non-wasted on the wire branch; must not rot open across change sets.
