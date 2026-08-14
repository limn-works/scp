---
name: ceiling-wellformed-convergence-doc-ceb65aafa
description: §5.3.1.1 ceiling well-formedness follow-up — WASM error-map dedup + precise convergence doc (ceb65aafa) resolving prior LOW; ALIGNED zero findings
metadata:
  type: project
---

Follow-up commit ceb65aafa on branch fix/ceiling-wellformed-custom-enforcement (worktree /private/tmp/scp-ceiling), reviewed 2026-06-24 — ALIGNED, ZERO findings, ship.

Continues [[ceiling-wellformed-type-invariant-c2503b59a]] (the type-level invariant work). This commit addresses TWO non-blocking review notes:
- simplifier: extract private `validation_error(CeilingEntryError) -> ScpWasmError` (manager.rs:309-317); all 3 ValidatedCeilingStrings ctors (from_colon_entries:334, from_capabilities:353, from_ucan_strings:378) now reject via `Self::validation_error` instead of repeating the `ScpWasmError::Validation { message: e.to_string(), code: VALID_7000 }` closure verbatim. Byte-identical reject surface, pure dedup, no behavior change.
- alignment-reviewer (me): rewrote the loose "byte-identical ceiling the native bridge stores" doc (manager.rs:287-290) → "same canonical UCAN-string set the native bridge yields via Capability::ucan_capability_name (native stores Capability enums per ADR-034; the convergent property is this string projection, not the in-memory representation)."

This is the FIX for the LOW I carried across the type-invariant reviews: old prose implied representational identity across two implementations that DELIBERATELY store different types. Now correctly states projection-equivalence.

Verified all 3 load-bearing facts in code:
- native `CapabilityCeiling.capabilities: HashSet<Capability>` (roles.rs:461) = ENUMS.
- WASM `ValidatedCeilingStrings(HashSet<String>)` (manager.rs:292) = STRINGS.
- `ucan_capability_name(&self) -> String` = literally `format!("{resource}:{action}")` (roles.rs:341-344) = pure string projection of the enum — exactly what tests assert.
- ADR-034 (phase-4.md:1411-1465): WASM is verbatim RE-IMPLEMENTATION not fork (1435); contract = "both bridges produce identical OUTPUTS for identical inputs"; named primary risk = implementation drift (1449). So "convergence = observable canonical-string set, not in-memory repr" is the EXACT right characterization of the ADR-034 contract. Citation is on-point, not phantom.

NON-FINDING noted: ADR-034 doesn't itself prescribe the enum representation (that's roles.rs); ADR-034 is the ADR for the impl-split + output-convergence. "per ADR-034" attaches to the split/convergence framing, which is the correct and only ADR to cite for native-vs-WASM divergence. Not actionable.

LESSON: a "fix-the-loose-doc-to-match-reality" follow-up review = (1) re-derive every factual claim from code (grep the projection fn body, the native storage field type, the WASM storage field type); (2) confirm the cited ADR actually grounds the divergence claim (read ADR-034 — re-implementation-not-fork + output-convergence-is-the-contract); (3) confirm the dedup helper body is byte-identical to the closures it replaces (preserves error code/message). Projection-equivalence is the CORRECT weaker claim; representational-identity was the overclaim.
