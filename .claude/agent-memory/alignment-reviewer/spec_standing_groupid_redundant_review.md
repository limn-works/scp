---
name: spec-standing-groupid-redundant-review
description: Review of spec/standing-group-id-redundant (b258f2c42) dropping the redundant standing-pair group_id from §5.15.8 — ALIGNED on the cut, 1 MEDIUM dangling cross-ref in §9.18.2 separator registry
metadata:
  type: project
---

# Spec PR spec/standing-group-id-redundant Review (2026-06-15) — ALIGNED on the cut + 1 MEDIUM cross-section straggler

Branch spec/standing-group-id-redundant, HEAD b258f2c42 on origin/main e3c05688e. SPEC-ONLY, 1 file (.docs/specs/05-contexts.md §5.15.8), drops the redundant standing-pair `group_id`.

**Justification (artifact-flow invariant):** code revealed the spec over-specified a deterministic `group_id` (`SHA-256("scp-standing-group-v1:" ‖ len32-framed DIDs)`) that has no code counterpart and does NOT actually key MLS isolation — the crypto provider indexes MLS group state by `derived_context_id` via a create-time `Entry::Vacant` collision guard. Fix flows DOWN: spec corrected to match what keys isolation. Correct application of the invariant.

**VERIFIED ALIGNED:**
- Edit re-homes the "load-bearing injectivity" prose from the deleted `group_id` onto `derived_context_id` (Entry::Vacant guard is the real isolation key). Self-consistent across all 5 touch points: determinism-precondition para, injectivity-invariant para, Prepare-A table row + validation step (4), Prepare-B wire-list + validation step (3) + staged-evidence sentence, CreationReceipt JCS object (group_id field dropped).
- Length-prefix framing correctly demoted to OPTIONAL FUTURE hardening of `derived_context_id` ("NOT done here, since the DID-grammar property already forecloses the only realizable ambiguity") — matches the task's "noted-but-deferred" item. No scope leak.
- §5.12 parent-lineage `group_id` (05-contexts.md:1187,1189 — MLS group_context-derived child group identity) correctly LEFT untouched: genuinely distinct concept.
- Unblocks PR-3: standing-saga build now needs NO new MLS deterministic-group-id capability. Vestigial code field `StandingPairCreatePrepared.group_id` correctly out of scope (grep found no such field in crates/ at this HEAD — PR-3 removes it).
- ADR-049 clean: no ADR references standing-pair group_id or scp-standing-group-v1.

**MEDIUM (cross-section straggler — under-reach):** §9.18.2 Domain Separator registry in .docs/specs/09-security-model.md still LIVE-references the now-deleted `"scp-standing-group-v1:"` standing-pair MLS group-id derivation in TWO places:
- Line 1585 (prose): "...the table also includes non-§9.5.1 entries (for example the `\"scp-standing-group-v1:\"` length-prefixed `SHA-256` key/id-derivation domain..."
- Line 1627 (table row): `| \"scp-standing-group-v1:\" | Standing-pair MLS group-id derivation — a length-prefixed SHA-256 key/id-derivation domain... | §5.15.8 |`
Both now point at a derivation §5.15.8 no longer defines → dangling phantom-provenance refs (the registry cites §5.15.8 as the source, but §5.15.8 no longer contains the derivation). The `"standing:"` / `"standing-"` row (1628) is STILL valid (those prefixes survive). Fix: delete the scp-standing-group-v1 table row + scrub it from the 1585 prose example, KEEP the standing:/standing- entries. Belongs IN this same docs-only PR (same artifact, same cut) — not a follow-up.

**Verdict: ALIGNED on the cut; NEEDS the §9.18.2 registry scrub before merge to avoid a dangling separator-registry ref.**

LESSON: a "drop a redundant derived id" spec PR must be checked at the SEPARATOR/REGISTRY layer too — any deleted domain-separator-bearing derivation (here `"scp-standing-group-v1:"`) is almost always ALSO registered in the §9.18.2 domain-separator table (09-security-model.md) which cites the deleting section as its source. Grep the deleted separator string repo-wide; the registry row + its prose example are stragglers in the SAME logical cut.
