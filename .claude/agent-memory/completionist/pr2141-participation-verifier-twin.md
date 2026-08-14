---
name: pr2141-participation-verifier-twin
description: PR #2141 R6 — name-based SDK coverage gate can be satisfied by an INSECURE pure-language twin shadowing the secure UniFFI op; verify twin deletion + regex anchoring
metadata:
  type: project
---

PR #2141 Round 6 @5d118e1a2 — COMPLETE. Review-fix closures for participation-verifier + ucan-error-codes sync.

**Core lesson (name-resolution coverage gap):** `scripts/check-sdk-coverage.py` matches matrix entries by SYMBOL NAME only. A secure UniFFI-bridged op (`verifyParticipationRequirements(profileJson:requirementsJson:)`) can be silently SHADOWED by an insecure pure-language twin of the same base name (`verifyParticipationRequirements(requirement:profile:)` doing bare threshold compare, no sig/freshness/subject-binding/min_contexts). Gate passes on the twin's name → matrix `true` resolves to the WRONG (insecure) symbol. Fix = DELETE the twin so the name unambiguously resolves to the Rust-backed path.
- Insecure twins existed ONLY in Swift (Trust.swift, deleted 23779139f) + Kotlin (Participation.kt, deleted 7097938f5). Python (trust.py:1087) + TS (scp.ts:2812) NEVER had twins — both delegate straight to bridge. No participation.ts / participation.py module exists.
- All 4 bridges export + route to the SAME secure `scp_protocol::trust::participation::verify_participation_requirements`: PyO3 src/trust.rs:266, NAPI scp.rs:3354, UniFFI bridge.rs:6025, WASM wasm/src/trust.rs:301 (aliased `protocol_verify` — scp-protocol is pure-sync/wasm-safe so NO reimplementation drift). Coverage gate PASS, 0 unmatched-true. Deletions left zero dangling test/code refs.

**Regex fix (`_CODES_RETURN_RE` in test_ucan_conformance.py):** old `codes::(\w+)` was over-broad, matched a doc-comment `codes::PERM_3009` (ucan_errors.rs:114) → asserted a non-existent const → hard-fail. New `=>\s*\{?\s*codes::(\w+)` anchors on match-arm return position. All 7 real return sites in `ucan_error_code` are `=> codes::PERM_3001`; captured. Set={PERM_3001}→SCP-PERM-3001, in _PIPELINE_ABSORBED_CODES. Test passes.
- LATENT (not a current gap): a hypothetical multi-statement block arm `=> { stmt; codes::X }` would be MISSED (regex requires codes:: immediately after `=> {`). No such form exists; `const fn` constrains it. Comment only claims `=> { codes::X }` single-expr block coverage — accurate.
