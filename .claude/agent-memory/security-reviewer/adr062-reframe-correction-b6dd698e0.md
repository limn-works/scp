---
name: adr062-reframe-correction-b6dd698e0
description: ADR-062 reframe-correction PR #2136 (b6dd698e0) security verify — docs-only, MERGEABLE, zero residual nullifier
metadata:
  type: project
---

# ADR-062 reframe-correction — PR #2136 (branch docs/adr-062-reframe-correction, b6dd698e0) — 2026-07-14 — MERGEABLE

Corrects #2120 (auto-merged the WRONG 15-story pre-rotation-realization version to main). This PR is DOCS-ONLY (4 files: ADR-062, ADR-054, PRD adr062-capability-injection.json, spec §9.7.4.1). Reduces PRD 15→6 stories (000/001/006/009/010/011); punts pre-rotation *realization* to RFC #2130/#1729/#1777; downgrades ADR-054 Accepted→Proposed. KEEPS the security-critical nullifier severance (Slice 6 / story 006).

## Verdict: all 5 docs-level security properties HOLD. Zero residual nullifier. Spec clause STRENGTHENED, not weakened.

## Load-bearing code anchors verified (code == main; PR is docs-only)
- `InMemoryPreRotationCustody` is the SOLE impl of `PreRotationCustody` (scp-platform/src/testing/pre_rotation_custody.rs:67); already lives under `#[cfg(feature="testing")] pub mod testing` (lib.rs:46). Every other `PreRotationCustody` hit is a `&impl` param sig.
- THE WELD IS REAL + UNCONDITIONAL: scp-identity/Cargo.toml:21 pulls `scp-platform{features=["testing"]}` NON-optionally (main dep, not dev). scp-node/Cargo.toml:28 same. So production graphs carry the nullifier type → config.rs:334 `create_inner` mints `InMemoryPreRotationCustody::new()` for EVERY custody kind (generic K); scp-node/src/lib.rs:2560/2754/3634 mint it too. Sever the testing edge ⇒ these ~15+ sites won't compile ⇒ MUST return typed IdentityError. Fail-closed is REAL, scoped to ALL prod creation (File/Sqlite/callback/node).
- create ALWAYS commits a PreRotationCommitment (dht.rs create builds it into DidDocument unconditionally) — no non-committing path exists ⇒ Option A correctly out of scope (#1553).
- NO pre-rotation realization exists: grep kms|argon2|passphrase|shamir|bip39|encrypted-offline|strongbox|secure-enclave near pre_rotation = EMPTY. config.rs:315 warn! openly admits "the only PreRotationCustody backend that exists today is the in-memory one." ⇒ canonical unwind (drop 3a(a)/(b) floors, §5 filtered ceremony, §6 realization, ADR-054→Proposed) drops ZERO shipped guarantee.

## Docs consistency (all clean)
- spec §9.7.4.1:670 NEW standalone "Fail closed — no fallback (normative)" paragraph forbids fallback to co-located storage AND to in-memory/dev-test stand-in (adds the PR#2132 stand-in prohibition) — STRONGER than removed 3a(a). :676 keeps items 4/5 canonical, punts only per-profile filtering to RFC #2130.
- ZERO dangling refs: no 3a(a)/(b)/(c) left in spec; PRD 0 refs to deleted stories 002-005/007-008/012-014; ADR-062 0 refs to deleted slices; no lingering "ADR-054 Accepted"; ADR-054 body now wholesale Proposed + scope-note.
- G1 zero-nullifier: ADR Decision 6 + Rejected-alts explicitly reject "documented/tracked/legible" exception; story 006 AC#7 asserts allowlist = durability-only ONLY; AC#9 asserts scp-platform/testing + scp-dht/testing + scp-testing + scp-core→scp-protocol→scp-did/testing did:key chain absent (as TEST INPUTS not the check).
- story 006 blockedBy=[001] forward-only; validate-prd passes; gates match.

## Observations (non-blocking, carry-forward)
1. Post-severance, ALL production identity creation fails closed until #1729 — functional availability regression, but the honest SECURE state (nullifier gone); node self-host failing closed aligns w/ #2135 "node is not a participant." Security improvement, not regression.
2. RFC #2130 MUST carry forward the interactive-passphrase ≥128-bit min-strength check (was spec item 3a(b), now removed) when the encrypted-offline interactive backend is eventually built — else realization could ship without it. Nothing implements it today so no current defect.
3. Same as prior 5482c6917 obs#2: spec item-4 menu "any one is sufficient" dropped explicit residence cross-ref; still governed by normative 3a paragraph but a forward-ref would harden it across the RFC #2130 boundary.
4. CLAUDE.md "no deferral" tension is an alignment/scope call adjudicated by maintainer (PR#2132 ruling + external-constraint framing); from security lens fail-closed > unaudited fresh KMS backend. Not a security finding.
