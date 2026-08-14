---
name: finding-pr1867-doc-review
description: PR #1867 (fix/sdk-coverage-fail-closed-and-parity, HEAD b712f94ae) doc/ADR/lesson/provenance review findings
metadata:
  type: project
---

PR #1867 doc-focused review (2026-06-22). Branch fix/sdk-coverage-fail-closed-and-parity.

**ADR-053** (pre-rotation custody substrate isolation) verified internally consistent:
- Refs ADR-003/021/025/034 all exist (003="DID Creation (did:dht)" titled, but item 4b = migrate_identity is real; "§4b" accurate).
- Spec §9.7.4.1 §3/§4/§5/§6 citations all match 09-security-model.md exactly. Partial-publish recovery paragraph IS under §9.7.4.1 (line 696), not §9.12 — earlier commit 06d15bb6a fixed this correctly.
- Migration flow correct: consume (=PreRotationCustody::destroy_after_migration) -> KeyCustody::import_ed25519_signing_key. Final commit edef523f8 correctly changed import_seed_bytes->import_ed25519_signing_key for the operational install step. import_seed_bytes remains correctly the NEW pre-rotation-provider method name (distinct from operational KeyCustody method). Canonical method-name table self-consistent.
- LOW nuance: ADR line 49 separates consume(step5) from item-6(fresh gen), while spec equates step-5 consume WITH item 6. Finer decomposition, not a contradiction.

**Lessons** (5 new, all accurate, all cross-refs resolve):
- coverage-gates-must-fail-closed.md (consolidates prior-session fail-closed + suffix-matcher lessons)
- ucan-validate-needs-real-capability-uri.md
- identity-migration-cite-9.12-not-3.2.1.md (verified §3.2.1=03-identity custody migration, §9.12=09-security compromise recovery)
- mock-test-must-not-invert-real-bridge-behavior.md (test now asserts migrated.did !== identity.did)
- fromhandle-must-surface-all-protocol-significant-fields.md
- Prior-session lesson names (fail-closed-gate-escape-hatch, suffix-matcher-becomes-bypass, cross-sdk-method-naming) NOT present — consolidated/dropped; cross-bridge-canonical-naming.md covers naming. No missing lesson.

**Comments**: trust.ts/trust.py UCAN comments accurate (scp:ctx:{id}/{resource}:{action} format confirmed via scp-protocol/crypto/ucan/mod.rs). provider.rs = comment-only (ADR-049 actor alignment + #1294 issue-ref removal).

**FINDINGS**:
- LOW: trust.py line ~803 comment cites "trust.ts line ~461" but actual PERM-3030 check is line 483. Brittle/stale line-number cross-ref.
- LOW (process): ADR-053 + §22 citation work bundled with unrelated trust/coverage fix — mild "atomic/no-bundle" git-rule deviation.
- LOW: rotate_key kotlin/swift exemptions document a known half-done gap (bridge exports, no SDK wrapper) — honest, not weakening, but a deferral per builder tenets.

CI correctly runs gate self-tests BEFORE gate (ci.yml). Matrix JSON valid; exemptions vs coverage_exemptions keys used correctly. No spec changes in PR.
