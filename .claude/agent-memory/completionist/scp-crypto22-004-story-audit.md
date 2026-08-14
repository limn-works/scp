---
name: scp-crypto22-004-story-audit
description: Audit of PRD story SCP-CRYPTO22-004 (keypackage-attestation.json) — AC7↔AC10 resolver-seam contradiction found, then RECONCILED (COMPLETE at commit 94d204956)
metadata:
  type: project
---

RESOLUTION (2026-08-03, commit 94d204956): re-review confirms the contradiction is FIXED.
The old resolver-freshness AC7 was replaced with an honest clock-derived AC7 — Layer B
stamps `resolved_at` = injected clock's time at the `DidResolver::resolve()` call (never a
fabricated/hardcoded value or a served-document age field), so it touches NO shared resolver
type and stays inside AC10's scope. The privacy-cache/resolve_fresh/ResolvedDidDocument-age
enforcement was relocated to `details.followOn` (SCP-CRYPTO22-005) + `details.openQuestions`.
Verified: all 6 resolver-seam tokens (resolve_fresh, resolved_at field, privacy cache,
ResolvedDidDocument, scp-identity/src/resolver.rs) appear ONLY in details, ZERO in the 10
hard ACs (the only `scp_identity` hit in an AC is AC5's `DidResolver` DI trait consumption —
importing, not modifying resolver.rs). files[] now includes the PRD JSON, excludes
resolver.rs. blockedBy/blockedByIssues [] honest (startable now vs merged S2 PR #2246).
validate-prd.py passes on branch content (443 stories, 18 files, exit 0). No AC gutted into
a tautology — Layer A's check-2 300/301 boundary is still fully enforced with caller-supplied
inputs; Layer B just always passes it (correct given it can't yet read served-doc age).
Verdict flipped INCOMPLETE → COMPLETE — conformant.

---
Original audit (before reconciliation):
Audited `.docs/prds/keypackage-attestation.json` story `SCP-CRYPTO22-004` on branch
`crypto22-s4-prd-story` (2026-08-03). Verdict INCOMPLETE.

Headline finding — two HARD acceptance criteria mechanically contradict:
- AC7 (resolver-freshness): a scp-runtime test where a resolver-served document >300s
  age forces fresh resolution. Requires reading document age at Layer B.
- AC10 (scope boundary): `git diff --name-only origin/main` touches ONLY
  crates/scp-mls/keypackage_attestation.rs + crates/scp-runtime/crypto/mls/* + the PRD.
- BUT `ResolvedDidDocument` (crates/scp-identity/src/resolver.rs) has NO resolved_at
  timestamp and `DidResolver` trait has no resolve_fresh/max_staleness (verified on
  origin/main: fields are document, seq, source). So AC7 needs a scp-identity resolver
  change — which AC10 forbids. The story's own openQuestions admit the seam "must be
  settled upstream before Layer B's freshness check is wired" and actionItems[7] defers
  the age-consultation shape to a human. So AC7 is not completable as written; the
  upstream dep is not in files[]/blockedBy/blockedByIssues.

Minor: files[] omits the PRD JSON file itself though AC9/AC10 whitelist "this PRD file"
in the diff.

Everything else was clean and notably rigorous: all required fields well-formed; all 6
sources exist + match verbatim (§9.7.1, §9.18.7, §9.14, §9.10.7, §7.4.4, ADR-057
2026-08-01 Amendment); all cited symbols real on origin/main (verify_attestation,
AttestationVerifyError::SignatureInvalid, resolved_current_vm_pubkey,
MAX_ATTESTATION_KEY_RESOLUTION_STALENESS=300, Vector-37 tests, credential.rs:157
resolve_signing_key, provider.rs:637 validate_creator_identity carve-out); blockedBy []
honest (S1/S2 shipped without story IDs — cited by real merged PR #2246, not fabricated);
9/10 ACs machine-verifiable.

Gotcha: local `main` was stale (behind origin/main), and detached working-tree HEAD
predated ADR-057 — so `validate-prd.py` run against the working tree false-flagged the
ADR source as missing. Always validate story sources against the BRANCH content
(git show branch:file), not a stale working tree.
