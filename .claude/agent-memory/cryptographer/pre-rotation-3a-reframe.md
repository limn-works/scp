---
name: pre-rotation-3a-reframe
description: §9.7.4.1 item 3a recovery-authority-residence RULE kept canonical; realization punted to RFC #2130; ADR-054/062 Proposed; InMemory nullifier severance is Slice-6 future work
metadata:
  type: project
---

# Pre-rotation custody reframe (branch docs/adr-062-capability-injection, 2026-07-14)

Pre-rotation custody REALIZATION punted to RFC #2130 (a Discussion, not ADR) for the e2e-collab stage. Only the recovery-authority-residence RULE stays canonical.

**Why:** maintainer principle — don't commit a fully-specified design as canonical ADR when not executing it now; frame as Proposed, re-validate at execution.

**What stayed canonical (spec §9.7.4.1):**
- item 3a core paragraph — recovery authority MUST reside in substrate whose compromise is independent of operational custody; principal-distinctness not cipher-strength; transitive reachability closure to chain root; encrypted-offline ciphertext treated as adversary-visible.
- item 3a(c) — migration is not a daily operation (distinct migration-time principal OK).
- at-rest closing paragraph — property is at-rest/daily-ops, not the migration instant (`consume` yields plaintext by construction).
- Items 4/5/6/7 REVERTED byte-identical to pre-§3a parent 34d52da16 (verified via diff).

**What moved to RFC #2130 (proposed):** 3a(a) server KMS/HSM floor, 3a(b) interactive user-passphrase floor, per-backend §3-soundness table, conformance PAIR (negative-reachability + principal-distinctness), §5/§6 ceremony. RFC #2130 §3.4/§3.5 preserve the table + PAIR verbatim incl. "part 2 guards part 1 false-PASS" + Zeroize-the-KEK. Nothing security-critical lost.

**Soundness verdict:** retained rule stands on its own (self-contained MUST; removed clauses were profile-specific realizations of it, not premises). No shipped crypto guarantee lost — no real backend ever existed (all InMemory, config.rs:334).

**Findings (LOW/informational, docs-cleanliness only):**
1. Spec item 3a has ORPHANED "c." sub-label — no a./b. after the cut. Reads oddly ("3a ... c."). Recommend relabel to plain sub-paragraph.
2. ADR-054 lines 151-152 cite "§3a(a)"/"§3a(b)" which no longer exist in spec (moved to RFC #2130). ADR framing (lines 5/121/123) makes clear these are its own proposed sub-clauses, but the bare spec-style citation is a cross-ref hazard.

**Code state:** Slice-6 severance NOT landed on this branch (docs-only deliverable). config.rs:334 still mints InMemoryPreRotationCustody with a warn!. dht.rs has ~40 InMemoryPreRotationCustody sites (mostly #[cfg(test)]). ADR-062 §Decision 4/6 mandates fail-closed typed IdentityError once Slice 6 demotes the nullifier to #[cfg(feature="testing")]; production create fails closed, never falls back to nullifier. Pre-severance identities carry a valid-but-non-durable commitment (SHA-256(pubkey) real, private key process-local) — covered by spec failure mode line 701 + config.rs warn; pre-release so moot.

ADR-062 Status: Proposed. ADR-054 Status: Proposed (commit dc9bcf5f2 fixed residual "moves to Accepted" claim). No stale Accepted claims remain.
