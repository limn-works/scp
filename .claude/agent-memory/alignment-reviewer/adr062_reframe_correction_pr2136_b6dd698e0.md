---
name: adr062-reframe-correction-pr2136-b6dd698e0
description: PR #2136 (docs/adr-062-reframe-correction, b6dd698e0) — corrects wrongly-auto-merged over-scoped ADR-062 (#2120); faithful to all 6 maintainer decisions; ALIGNED/mergeable; supersedes prior 5482c6917 scar-tissue findings
metadata:
  type: project
---

PR #2136 corrects PR #2120 (which wrongly auto-merged the OLD 15-story over-scoped ADR-062 to main: ADR-054 Accepted, pre-rotation in-scope, no fail-closed severance). This branch (off CURRENT origin/main) lands the maintainer-directed reframe. Docs-only, 4 files. VERDICT: ALIGNED / mergeable as-is.

**Why:** maintainer ruled pre-rotation realization punted, zero nullifiers, nullifier severed fail-closed broad-scope, 6 execute-now stories.

**How to apply:** treat this branch as the canonical ADR-062 state; the 15-story over-scoped version on main pre-#2136 is superseded. Prior review memory [[adr062_prerotation_reframe_5482c6917]] flagged 2 residual scar-tissue contradictions (ADR-054:176 "residue framing"/present-in-binary; ADR-062:5 "weld it does not fix") + provenance gaps (branch lacked PR #2132) — ALL RESOLVED here: b6dd698e0 is off main which contains PR #2132 (84aa20443).

All 6 decisions verified faithful:
1. Pre-rotation PUNTED — ADR §Decision 4 "does not realize pre-rotation custody"; ADR-054 Status=Proposed (header + line5 + Amendment heading + OQ resolution-status all say Proposed, ZERO stray "Accepted" — grep clean); spec §9.7.4.1 keeps ONLY item-3a residence RULE + restored fail-closed-no-fallback clause + migration-not-daily + at-rest canonical; realization→RFC #2130/#1729/#1777. Spec items 4/5/6 reverted to pre-§3a original text (per-profile filtering removed, now RFC #2130's). No dangling 3a(a)/(b) refs in spec.
2. Zero nullifiers — ADR §Enforcement G1 "allowlist permits durability-only only (in-memory-storage/in-memory-push) — ZERO nullifiers, no exceptions"; story-006 AC7 asserts behaviorally (allowlist contains ONLY durability-only; NO nullifier feature on any allowlist).
3. Severed FAIL-CLOSED broad scope — ADR §Decision 4/6 + Consequences + story-006 consistently name File/Sqlite/callback + scp-node self-host via config.rs:334 lowering, "not merely the callback bridges." story-006 AC5 explicitly asserts File+Sqlite+node-self-host create paths return typed error. FACTUALLY VERIFIED on main: config.rs create_inner unconditionally does `InMemoryPreRotationCustody::new()`, all create paths funnel through it (doc-comment admits "only backend that exists today is in-memory") → severing→all prod creation fails closed is grounded, not aspirational.
4. 6 stories 000/001/006/009/010/011 — confirmed in PRD (6 stories, 6 gates); ADR rollout lists slices 0,1,6,9,10,11 + "Out of scope (RFC #2130)" for pre-rotation realization. ZERO leftover deleted CAPINJECT-002/003/004/005/007/008/012/013/014 IDs in ADR or PRD.
5. Restored fail-closed clause sound — spec §9.7.4.1 "Fail closed — no fallback (normative)" is general (typed error, no fallback to co-located OR in-memory/dev-test stand-in), NO per-profile realization detail (no KMS/HSM floor, no passphrase min-strength). Aligns w/ PR #2132 tenet.
6. Provenance in-tree — CLAUDE.md:26 "No dev/test-only stand-ins" tenet, CLAUDE.md:149 + sdk-common.md:197/209 §Stub-Placeholder rule, spec §17.17.2/SCP-CAPSEL-8012 all present on branch. validate-prd PASS (16 files, 437 stories).

RESIDUAL (non-blocking, LOW): (a) story-011 (E4 MultiRelayQuerier) narrative says it "brings a DhtMode::Disabled node's relay-resolution path online" (a Slice-1/story-001 construct) but blockedBy:[] — soft sequencing dep on 001 not encoded; validate-prd passes, relay layer is genuinely separate so independent execution OK. (b) ADR+story cite specific code lines (config.rs:334 verified accurate; dht.rs:2073 create, ~15+ weld sites) — code-provenance for executing slice to re-verify at Slice-6 time.
