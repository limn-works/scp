---
name: adr062-prerotation-failclosed-scope
description: ADR-062 pre-rotation nullifier severance — the "callback-custody bridges fail closed" framing understates that ALL production identity creation fails closed
metadata:
  type: project
---

ADR-062 (docs/adr-062-capability-injection) severs `InMemoryPreRotationCustody` to
test-harness-only (Slice 6, SCP-CAPINJECT-006) and makes production identity creation
fail closed with a typed `IdentityError` because no real pre-rotation backend exists
(deferred to RFC #2130 / #1729).

**Verified reality (interrogated 2026-07-14):** the pre-rotation nullifier is minted
*custody-agnostically* at every production create site — `scp-identity/src/config.rs:334`
(`create_inner`, the shared lowering both `Identity::create` paths funnel through),
`scp-node/src/lib.rs:2560/2754/3639`, and all three bridges (`scp-ffi/src/identity.rs:988/1094/1230`,
`runtime.rs`, `scpid.rs`; napi equivalents). It does NOT depend on operational custody kind
(File/Sqlite/Callback all get the nullifier). `DidDht::create` (dht.rs ~2073) always requires
a `PreRotationCustody` and always commits — no non-committing create path exists.

**Consequence:** after Slice 6, ALL production identity creation fails closed until #1729 —
not only "via the callback-custody bridges" as ADR-062 prose repeatedly says (lines 17/85/126).
The narrow framing is scar tissue that understates the blast radius. The honest statement:
the entire production identity-creation capability is disabled until a real pre-rotation backend
lands. PRD AC (SCP-CAPINJECT-006, ~line 269) only tests the callback path fails closed — it
under-verifies the true (all-paths) scope.

**Why:** relevant to any future review of this PRD or of §9.7.4.1 realization. The severance
mechanism is real/correct (fail-closed is the right posture — a nullifier recovery backstop is
a DOA identity); the honesty gap is purely in the scope wording + the acceptance-criteria coverage.
**How to apply:** if this PRD is revisited, push to (a) reword the fail-closed scope to "all
production creation," (b) add ACs asserting File/Sqlite create paths also fail closed.

**RESOLVED — PR #2136 `docs/adr-062-reframe-correction` (b6dd698e0, interrogated 2026-07-14).**
The correcting PR (fixes #2120's bad auto-merge of the 15-story over-scoped ADR) closes BOTH prior
findings. (1) Scope honesty: ADR-062 E5 bullet (L17/22), Decision 4 (L91), Decision 6 (L108),
Consequences (L139), and classification table (L38) now all state "ALL production identity creation
— File/Sqlite/callback custody AND scp-node self-host, every path through config.rs:334, not merely
the callback bridges — fails closed"; PRD story SCP-CAPINJECT-006 AC[4] asserts File/Sqlite/node-self-host
paths ALSO return the typed error, not just callback. Premise re-verified against current origin/main
(create_inner still mints generically over K:KeyCustody). (2) Invariant restore: spec §9.7.4.1 item 3a
now carries "**Fail closed — no fallback (normative)**" — core invariant ONLY; per-profile floors + §5
ceremony correctly punted to RFC #2130, NOT re-introduced into canonical spec. Reframe scoped ADR-062
to 6 stories (000/001/006/009/010/011), ADR-054 flipped Accepted→Proposed, pre-rotation *backend*
out-of-scope (nullifier severance stays in-scope). VERIFIED CLEAN: no story depends on Proposed ADR-054
(no source cites it; header disclaims dependency); no residue-framing applied to the severed nullifier
(all such strings are severed-mechanism descriptions or explicit REJECTED-alternatives); no dangling
cut-slice refs (2-5/7-8/12-14 gone); prior orphan spec "c." sub-clause gone; ADR-054 L151-152 §3a(a)/(b)
relabeled "RFC #2130 proposed §3a(a)/(b)" (phantom-provenance fixed); RFC #2130 and #1553 are REAL
GitHub *Discussions* (not fabricated refs — #2130 = "RFC: Pre-rotation recovery custody", #1553 =
non-committing-create design); #1729/#1777 real OPEN issues; PRD validates clean on branch tree.
Verdict MERGEABLE. Two residual LOW cleanups only: (a) ADR-054 L119 retained rejected-alt "Defer to a
tracking issue. Rejected... acceptance authorizes the implementation workstream" is stale vs the new
Proposed/deferred-to-#2130 posture (superseded by scope note, but reads as contradicting the reframe);
(b) spec §9.7.4.1 item 5 "SDK MUST present custody options" stays an unconditional MUST while production
creation fails closed pre-#1729 — coherent ONLY via the restored item-3a fail-closed clause (present-what-
conforms; if none, fail closed), which is exactly why restoring that clause was load-bearing.
