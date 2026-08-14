---
name: pr1873-adr053-prerotation-substrate
description: PR #1873 pre-rotation custody substrate ADR — ROUND 2 @ 205aedc69 ALIGNED (053→054 collision fix landed); ROUND 1 @ 35c9b3d55 was NEEDS DISCUSSION
metadata:
  type: project
---

# PR #1873 ROUND 2 @ 205aedc69 (2026-06-23) — ALIGNED, ZERO findings (prior BLOCKING collision CLOSED)

Re-review of SAME PR after the renumber. File now `ADR-054-pre-rotation-custody-substrate-isolation.md` (+121, Status: Proposed). 2 commits ahead of main (`35c9b3d55` add-as-053 → `205aedc69` renumber-to-054 + reconcile method names); net `git diff --name-status` = single `A` of the 054 file only — no code/spec/other-ADR touched. The ROUND-1 BLOCKING ADR-053 collision is **CLOSED exactly as prescribed**: H1 `# ADR-054:`, zero stray `053` in file, `grep -rn ADR-054 .docs/` finds only the new file (number free), existing ADR-053 "Node Is Infrastructure" (phase-2.md:1877) untouched (phase-2.md not in diff). Re-verified ALL provenance still clean (spec §9.7.4.1 §3/§4/§5 verbatim @665/667-676/678-684; §9.12 @1150; ADR-003 §4b @phase-1:375; ADR-021/025/034 exist; code pointers identity.rs:824/922/1052, bridge.rs:676/714/736 + honest comment @686-692). Method-name table EXACT vs on-disk trait `PreRotationCustody` (traits.rs:745-793 = store_committed_pre_rotation_key/reveal_public_key/destroy_after_migration/custody_kind, NO generate): public_key→reveal_public_key, import_seed_bytes→store_committed_pre_rotation_key (adapter derives pubkey, forwards both — matches `(public_key:&[u8;32], private_key:Zeroizing<[u8;32]>)` sig), consume→destroy_after_migration, generate=new-no-counterpart, custody_kind diagnostic-only no FFI counterpart. import-vs-store coexist/not-renamed stated correctly. Artifact-flow downstream (Open-Q3 defers spec sub-clause to spec). Header matches ADR-050/051. Did NOT push/PR/arm-merge.

---
PRIOR (superseded by the fix above):
# PR #1873 docs/adr-053-pre-rotation-custody @ 35c9b3d55 (2026-06-23) — NEEDS DISCUSSION

Docs-only PR, 1 file +115 (`.docs/adrs/ADR-053-pre-rotation-custody-substrate-isolation.md`), Status: Proposed. 1 ahead / 0 behind origin/main. Split out of over-bundled `fix/sdk-coverage-fail-closed-and-parity`.

**BLOCKING: ADR number collision.** `## ADR-053: Node Is Infrastructure; Participation Is an SDK Client` ALREADY exists on main at `.docs/adrs/phase-2.md:1877` (Status: **Decided**), referenced twice by self-host-binary PRD (`.docs/prds/self-host-binary.json:123,344`). New file reuses 053. FIX = renumber new ADR to **ADR-054** (verified free + unreferenced); rename file + H1 line 1 only, zero inbound refs so no downstream breakage. NOTE numbering map: ADR-052="Unified Construction Pattern" phase-2.md:1805; standalone files only go up to ADR-051 (.md) + ADR-050; phase docs carry 052/053. Some ADRs live in phase-N.md by SUBJECT not number (032/035/042/052/053-node).

**Provenance VERIFIED (all clean):**
- §9.7.4.1 §3 isolation quote = VERBATIM from 09-security-model.md:665. §4 backends match table 667-676 (Argon2id 64MiB/iter3/par4/≥128-bit @674 exact). §5 ceremony @678-684. item-6 cycling @686. partial-publish-recovery @696.
- ADR-003 §4b @phase-1.md:375 = migrate_identity signature taking SEPARATE pre_rotation_custody (ADR claim exact). ADR-021@phase-4:620, ADR-025@phase-5:325, ADR-034@phase-4:1411 — all subjects match.
- Code-location pointers REAL: PyO3 InMemoryPreRotationCustody @identity.rs:824/922/1052; UniFFI generate_ephemeral_ed25519_seed @bridge.rs:676 + "Substrate isolation NOT yet satisfied" comment; fail-closed import_ed25519_signing_key error @bridge.rs:736 quoted verbatim.

**Standalone-PR check PASS:** docs-only, Proposed (design-only, no compile dep on the SDK code it was bundled with), fresh off main. Genuinely standalone.

**Non-blocking:** same filename still on source branch fix/sdk-coverage-fail-closed-and-parity (must drop after merge to avoid dup-add). Line-range cites approximate ("≈") but bracket right blocks — fine.

Verdict NEEDS DISCUSSION: aligned in substance/provenance/scope; blocked only by 053→054 renumber. Header format matches ADR-050/051 standalone convention. Did NOT push/PR/arm-merge.
