---
name: adr011-eventtype-unification-84c441c06
description: ADR-011 native↔WASM event-log unification docs amendment review (commit 84c441c06) — APPROVED; enum sync 36+24=60, signing_key_id removal, RFC6962 tree::root export binding
metadata:
  type: project
---

# ADR-011 EventType-unification docs amendment — APPROVE (2026-06-17)

Reviewed commit `84c441c06` (branch `spec/adr011-eventtype-unification`, parent `3cf1d4a01`). Docs-only, 4 files: `.docs/adrs/phase-2.md` (ADR-011), `.docs/adrs/ADR-050-signed-context-export.md`, `.docs/specs/23-sync-and-offline-strategy.md` (§23.16.8 line 475), `.docs/specs/25-test-vectors.md`.

**Why:** Alec directed the "full" event-log unification — runtime adopts canonical RFC 6962 Merkle tree with typed-event-hash leaves (`SHA-256(0x00 ‖ rmp_serde(Event))`). Amendment adds 24 EventType variants, excludes MessageReceived/EquivocationDetected from the Merkle log, corrects export-binding chain-head→tree::root.

**Verified (all CONFIRMED):**
- Enum: post-amendment ADR `EventType` = 60 variants, 0 dups. The 36 non-new match `scp_event_log::EventType` (crates/scp-event-log/src/lib.rs) EXACTLY (comm -13 empty). The 24 new are genuinely absent from canonical (comm -23 = exactly 24).
- All 18 distinct GovernanceAction trace names exist in ADR-031 §2 enum at **`crates/scp-protocol/src/context/governance/mod.rs`** (30 imperative variants: TransferAdmin, ModifyCeiling, SuspendCapability, SuspendAccess, RotateContentKeys, ProposeContextMigration, etc.). NOTE there are TWO GovernanceAction enums: protocol's request-enum (governance/mod.rs, imperative) vs runtime result-style (`scp-runtime/src/context/state.rs`, past-tense incl AccessRevoked). The amendment correctly used REQUEST names.
- Flag #2: MemberSuspended→SuspendCapability, MemberSuspendedAll→SuspendAccess both correct. AccessRevoked is NOT a request variant (only in state.rs result enum) — no confusion.
- ContextMigrationStarted is the EXACT event name in §5.11A (05-contexts.md:570: `ContextMigrationStarted { destination_id, grace_period_end }` emitted at grace start); GovernanceAction is ProposeContextMigration.
- signing_key_id removal correct: canonical Event has exactly 7 fields, no signing_key_id (grep=0). generate_checkpoint's signing_key_id is a separate checkpoint arg, unaffected.
- Exclusions sound: §9.9.3 detects equivocation by "Merkle-root equality at same event count" (needs convergent root-sets); §23.16.6 confirms EquivocationDetected is local tier-(a) SDK alert.

**How to apply (next work item):** This is docs leading code. Follow-on impl PR must wire tree::root through export/import (`crates/scp-runtime/src/context/export_import.rs`, `providers/event_log.rs`) AND all 4 FFI bridges (`scp-ffi/src/event_log.rs`, napi, uniffi, wasm `manager.rs:5152-5181`) + land deferred typed-leaf + checkpoint KATs in §25. Until then spec/code gap is intentional and flagged.

**Reusable patterns:**
- When verifying an ADR enum-sync claim, extract BOTH enums to /tmp and use `comm -13`/`comm -23` — gives exact missing/extra sets, not eyeballing.
- Worktree may be checked out on a DIFFERENT branch than the review target. ALWAYS `git show <reviewcommit>:<file>` — do not trust the working-tree file. Here worktree was on `fix/sdk-coverage-fail-closed-and-parity`@8c07134, not the ADR-011 branch; on-disk file lacked the amendment entirely.
- Two same-named enums (GovernanceAction request vs result) is a real trap — confirm which one a trace comment refers to by reading both definitions.
