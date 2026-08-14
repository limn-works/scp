---
name: saga-2c-broadcast-types-2d-wiring-a784ca50d
description: Alignment review of broadcast hosting-handshake types (§5.14.13) + Phase 2D replay-at-startup wiring (§17.16.4); ALIGNED except 1 HIGH error-code sub-block misallocation
metadata:
  type: project
---

# Branch feat/2c-saga-dispatch, worktree saga-2c, HEAD a784ca50d (2026-06-23)

Two commits reviewed:
- b001f49a6 — broadcast hosting-handshake saga protocol TYPES (scp-protocol leaf only; §5.14.13)
- a784ca50d — Phase 2D replay-at-startup wiring (§17.16.4 replay-before-restore)

## VERDICT: NEEDS DISCUSSION — 1 HIGH (error-code sub-block) + minor observations. Everything else ALIGNED.

## HIGH — SCP-SAGA-13003/13004/13005 are in the WRONG sub-block + unregistered
- File: crates/scp-protocol/src/context/broadcast/hosting_handshake.rs:72/76/84 (PreimageConstruction / SignatureInvalid / ConfigInvalid).
- Governing artifact: .docs/standards/sdk-common.md §"Registered SCP-SAGA- codes" partition table lines 58-62:
  - `13000-13009` = owner `scp-protocol cross_context_saga.rs` (used: 13000/13001/13002).
  - `13010-13099` = runtime handler+supervisor.
  - `13100-13999` = **reserved for future saga families — explicitly names "standing-pair, broadcast-hosting handshake"**.
- The broadcast handshake's pure signing/verify/validate errors are EXACTLY the reserved-band family, but the code picked 13003/13004/13005 = the next-free numbers INSIDE cross_context_saga's 13000-13009 block. Wrong sub-block.
- Also UNREGISTERED: not added to the registry table (sdk-common.md lines 69-114, which jumps 13002→13010). The table's whole purpose is grep-disambiguation to one call site; normative prose says "take the next free number inside the owning sub-block" + uniqueness maintained by the table.
- check-error-codes.sh is RANGE-ONLY (13000-13999) — passes EXIT=0, does NOT catch sub-block. So this ships silently.
- Phantom-provenance smell: the code's own doc-comment lines 61-62 cites "the SCP-SAGA- band (13000-13999)... see sdk-common.md" as justification while violating that same standard's partition.
- FIX (flows down correctly — it's a standards-doc allocation, not a code-reveals-spec-wrong case): renumber to 13100/13101/13102 (or next free in 13100-13999 broadcast sub-block) AND add a broadcast-hosting sub-block row + the three table entries to sdk-common.md, updating the byte-embedded codes in the #[error(...)] strings + the byte-exact tests if any assert the literal.

## ALIGNED (verified):
- §5.14.13 field sets BYTE-EXACT: BroadcastHostConfig (max_forward_rate_per_minute u32 [1,6000] def 600; max_subscribers u32 [1,1_000_000] def 10000; forwarding_policy verbatim|routing-stripped def verbatim; expires_at_ms u64 >0). validate() rejects only expires_at_ms==0; clamp() clamps the two range u32s, carries policy+expiry through (expiry upper ceiling = B Prepare-B step, correctly deferred — not a leaf property).
- Request preimage order (hosting_handshake.rs:336-343) == spec 1614-1617 EXACTLY: Fixed32(host),Fixed32(broadcast),VarBytes(subscriber_did),Fixed32(wrapping_pubkey),VarBytes(jcs(requested_config)),OptVarBytes(ucan),RawBytes16(nonce),U64(timestamp_ms).
- Grant preimage (506-513) == spec 1628-1631: same minus ucan, plus U64(current_key_epoch) after config.
- OptVarBytes(ucan): present⇒VarBytes(4-byte BE len+bytes), absent⇒CanonicalField::Absent⇒SHA-256(0x00) sentinel (canonical.rs ABSENT_SENTINEL) — §9.5.1 optional-field rule; test ucan_absent_differs_from_present_empty proves absent≠present-zero-length.
- Two separators BCAST_HOST_REQ_DOMAIN "SCP-BCAST-HOST-REQ-V1:" + BCAST_HOST_GRANT_DOMAIN "SCP-BCAST-HOST-GRANT-V1:" REGISTERED in §9.18.2 (09-security-model.md:1630-1631), distinct from each other + envelope/key labels (test domain_separators_are_distinct).
- AcceptedHostSnapshotEntry (606-631) == spec 1702-1705 EXACTLY: host_context_id, subscriber_did, wrapping_pubkey, granted_config, granted_at_ms, key_epoch_at_grant, saga_id. Correctly OMITS broadcast_context_id (spec snapshot has none).
- Scope honesty: BroadcastHostingHandshakePrepared staged-state type (key_epoch_at_grant/grant_nonce/grant_timestamp_ms/broadcast_host_config_bytes) NOT in this commit — correctly a later 2C runtime step. Commit msg says "scp-protocol only (no runtime/FFI — later 2C steps)". No dispatch, no FFI. Honest.
- mod.rs change = broadcast.rs→broadcast/mod.rs rename + `pub mod hosting_handshake;` (the +10 stat). git shows 5049-line "new file" due to rename threshold, NOT new code.

## Phase 2D (a784ca50d) ALIGNED — genuine wiring, not just export:
- New Supervisor::restore_on_startup (supervisor.rs:7841) = replay_unresolved_sagas().await? THEN restore_all_contexts().await. Folds both behind one method so a bridge can't call one without the other / out of order.
- Routed into ALL production bootstraps: BridgeInstanceCore::restore_all_persisted_contexts (resume/startup), PyO3 restore_all_contexts (context.rs), NAPI context_restore_all_on, UniFFI Scp::restore_all_contexts. WASM unchanged (ephemeral, ADR-034) — correct.
- Ordering rationale traces to §17.16.4 (17-persistence-and-storage.md:961) recovery semantics: non-resident caller → record-keyed reversal lookup-miss → ReversalOutstanding → left non-terminal at PreparingB for later sweep; if restore ran first the now-resident caller goes down the LIVE-reversal path, changing semantics. NOTE: the literal sentence "replay MUST precede restore" is NOT in the spec — it's a sound DERIVATION from the §17.16.4 recovery branch behavior + recover_preparing_b_entry (supervisor.rs:5596). Docstring cross-refs all exist + are accurate.
- pipeline_wiring.rs (scp-TESTING/tests, not scp-runtime — path gotcha) gains 2 real structural assertions + floor 43→45 (additive, coverage-expanding, legit): restore_on_startup_runs_replay_before_restore (replay_pos<restore_pos in fn body) + bridge_resume_path_routes_through_restore_on_startup (positive: calls restore_on_startup(); negative: must NOT call bare restore_all_contexts()).
- Test restore_on_startup_replays_unresolved_journal_without_manual_replay: 2-process crash sim, injects Initiated saga, fresh supervisor, asserts journal empties via restore_on_startup w/ NO manual replay, AND restore leg surfaces PersistenceFailed AFTER replay (proves order). NoopPersistence harness real (test file:41).

## Minor observations (non-blocking):
- Spec JSON wire bodies show "type":"broadcast-hosting-request"/"-grant" but neither the leaf structs NOR the mirrored template (cross_context_saga.rs) carry a serde "type" tag. The type tag is a wire-envelope discriminator (NOT in the §9.5.1 preimage, which starts at Fixed32(host_context_id)); wire-tagging/dispatch is a later 2C runtime concern. Consistent with template. Note it; not a signing defect.

## LESSON
For "add saga-family error codes" PRs: the SCP-SAGA- band is SUB-BLOCK-partitioned in sdk-common.md but the CI gate (check-error-codes.sh) is RANGE-ONLY — it will pass codes that sit in the wrong owner sub-block. Must manually verify (a) the code sits in the family's RESERVED sub-block (broadcast-hosting = 13100-13999, NOT the cross_context_saga 13000-13009 block) and (b) each new code is added to the registry table. A passing error-code gate is necessary-not-sufficient. Phantom-provenance tell: code doc-comment citing the band as justification while violating the same standard's finer partition.
