---
name: adr011-eventtype-unification-amendment
description: Review of ADR-011 EventType closed-set unification amendment (commit 6c8a03c54); found one uncovered runtime append name; stale-merge-base trap
metadata:
  type: project
---

# ADR-011 EventType Unification Amendment Review (commit `6c8a03c54`, 2026-06-17)

Docs-only amendment declaring `scp_event_log::EventType` a CLOSED 75-variant taxonomy (verified exactly 75 via `git show 6c8a03c54:.docs/adrs/phase-2.md`), rejecting `Other(String)`, excluding `MessageReceived` + `EquivocationDetected` from the Merkle log, and correcting the signed-export root from hash-chain head to RFC 6962 `tree::root`. 4 files: phase-2.md (+149), ADR-050-signed-context-export.md, spec 23 §23.16.8, spec 25 §25.8.

**Verdict: CHANGES-NEEDED.** ONE genuine closed-set gap.

## The gap (blocking the closed-set + exclusion-list claim)
`crates/scp-runtime/src/context/trust_recovery_helpers.rs:256` — production `pub fn recovery_advance_epoch` appends `"recovery/epoch_advanced"` (free-form slash-string, actor `"system:recovery"`) to the Merkle log (`append_context_event` + `checkpoint_events_since += 1`). This name maps to NEITHER a 75-enum variant NOR one of the two documented exclusions. It is an MLS/sender-key epoch advance during trust recovery — semantically `EventType::KeyEpochAdvance` (already in the enum, "ADR-007 sender key epoch rotation"). The amendment asserts "these are the **only** two exclusions: every other distinct event the scp-runtime provider appends maps to a typed variant above" — that assertion is FALSE until `recovery/epoch_advanced` is mapped to `KeyEpochAdvance` (preferred) or added/excluded. Fix is upstream (this amendment), not just code.

## Everything else verified CLEAN
- Enumerated ALL production append sites: grep `append_context_event(_with_payload)?` + `append_event(` non-test, resolved every variable name (`governance_event_label`→all map; consequence `event_name`→4 Consequence* variants; `deliver_plaintext_or_announcement`→MessageReceived/PseudonymAnnounced; `payload.to_string()` JSON-tag defects SpendApproved/TTLExtended/TTLExtensionRejected; `format!` defects ContextTombstoned/ContextMigrationCancelled). 60-name inventory diffed against the 75-enum: only `recovery/epoch_advanced` uncovered.
- 5 local-only ContextEvent signals (DegradedMode, BufferOverflow, SequenceGapDetected, WelcomeGenerated, CheckpointCosignatureRequired): 0 appends each — correctly "out of EventType scope."
- Exclusions justified: `MessageReceived` (per-recipient, queries from deliver path) + `EquivocationDetected` (tier-a local alert, queries_helpers.rs:926, §23.16.6/§9.9.3). §23.16.6:423 allows the SIGNED `EquivocationAlert` (tier b) to be logged but runtime never appends it separately — no gap.
- 7-field canonical `Event` (event_type, actor_did, timestamp, sequence, payload, prev_hash, signature) — `signing_key_id` removal correct (0 occurrences in crate). ADR-003 References reconciled.
- ADR-031 referenced as §2/§3/§8 only, no count claim (phase-6.md:2892 actually says "all 30 variants", not 28 — but amendment introduces no contradiction). Cited action names (TransferAdmin, ApproveSpend, RevokeReadAccess/RevokeWriteAccess, RotateContentKeys) all exist in phase-6.md.
- Acronym casing consistent: `TtlExtended`/`TtlExtensionRejected`/`SpendingUcanGranted` (Ttl/Ucan PascalCase). Parameters in EventPayload, never in type name. Name-string defects correctly diagnosed.
- ADR-050 §Negative + §23.16.8 + §25.8 coherent: tree::root over `SHA-256(0x00 ‖ rmp_serde(Event))`, suffix/prefix/interior truncation forgery closed.

## Informational (non-blocking)
- Amendment comments `AccessRestored // RestoreAccess`, `MemberSuspended // SuspendCapability`, `MemberSuspendedAll // SuspendAccess` use action-name forms that straddle pre-existing spec/ADR drift (spec §3.408/§5.389 use `RestoreAccess`/`RevokeAccess`; phase-6.md ADR-031 uses `RestoreReadAccess`/`RevokeReadAccess`/`RevokeWriteAccess`). Tracing hints, defensible, drift is pre-existing — not introduced here.

## REUSABLE LESSON — stale-merge-base three-dot diff trap
The worktree HEAD had moved off `6c8a03c54` to `8c071349` (branch `fix/sdk-coverage-fail-closed-and-parity`) by review time (session date rolled 06-05→06-17). `6c8a03c54` was NOT even an ancestor of the live HEAD. Worse: `git diff origin/main...HEAD` (THREE-dot) against a STALE merge-base (`0c8f0b06`) showed the amendment's additions correctly ONLY while HEAD==6c8a03c54, but reading `git show HEAD:` after the move returned the WRONG file (pre-amendment 19-variant enum) and the two-dot `origin/main..HEAD` showed "77 deletions" (origin had moved on with InclusionProof/AbsenceProof content the branch lacked). ALWAYS pin analysis to the EXPLICIT commit SHA the task names (`git show <sha>:path`, `git diff <sha>^..<sha>`), never `HEAD`/three-dot, when a worktree may have drifted. Confirm `git rev-parse HEAD` == the named SHA before trusting any `HEAD`-relative read.
