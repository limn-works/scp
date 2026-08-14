---
name: adr011-eventtype-unification
description: ADR-011 amendment closing EventType (now 75 variants) + runtime onto canonical RFC 6962 tree; the recovery/epoch_advanced gap and append-site inventory
metadata:
  type: project
---

ADR-011 amendment (latest commit 6c8a03c54, branch spec/adr011-eventtype-unification): scp-runtime adopts canonical RFC 6962 `scp_event_log::EventLog` (typed-event leaves `SHA-256(0x00 ‖ rmp_serde(Event))`, `tree::root`), retiring the free-form-string `EventLogEntry`/`"SCP-EXPORT-ENTRY:"` hash-chain. `EventType` is a CLOSED 75-variant set (no `Other(String)`); export/checkpoint root = `tree::root` not chain-head; spec `Event` struct loses stale `signing_key_id` (code-side already had only 7 fields).

**Why:** native↔WASM equivocation detection (§9.9.3) needs convergent member root-sets; free-form string leaves are the non-convergence vector. Closing the enum enables compile-time cross-bridge tag parity. Artifact-flow prerequisite (spec/ADR fixed before code); unblocks #1535, fixes latent #1540.

**Earlier-commit gaps (84c441c06) now RESOLVED at 6c8a03c54:** stale `signing_key_id` line-706 reference fixed; format!/JSON-blob name defects (ContextTombstoned/ContextMigrationCancelled/AppBound/AppUnbound/SpendApproved/TtlExtended/TtlExtensionRejected) now documented as defects with target variants; lifecycle/app-sandbox/consequence enumeration now in the rejected-alternative argument (closure rests on union of sources, not GovernanceAction alone). The earlier review's open items are addressed.

**NEW completeness gap (found this review, NOT previously flagged):** `trust_recovery_helpers.rs:256` appends production event `"recovery/epoch_advanced"` (MLS epoch advance during trust recovery, actor `system:recovery`). Maps to NO variant in the 75-set and is NOT in the two-item exclusion list — contradicts "every other distinct event maps to a typed variant." Existing `KeyEpochAdvance` (ADR-007 sender-key rotation) is a different semantic. Needs a variant (e.g. `RecoveryEpochAdvanced`) or explicit mapping. Survives today only because `governance_logic.rs:~702` string→EventType map uses `_ => continue` (silent skip) — closed enum removes that escape hatch.

**Append-site inventory (production):** literals in builder/ttl/broadcast/governance/economy/messaging helpers; dynamic via `governance_event_label()` (8 governance labels, all map), `append_consequence_event` (5 consequence names, all map), format! defects + JSON-blob defects (all map to documented variants). All map EXCEPT `recovery/epoch_advanced`.

**ContextEvent (crates/scp-protocol/src/context/membership.rs:249)** is the receive-buffer notification enum, correctly out of Merkle EventType scope. `EquivocationDetected` is appended TODAY at `queries_helpers.rs:763`; amendment excludes it (correct per §9.9.3), so that append site must be deleted when impl lands. Same for `MessageReceived` (messaging_helpers.rs:2187).

**Sound parts:** Closing the enum is the right No-DOA call; ADR-050/§23.16.8 export-root correction (prefix+suffix truncation now rejected by construction, not merely detected) is a genuine security upgrade consistent with ADR-050's whole-snapshot-signature stance; spec now agrees with code on 7-field Event.
