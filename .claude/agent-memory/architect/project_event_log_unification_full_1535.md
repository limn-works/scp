---
name: project-event-log-unification-full-1535
description: ADR-011 FULL resolution — unify scp-runtime event log onto canonical RFC6962 typed-event-hash leaves; EventType enum expansion + chain-head→tree::root migration
metadata:
  type: project
---

Alec chose "FULL" resolution for the native↔WASM event-log checkpoint-root divergence (#1535/#1540): unify `scp-runtime` event log onto the canonical RFC 6962 Merkle tree with **typed-event-hash leaves** (`SHA-256(0x00 || rmp_serde(Event{event_type:EventType,...}))`), matching FFI/WASM + ADR-011 + §23.16.1.

**Why:** scp-runtime `MerkleEventLogProvider`/`ContextLog` (`providers/event_log.rs`) is a divergent hash-CHAIN (domain `"SCP-EXPORT-ENTRY:"`, free-form `event:String`), `merkle_root()`=chain head. WASM (`scp-ffi/wasm/src/manager.rs::append_log_event`) is the reference — uses `scp_event_log::EventLog` + typed `Event` + `tree::append_unsigned_event`/`root`. Native runtime ALSO holds the real tree (`PerContextState.merkle_tree`) but `sync_merkle_tree` (`queries_helpers.rs:855`) wrongly pushes CHAIN hashes as leaves via `push_leaf_raw`. So checkpoint `merkle_root` (build_checkpoint `queries_helpers.rs:624`) and export binding (`export_import.rs:638`, §23.16.8) use chain-head; cross-member equivocation detection compares incompatible roots.

**Blocker for FULL (now resolved by ADR amendment):** ~30 runtime event-name strings have NO `EventType` variant → they'd hash differently than WASM's typed events. Full inventory: see classification in the decision doc. Most map to NEW EventType variants traced to ADR-031 GovernanceAction variants (`variant_name()` in `crates/scp-protocol/src/context/governance/mod.rs:776`) + §19 economic + §5.11A migration. `MessageReceived` and `EquivocationDetected` are local-only (NOT Merkle-logged in the canonical model — receive-side + local alert).

**Already-correct facts:**
- `Event` struct LACKS `signing_key_id` field that ADR-011 AC1 specs (latent ADR/code drift, orthogonal).
- §25.8 has RFC6962 Merkle KATs but they hash raw byte strings, NOT serialized typed `Event` — no cross-bridge leaf-from-typed-event KAT exists (the §25 gap to fill).
- ADR-050 §65 + `export_import.rs:620-637` explicitly document chain-head-not-tree as a "known limitation" — that text becomes OBSOLETE under FULL, amend in lockstep.
- `EventType::ConsistencyCheckpoint` exists; spec text (phase-6 §2199) calls it `Checkpoint` and also specs `QueueDrained` — neither `Checkpoint`(renamed) nor `QueueDrained` is in code yet.

**How to apply:** ADR-011 amendment lands FIRST (artifact-flow), then code. Sequencing + blast radius in the decision output. WASM unchanged (reference); FFI tag sites get real variants for new EventTypes.
