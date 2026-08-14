---
name: adr057-t2-client-storage
description: ADR-057 T2 scp-client snapshot/restore storage wiring — re-attack findings and confirmed-clean surfaces
metadata:
  type: project
---

# ADR-057 T2 client storage (branch feat/adr057-t2-client-storage)

Re-attack after 16-item fix batch. HEAD 15ecc84cb. Files: crates/scp-client/src/{client,snapshot,context,storage,error}.rs, crates/scp-mls/src/snapshot.rs, crates/scp-client-wasm/src/error.rs.

## Confirmed CLOSED (prior findings held)
- BLACK-T2-01 spec §17.6 rewrite ("Browser Clients Run Storage In-Process"): honest, no overselling. "sole defense is AEAD at rest" + "protocol does not defend rollback/resurrection" stated plainly. "true-loss" framing for failed-persist-after-decrypt is CONSERVATIVE (durable ratchet is pre-decrypt, so relay re-delivery could recover — spec under-claims durability, safe direction).
- BLACK-T2-02 pending-join binding: owner_did + context_id both bound (scp-mls PendingJoinSnapshot), both verified on restore. context_id derived from storage KEY, compared to embedded bound_context_id. cross_identity swap → StorageIdentityMismatch(8012); cross_context swap → StorageCorrupt(8011). Both tested (snapshot_restore.rs:552,567). Foreign-MLS-entries-with-matching-bindings scenario closed by MLS HPKE layer (foreign provider can't open a Welcome meant for the real KP → MlsError). Requires AEAD break to even craft.
- Poison collision: create_context/join_context_encrypted guard via contains_key (INCLUDES poisoned) → ContextAlreadyExists. No MLS-state overwrite on re-create of poisoned id.
- Observers: context_ids() lists poisoned (all), member_dids()/event_log_root() return None for poisoned (live_context_ref filter). Disagreement is BY DESIGN, fails safe.
- Renumber: wasm error.rs uses SCP-STORAGE-8010-8013; 8001-8003 = Android. Clean. TS errors.test.ts 8001 refs are pre-existing generic storage-class routing, not browser-meaning.
- Drop impls (ContextSnapshot, ProviderSignerDump): zeroize on empty/drained/moved-out vecs = no-op, no panic-in-drop. local_sender_key mem::replace'd with zeroed placeholder; mls_state NOT taken so drop zeroizes the real blob. Sound.

## OPEN finding
- MEDIUM (contract/doc + narrow data-loss): close_context on a POISONED context deletes the last-good durable snapshot — the exact snapshot ContextPoisoned's contract promises for reconstruct-recovery. Ordering deletes ctx snapshot FIRST (client.rs:734) then pending; a partial close failure (ctx delete OK, pending delete fails) returns Err with docs claiming "left fully live... retryable", but for a poisoned context the recovery snapshot is already gone AND poison guard blocks any re-persist (unlike a healthy context, which re-persists on next op). Two escape hatches (reconstruct=recover vs close=abandon) not cross-referenced; close's forfeiture of the recoverable snapshot not stated. Compounds accepted selective-poison DoS into permanent local loss. Not attacker-controlled beyond caller choice.
