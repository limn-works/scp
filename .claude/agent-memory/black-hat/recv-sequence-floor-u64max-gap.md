---
name: recv-sequence-floor-u64max-gap
description: recv_sequence import merge 2b guard bounds epoch only, sequence unbounded — (E_valid, u64::MAX) accepted; LOW (creator-key gated, transient per-epoch DoS)
metadata:
  type: project
---

# recv_sequence floor import: unbounded sequence component (branch fix/adr049-recv-sequence-floor-maxmerge @ca8edb253)

**File:** `crates/scp-runtime/src/crypto/mls/provider.rs`
- `validate_and_merge_recv_sequence_floors` (~2888). Guard 2b (line ~2964-2972) checks only `imp_epoch > ceiling` where ceiling = `sender_key_store.epoch(ctx,did) + MAX_EPOCH_ADVANCE(1000)`. The sequence `_imp_seq` is discarded. So an imported floor `(valid_epoch, u64::MAX)` passes 2a (not a regression if > live) + 2b (epoch within ceiling) and max-merges in at step 3.
- Effect on `open()` (~1743-1753): replay check rejects `epoch==last_epoch && sequence <= last_seq`. Floor (E, u64::MAX) => every message in epoch E rejected. New epoch (epoch > E) unlocks (accepted regardless of seq). H9 ceiling (~1730-1739) caps epoch at high_water+1000.

**Reachability / trust (the load-bearing point):**
- Only path = `restore_crypto_state_with_floor_guard(...,false)` via `PrepareForReplace` / `import_context` (lifecycle_helpers.rs:1779, 2031, 2045).
- `import_context` (lifecycle_helpers.rs:1884) calls `validate_export_for_import`: Ed25519 `snapshot_signature` over the ENTIRE snapshot (incl `mls_crypto_state` which carries recv_sequence_tracker), AND enforces `exporter_did == role_state.creator_did`, key resolved from creator's DID doc.
- => u64::MAX sequence can ONLY come from a snapshot signed by the CREATOR's key. Third parties cannot. Relay/MITM replay of a LEGIT snapshot can't either (legit snapshots have tiny real sequences). Requires creator complicity or full creator-key compromise.
- Fresh-import path: local_floors empty => cold-restart no-op, guards don't even run, snapshot loads verbatim (but no live floor to protect).
- PrepareForReplace requires context replaceable (Closing/Closed/Expired/Tombstoned/Poisoned) — cannot hit a live healthy context.

**Damage:** transient per-epoch receive-DoS on the importing node for chosen victim DID(s) (can poison all members in one HashMap). Recoverable at victim's next sender-key epoch advance (one rotation). NOT permanent — strictly less severe than the epoch=u64::MAX case that commit ca8edb253 fixed (which was permanent because H9 can never exceed u64::MAX).

**Comparison (point 3):** a creator-key holder already loads sender_key_entries (set_unchecked, verbatim, provider.rs:2506), member_wrapping_keys, and full MLS group state from the same signed snapshot — total control over the imported context's crypto + membership + governance. The recv-seq gap is a tiny subset of that power.

**Severity: LOW.** Real inconsistency vs the epoch twin's overshoot ceiling; worth a defense-in-depth symmetric bound, but creator-key-gated + transient + dwarfed by other verbatim-loaded signed fields. Not a blocker. Note: forward-merging a higher sequence is Invariant-4 (append-only) COMPLIANT — it's not a replay/rollback hole; the only harm is artificially-high DoS, same shape as the epoch overshoot 2b already bounds.
