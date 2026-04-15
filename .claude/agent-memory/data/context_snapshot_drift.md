---
name: ContextSnapshot persistence drift
description: Why the current ContextSnapshot blob is fundamentally torn against MLS state, event log, and transport state.
type: project
---

Problem: Current persistence model is "snapshot the union of PerContextState + exported MLS crypto state as one MessagePack blob." Event log entries persist independently per-append. BroadcastContextSnapshot is a second blob.

Why this is structurally broken, not just racy:

1. **Three separate persistence clocks** — every mutation can trigger 0-3 durable writes:
   (a) `event_log.append_context_event(...)` — FIRST, while map mutex may or may not be held depending on call site.
   (b) `persist_context_snapshot` — called AFTER releasing the map mutex (see mod.rs:1972, ordering note in mod.rs:1952-1959).
   (c) `persist_broadcast_snapshot` — for broadcast contexts, in a different code path.
   They are NOT journaled together. Any crash between them creates divergence.

2. **MLS crypto state is re-exported on every snapshot** (mod.rs:1979 `self.crypto.export_crypto_state(...)` every call). This:
   - Acquires MLS provider's `contexts` Mutex separately from CM's map mutex.
   - Means the exported MLS state is a different point-in-time than the CM `PerContextState` clone.
   - For sender_key_epoch, send_sequence, recv_sequence_tracker: you can persist a SCP-layer envelope whose sequence number refers to an MLS state that was a different epoch.

3. **Storage trait has no multi-key atomicity** (`scp-platform/src/traits.rs:472`). `store`/`retrieve`/`delete`/`list_keys`/`delete_prefix`/`exists`. No `transaction`, no `batch_write`. SQLite backend has transactions available but the trait doesn't expose them.

4. **Snapshot size is unbounded in practice**. `ContextSnapshot` has ~53 fields including `access_key_store`, `velocity_tracker_state` (per-sender timestamps), `hard_rate_limit_state` (token buckets), `pending_commits`, `approved_proposals`, `executed_proposals`. On every mutation the whole blob is re-serialized and re-written. For a context with N members, M approved-pending proposals, and sustained rate-limit activity, the blob is tens of KB written on every message send.

5. **Per-SDK persistence implementations are divergent**. Python bridge uses `EncryptingAdapter<InMemoryStorage>` (ephemeral). NAPI uses `NapiBridgePersistence` (DashMap in-memory — explicitly NOT persistent). UniFFI/WASM vary. The trait is correct; the defaults are all ephemeral, so "has_persistence()" guards much of the code and production deployments depend on scp-node's `ProtocolRepositoryContextBridge`.

6. **Bridge blocks-on-async** (`store/context.rs:944 tokio::task::block_in_place + Handle::block_on`). The sync `ContextPersistence` trait forces every persist call to pay the block-in-place penalty, and on some runtimes this is outright a footgun.

7. **Transport/relay state isn't persisted at all**. Subscription tables, reliability scores, suppression tracker, connection_last_used — all in-memory. On restart the CM restores contexts from snapshots but has no persistent record of which relays to re-subscribe on. The SDK-level pump (napi context.rs:1029) has to be re-initiated by the application.

8. **Event log restoration is independent** and never cross-validated against the snapshot's `mls_epoch` or `executed_proposals`. `grace_entries` in the snapshot has an inconsistency-detection branch (§23.11 fallback mod.rs:1196), but that's only for grace store vs. snapshot, NOT for event log vs. snapshot.

Root cause: there is no **durable per-context log of mutations**. Persistence is a state dump, not a transactional history. The protocol has a Merkle event log already (the best candidate for that role), but it's decoupled from in-memory state mutation and used only for attestation.
