# ContextManager Concurrency — Independent Redesign Findings (2026-04-14)

## Critical cryptographic finding — orphaned grace store

`PerContextState.epoch.grace_store` (EpochGraceStore) is WRITTEN on every
governance epoch advance (governance.rs:1113, trust_recovery.rs:289) and
SERIALIZED on snapshot (mod.rs:2303), but is NEVER READ by the production
decrypt path. `MlsCryptoProvider::open` (provider.rs:1089) does not have access
to it. Old-epoch decrypts go directly through OpenMLS without consulting the
grace store. Spec §23.11 isolation invariant is unenforceable in current shape:
the grace store lives behind the runtime mutex; the decrypter lives behind a
separate provider mutex and never sees it.

Implication: the SCP-layer grace store is a record-keeper for snapshots, not a
gate on decrypt. OpenMLS internally manages epoch secrets via its
`StorageProvider`. If OpenMLS drops old secrets, the grace window is governed by
OpenMLS, not by SCP. If OpenMLS retains them past 30s, SCP cannot enforce
forward secrecy because the deletion handle is owned by OpenMLS.

## The two-mutex sandwich

Per encrypt/decrypt operation, two independent mutexes are held in sequence:
1. `ContextManager.contexts[ctx_id].lock()` — `tokio::sync::Mutex`, async-fair
2. `MlsCryptoProvider.contexts.lock()` (also wrapping_public/secret) —
   `std::sync::Mutex`, blocking, held inside async with `with_context`

These are never held simultaneously. Between them, the runtime drops the
per-context lock (Phase 1 → Phase 2), encrypts/decrypts under the provider lock
only, then re-locks the per-context lock (Phase 3) for state updates.

## Compose-but-don't-lock pattern is structurally sound, executionally fragile

Send pipeline holds the per-context lock for: capability check, hard rate
limit, velocity record, economy enforcement, sequence number assignment, access
key collection, EconomyTicket creation. Drops lock. Phase 2: payment auth +
encrypt + transport.send. Re-locks (relock_context with generation check) for:
event log append, receive buffer push, consequence evaluation, checkpoint
counter, persistence snapshot.

The sequence number is assigned in Phase 1, but the inner-envelope construction
(which uses sequence + epoch for AAD) happens in Phase 2 without the lock.
Concurrent sends serialize at the per-context mutex, so sequence assignment is
ordered. But the AEAD encrypt itself uses the per-provider mutex, which is also
serialized. So no two encrypts under the same context can pull state
simultaneously. Nonce uniqueness is via OsRng (random GCM nonce), so even if
sequences crossed, nonces wouldn't. Confirmed safe.

## TOCTOU windows that survive `relock_context`

Generation check detects destroy-then-recreate but NOT:
- Same context, same generation, but `epoch_state.mls_epoch` advanced between
  Phase 1 and Phase 3. `finalize_send` then writes `MessageReceived` events
  and updates checkpoint counters under what may be a different MLS epoch
  than the one the message was sealed under. (Not security-critical: AAD
  binds epoch in the ciphertext; receivers reject mismatched epochs.)
- Capability revocation between Phase 1 and Phase 2. The capability check
  passes; the message gets sent; the recipient sees a message from a member
  whose capability was revoked. Not strictly a security failure (the receive
  path re-checks capability), but a fairness issue.
- Access key store rotated between Phase 1 (collect recipients_data) and
  Phase 2 (build encrypted envelope). The send uses the old wrapping; the
  recipient may have already discarded the old access key. Result: undecryptable
  message. The pull-based key distribution can repair this.

These are narrow windows. The current design accepts them.

## MLS state mutation outside the per-context lock

`crypto.advance_epoch(&context_id_bytes)` is called WHILE the per-context lock
is held (governance.rs:4306). But `crypto.seal()` and `crypto.open()` only need
the provider mutex — they're called outside the per-context lock in some paths.
If `seal()` is called concurrently with `advance_epoch()` for the same context,
the provider mutex serializes them. Outcome depends on order: either pre-epoch
(legitimate), or post-epoch (legitimate, new key). No nonce reuse risk.

## Persistence vs. crypto state divergence

`snapshot_context` is captured under the per-context lock. `persist_context_snapshot`
runs after the lock is released. If the process crashes between snapshot
capture and persist write, the on-disk snapshot is stale. This is documented
and acceptable.

But: the MLS crypto state (`MlsCryptoSnapshot`) is exported via
`crypto.export_crypto_state` separately, NOT under the same lock. If a Commit
broadcast advances the local epoch, persists the runtime snapshot, then crashes
before persisting the crypto snapshot, the two are out of sync on restart.
Restore code at mod.rs:1240 checks `grace_entry.epoch > snapshot.mls_epoch` and
fallback-reconnects, but the inverse (mls_epoch in crypto snapshot lower than
persisted grace entries) is not symmetrically detected.

## Background tasks compose on top of the same mutex

Governance timeout, TTL timer, commit retry drain, receive subscription all
acquire the per-context mutex. Long-running work in the timeout task (governance
processing) holds the lock while spawning child work. The TTL expiry task can
race with `send_message` (acquired-after pattern: send takes lock, finishes,
TTL takes lock, expires the context, future sends fail). This is correct but
creates a scenario where a message is "in flight" (Phase 2, lock dropped) and
the context expires before Phase 3. `finalize_send` handles this with
`require_active(&ctx.handle)` plus sequence number rollback at lines 679-684.

## Verdict

Current design: **cryptographically safe but overcomplicated**. Two independent
mutex hierarchies (runtime + provider) plus generation-counter TOCTOU detection
plus lock-drop-relock pattern across 549 sites is a maintenance trap. No active
unsafe window identified, but the orphaned grace store is a latent
specification violation: the SCP layer cannot enforce §23.11 grace-window
discipline because deletion is owned by OpenMLS.
