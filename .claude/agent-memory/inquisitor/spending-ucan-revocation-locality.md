---
name: spending-ucan-revocation-locality
description: Why global-scope spending-UCAN revocation (commit 904f6d3dc, §19.5) is local per-instance and Supervisor-held — premises and the coherence dependency to watch
metadata:
  type: project
---

Commit 904f6d3dc: scope-matched spending-UCAN revocation. Global tokens (`scp:spending:*`)
revoked into a durable DID-scoped store `identity/{did}/revoked_spending_ucans/`, cached in a
Supervisor `ArcSwap<HashMap<DID,HashSet<cid>>>` the sync paid-action gate reads lock-free.

**Verdict: SOUND.** Premises interrogated and how they held up (verify against current code before relying):

- **"Supervisor holds no DID-scoped identity state" (ADR-049) — this premise was ALREADY false pre-commit.**
  `deps.rs` `local_dids: Arc<ArcSwap<HashSet<DID>>>` is a pre-existing Supervisor-held, all-DID cache
  read by every actor's `ActorDeps`. The new `global_revoked_spending_cids` mirrors it exactly. ADR-049
  line 130's `OwnedIdentityDid` rule is narrower than the shorthand: it governs per-identity *SupervisorHandle
  methods*, not a shared cache indexed by charged DID. Not a violation.
- **The durable provider is an `Arc<dyn RevokedSpendingUcanStore>`** bridge-constructed over the bridge's own
  `ProtocolRepository` (`ProtocolRepoVariant::revoked_spending_ucan_store()` just erases the existing Arc —
  no new Storage handle). Same shape as event_log/crypto/persistence/saga-journal provider OnceLocks. Consistent
  with the ADR-049 durable-providers rule; forward-compatible if cross-device sync later lands. Not DOA.
- **adapter_credentials is the claimed precedent — true only at the KEY-NAMESPACE level** (`identity/{did}/...`),
  NOT the wiring level. adapter_credentials is generic free-fns (`configure_adapter<S>`) with zero current callers.
  The real wiring precedent is `local_dids` + provider OnceLocks.
- **ArcSwap cache is necessary, not accidental.** `ContextRevocationChecker::is_revoked` is sync over borrowed
  `HashSet`s (economy_logic.rs). The gate runs on the hot paid-action path and cannot await Storage per call, so
  the durable store must be mirrored into an in-memory snapshot. Gate reads `.load().get(charged_did)`.
- **`self_host.rs` passes `None` for the store = legitimate boundary, NOT a gap.** scp-node has ZERO economy/
  spending surface (grep: no economy/spending/paid in crates/scp-node/src). `revoke_spending_ucan` is fail-CLOSED
  when store is None (errors `NotInitialized`), and hydrate is a documented no-op → empty gate. Internally coherent.

**Cross-device axis (the sharp one):** cross-CONTEXT was "instance ignores info it has" (a real bug, now fixed —
the global cache is instance-wide so all contexts see the revocation). Cross-DEVICE is "instance lacks the info";
device B genuinely never saw the revoke, bounded by the same 24h UCAN expiry (§9.5) that governs ALL un-propagated
per-instance spending state (max_total, ledger — ledger unimplemented, #2070). Principled line, sound.
**CONDITIONAL coherence dependency:** this only stays coherent while NO cross-device identity-state sync exists
anywhere. If such sync lands, revocation MUST ride it or it becomes the one un-synced piece and drifts. #2069 tracks.

**One QUESTION-level oddity:** the best-effort `SpendingUcanRevoked` audit leaf for a GLOBAL revoke is written
under whatever `context_id` the revoke call named, though a global revocation is context-independent — different
calls could land it in different context logs. Non-authoritative (durable store is the record), but slightly incoherent.
