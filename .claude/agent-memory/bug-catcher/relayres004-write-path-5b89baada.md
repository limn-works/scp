---
name: relayres004-write-path-5b89baada
description: SCP-RELAYRES-004 relay WRITE path review (branch worktree-agent-ac667e2f552c34a31 @5b89baada) — 6 findings; verified-clean areas so a future pass doesn't re-derive them.
metadata:
  type: project
---

# SCP-RELAYRES-004 relay WRITE path — bug-catcher pass (HEAD 5b89baada, 9 commits)

Real `TransportRelayPublisher`, `RelayPublisher::publish(blob_ttl, &DidRecordV1) -> RelayPublishOutcome`,
one-shot relay latch + `bound_relay_count` DELETED, DHT read-back source DELETED
(`DidDht::publish_document` now returns the `RepublishEntry` it signed), three live
`watch`-backed slots (`PublishedDidRecord`, `NodeDidDocument`, `NodeRelayUrl`), shared `BoundRelays`,
`did_key_routing_id`/`did_record_routing_id` family.

## Findings (all re-derived from current code, not inherited)

1. **MEDIUM — `SelfDidRepublishing::stop` can leak both arms past shutdown.**
   `crates/scp-node/src/self_host.rs` ~1576. `reseed_task.abort()` is NOT synchronous for a
   task that is *currently being polled*: tokio applies cancellation when the future next
   returns `Pending`. `seed_republish_arms` → `RepublishManager::start_republishing` can run
   to completion with no yield (uncontended tokio `Mutex::lock().await` returns Ready;
   `tokio::spawn` never yields), so the observer can insert two fresh arms AFTER `stop_all()`
   drained the maps. `TaskHandle` only holds an `AbortHandle` (dropping it does not abort) and
   the `JoinHandle` was already dropped at spawn ⇒ detached arms republish forever.
   Needs multi-thread runtime (prod), so `#[tokio::test]` (current_thread) can't catch it.
   Fix: `self.reseed_task.abort(); let _ = self.reseed_task.await;` before `stop_all()`.

2. **MEDIUM — failed tier-change re-publish leaves a DEAD relay endpoint advertised.**
   `crates/scp-node/src/lib.rs` `apply_tier_change` writes `NodeRelayUrl`/`NodeDidDocument`
   on the `Ok` arm only. On `Err` the node HAS moved but `.well-known/scp` (public,
   unauthenticated) + `ApplicationNode::relay_url()` keep serving the old address. Contradicts
   the same function's `DhtMode::Disabled` rationale, which advances the URL precisely
   because "reachability changed even though nothing was published".

3. **MEDIUM — PRD/code divergence introduced inside the branch.** `bound_relay_count()` deleted
   in 36358fc17 but `.docs/prds/relay-did-resolution.json` (authored 4f6c247d3) still cites it
   8× including machine-verifiable ACs: stories[3].acceptanceCriteria[2] + actionItems[3],
   stories[5].acceptanceCriteria[2]/[6], stories[6].acceptanceCriteria[3]/[5].

4. **LOW — misplaced doc block.** self_host.rs 1427-1482: the 56-line doc describing
   `start_self_did_republishing` is attached to `fn layer_disabled_warning`; the real fn is undocumented.

5. **LOW — `backoff_secs` wrapping_shl reset.** republish.rs `1u64.wrapping_shl(attempt)` masks
   the shift by 63, so attempt 64 → 30 s. Pre-existing, but the always-enabled + never-bound
   relay arm makes permanent failure the normal state for `DhtMode::Production`, so every ~29 h
   the backoff collapses 30 min → 30 s and re-ramps (burst of extra attempts + degraded warns).

6. **LOW — residual relay-URL copy.** `build_self_host_tls_config(&node.relay_url(), …)` runs once;
   the self-signed cert's IP SANs freeze the startup external IP. Pre-existing in kind.

## Verified CLEAN (do not re-derive)

- `BoundRelays`: sync `RwLock`, every accessor clones out and drops the guard; `publish()` does
  `encode()` + `snapshot()` eagerly BEFORE the `async move` block. No lock across `.await`.
- `blob_ttl` u64→u32: checked at `native/client.rs:881` with `u32::try_from` → typed error.
- watch-slot seeding race: `borrow_and_update()` then spawn observer with the SAME receiver —
  no publish can be dropped or replayed. `Sender::subscribe()` marks current version seen.
- `start_republishing` abort+insert is atomic w.r.t. cancellation (no await between
  `tokio::spawn` and `insert`) ⇒ no double-spawn, no per-reseed leak.
- `PublishedDidRecord::set` only ever writes `Some`; `send_replace` cannot fail.
- No remaining `NodeState`/handle copies of the DID document or relay URL besides #6 and the
  deliberately-pinned bridge-auth audience.
- `did_key_routing_id` == old inline `did_routing_id ∘ did_from_ed25519_public_key` at all three
  sites (WRITE, relay admission, BRIDGE_REGISTER); tests keep an independent oracle.
- `DidRecordV1` framing in `maybe_trigger_healing` only fails on empty / >262039-byte value ⇒
  no realistic heal regression.
- Prod `TransportRelayPublisher` is never `bind`-ed — this is EXPECTED and story-owned
  (SCP-RELAYRES-006); PRD 004 `does_not_deliver` says so explicitly. Not a finding.
- Gates run green: check-error-codes, check-protocol-deps, check-cross-layer,
  check-no-shim-reexports, check-shipped-feature-graph. Full-workspace `cargo check` with the CI
  feature string: clean. (`cargo check` WITHOUT the testing features fails in scp-ffi-uniffi —
  pre-existing cfg-gating, not this branch.)
