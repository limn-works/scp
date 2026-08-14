---
name: relayres-004-final-9ca2c3f05
description: Security review of the FINAL SCP-RELAYRES-004 relay DID WRITE-path state (9ca2c3f05) — 1 MEDIUM (sanitize_relay_text misses Unicode bidi/Zl/Zp), 1 MEDIUM (sanitizer applied only on the WRITE half; READ half leaks raw relay text across FFI), 3 LOW.
metadata:
  type: project
---

# SCP-RELAYRES-004 final state (9ca2c3f05, GitHub #482) — security review

Reviewed at worktree tip 54ccc46d7; the two commits above 9ca2c3f05 touch only
`.claude/agent-memory/` and `Cargo.lock` — **zero** `crates/` delta, so the
reviewed code is byte-identical to the named commit.

## Findings

- **MEDIUM — `sanitize_relay_text` is incomplete.**
  `crates/scp-transport/src/native/relay_publisher.rs:70` gates on
  `char::is_control()`, which is Unicode category **Cc only**. Verified empirically
  (`rustc` harness): U+202E RLO, U+202A-U+202E, U+2066-U+2069 (bidi isolates),
  U+200B-U+200F, U+FEFF, and — most importantly — **U+2028 LINE SEPARATOR / U+2029
  PARAGRAPH SEPARATOR** all pass through verbatim. U+2028/2029 are JS line
  terminators, so the function fails against *its own stated threat* ("embedded
  newlines/CR would forge whole operator log lines"). ESC (U+001B) and NEL (U+0085)
  ARE escaped correctly. Byte cap holds (max ~518 bytes, verified).
  Fix: positive whitelist (`c.is_ascii_graphic() || c == ' '`), per CLAUDE.md's
  anti-denylist guidance.

- **MEDIUM — sanitizer applied on the WRITE half only.** Only 2 call sites, both in
  `relay_publisher.rs`. The READ half at
  `crates/scp-transport/src/native/relay_querier.rs:119` wraps
  `TransportError::SendFailed("relay error {code}: {msg}")` (raw relay-supplied
  `msg`, see `native/client.rs:806,897,1084,1285` and `native/adapter.rs:510,572,693`)
  into `IdentityError::RelayQueryFailed`, which is logged unsanitized at
  `scp-identity/src/resolver.rs:728` and crosses FFI as
  `ResolutionError::NetworkUnavailable(msg)` (`scp-ffi/common/src/resolvers.rs:311`)
  — unbounded and unescaped into every SDK.
  Fix: move the sanitizer to a shared `scp-transport` helper, apply at the
  `RelayMessage::Err` → `TransportError` boundary (one chokepoint).

- **LOW — `BoundRelays` poison handling is silent on the READ paths.**
  `native/mod.rs:143-163`: `bind` logs `tracing::error!` on poison, but `snapshot`,
  `get`, and `len` map poison to empty/0 with **no log**. A poisoned map therefore
  presents as `NoRelayBound`, which the republish loop *rate-limits* as a benign
  configuration state (`republish.rs:976`). Poisoning is near-unreachable (only a
  panic under the guard; the closures are String/Arc clones), hence LOW.

- **LOW — `RelayPublishOutcome::is_complete()` is vacuously true at 0/0.**
  `scp-identity/src/republish.rs:134` — `accepted >= attempted`. `Ok(0/0)` would
  reset `consecutive_failures` and sleep the full 6-day cycle (phantom success).
  No live path produces it (`TransportRelayPublisher` returns `NoRelayBound` when
  empty and requires `accepted > 0`), but the `>= 1` guarantee is doc-only.
  Fix: `self.accepted > 0 && self.accepted >= self.attempted`.

- **LOW — two doc inaccuracies.** `self_host.rs:1447` names `RelayPublishFailed`
  where the unbound path returns `NoRelayBound` (the whole point of the new
  variant). `published_state.rs:55` calls `document` "the one it last successfully
  published" — false for `DhtMode::Disabled`, which advances `document` on
  `Ok(None)` having published nothing.

## Verified SOUND (do not re-litigate)

- **Round-1 MEDIUMs closed.** `LiveSlot::modify` is a bare `fn` inside the *private*
  `mod published_state`, and `apply_tier_change` (its only caller) lives beside it —
  out-of-band writes are a compile error, not a convention.
- **DhtMode gate is a real chokepoint.** `publish_did_document_for_mode` has exactly
  ONE caller (`NodeDidPublisher::publish`, lib.rs:2172); `NodeDidPublisher` is the
  only production `DidPublisher` impl. Startup and tier-change both route through it.
- **Routing-ID binding is unrepresentable-by-construction.** `RelayPublisher::publish`
  takes no routing_id; it is derived from the frame's own key via the single
  `did_key_routing_id` ∘ `did_record_routing_id` family. A WRITE↔ADMISSION agreement
  test asserts `classify_did_record_frame` accepts the exact published pair. Tests
  keep independent recomposition oracles so both sides can't be vacuously wrong.
- **Write-ahead sequence store** (`dht.rs:885`) — store before network write; a
  failed store publishes nothing (test `a_failed_sequence_store_write_publishes_nothing`).
  `initialize_sequence` takes `max(store, DHT)` and the DHT gateway path
  BEP44-verifies before returning, so seq inflation needs the private key.
- **Heal path only republishes verified records.** `validate_relay_result` /
  `validate_dht_result` both run `verify_relay_record` (BEP44 verify + self-cert)
  before a `ValidatedRecord` exists; `maybe_trigger_healing` frames once, up front,
  and reports a framing failure as `DidRecordFramingFailed` (never as a layer fault).
- **No nullifier.** `TransportRelayPublisher` is constructed at `self_host.rs:1777`
  and **never bound** in production (verified: zero non-test `.bind(`). It fails
  closed with typed `NoRelayBound` — honest absence, detectable, story-referenced
  (SCP-RELAYRES-006). `InMemoryRelayPublisher` is `#[cfg(any(test, feature="testing"))]`.
  `NoOpDidMethod::publish` returns a typed error, never a fabricated record.
- **Dev API is not a new disclosure surface.** `identity_handler` now reads the live
  slot but sits behind `bearer_auth_middleware` + `localhost_host_middleware`.
  `.well-known/scp` (public) exposes only `relay_url`, as it did before — reading the
  slot once per request removes a two-endpoint skew, it does not add a field.
- **Rate-limited degraded reporting does not suppress a genuine fault.** `report` is
  unconditionally `true` for any non-`NoRelayBound` error (`republish.rs:976`).
- **`is_protected_did_record`** lost nothing in the `Option<(rid,seq)> -> bool`
  change: the sole caller (`gate_delete`) only ever did `.is_some()`.
- `repoint_relay_service`'s position-key agrees with `relay_service_urls()`
  (both filter `service_type == "SCPRelay"` preserving `service` order).
</content>
</invoke>
