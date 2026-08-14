# SCP-RELAYRES-004 WRITE path + node live slots (branch `worktree-agent-ac667e2f552c34a31`, HEAD `5b89baada`, 9 commits)

Double-zero confirming pass. Round-1 HIGHs all RE-DERIVED as genuinely fixed.

## Re-derived as CLOSED

- **Rollback / revoked-key resurrection (was HIGH).** `DidDht::publish_document`
  (`crates/scp-identity/src/dht.rs:836-889`) now RETURNS the `RepublishEntry` it
  signed. Every field is locally produced: `value` = local `document.to_json()`,
  `seq` = `self.sequence.fetch_add(1)`, `signature` = custody `sign_fn`,
  `public_key` = `extract_public_key(&identity.did)`. **Zero network input.**
  `self_did_republish_entry` (the DHT read-back) is GONE repo-wide. No sequence
  floor is needed because nothing is read back. `initialize_sequence` (pre-existing,
  untouched) is `max(stored, remote)` — monotone, and a remote can't forge a higher
  seq without the private key.
- **Missing BEP44 verify at the heal consumption site.** `maybe_trigger_healing`
  frames from `healing.raw_value`/`raw_signature`, which only exist inside a
  `ValidatedRecord` produced by `validate_relay_result`/`validate_dht_result` →
  `verify_relay_record` = `verify_bep44_signature` + UTF-8/JSON + self-certification.
  `public_key` is `extract_public_key(&did)` (DID-derived, self-certifying), never
  the frame-supplied key.
- **§3.10.6 mandated-warning suppression.** `self_host_republish_config()` wires
  `layer_disabled_warning`; `has_layer_disabled_callback()` is asserted by test.
- **Invisible partial relay-publish failure.** `RelayPublishOutcome{accepted,attempted}`;
  partial fires the degraded callback on the FIRST occurrence.
- **DhtMode gate on tier change.** `apply_tier_change` → `dyn DidPublisher` →
  `NodeDidPublisher::publish` → `publish_did_document_for_mode`. Single seam; the
  gate cannot be bypassed. `DhtMode::Memory` is `#[cfg(feature="testing")]`.
- **No nullifier.** `InMemoryRelayPublisher` is `#[cfg(any(test, feature="testing"))]`;
  scp-node depends on scp-identity WITHOUT `testing`. Absent state is `Ok(None)`
  (nothing published) or typed `RelayPublishFailed` / `DidRecordFramingFailed`.
- **Slot writers.** Exactly 3 `.set(` callsites in all of scp-node:
  `NodeDidPublisher::publish` (records), `apply_tier_change` (document + relay_url).
- **`.well-known/scp`** reads the relay-URL slot ONCE per response (`well_known.rs:109`)
  → no mid-build skew. No handler reads both the document and the URL slot.

## Open findings from this pass

1. **MEDIUM — anti-suppression detects only LOUD rejection.** A relay that ACKs
   `publish_raw` and then drops/withholds yields `accepted == attempted`,
   `is_complete() == true`, no warning, forever. §3.10.8's "withholding" variant is
   exactly the smarter attack. Fix: read back via the READ half (`query_raw`) after a
   publish cycle and count ACK-but-not-served as rejected. Note the whole partial-accept
   path is **dead in production today** — zero relays are ever bound (SCP-RELAYRES-006).
2. **MEDIUM — slot `set` is crate-visible, not module-private.** `NodeDidDocument`,
   `NodeRelayUrl`, `PublishedDidRecord` are declared in the crate ROOT (`src/lib.rs`),
   so `fn set` (no `pub`) is visible to *every* scp-node submodule. The doc claims a
   structural single-writer guarantee; it is prose + grep. Fix: move the three slot
   types AND `apply_tier_change` into one private `mod slots;`.

## Observations recorded

- Unbound-relay regime is the shipped default: permanent `RelayPublishDegraded` warn
  every 30 min forever on a healthy node (alarm fatigue; operator has no API to bind).
- `backoff_secs` uses `1u64.wrapping_shl(attempt)` → shift masked to &63, so at
  attempt 64 backoff RESETS to 30s and re-ramps (~every 30 h in permanent failure).
  Pre-existing on main, but the deleted latch makes it newly reachable.
- Relay-supplied error strings logged verbatim at `warn!` (`relay_url`, `error = %e`)
  → log-injection/forging by a malicious relay.
- `.well-known/scp` now tracks NAT tier LIVE on a public unauthenticated surface
  (was boot-frozen). Mitigated by the pre-existing reachability self-test in
  `DefaultNatStrategy::select_tier` before a STUN address is accepted.
- `apply_tier_change` rewrites only `SCPRelay` services whose endpoint `== current_url`;
  a mismatch is a silent no-op while the relay-URL slot still advances → doc/slot
  divergence. Not reachable today (no other doc mutator on the node path).
- `BoundRelays::bind` silently drops the bind on a poisoned lock (fail-closed, unlogged).
- `NativeRelayClient::send_request` has a 30 s timeout, so the sequential fan-out is
  bounded at 30 s × N — but that is an adapter property, not a trait guarantee.

## Positives worth preserving

- Type-enforced frame contract: `RelayPublisher::publish(&DidRecordV1)` makes unframed
  bytes and a mismatched routing ID *unrepresentable*; routing ID derived from the
  frame's own key (`did_record_routing_id`).
- ONE key→routing_id derivation shared by WRITE, relay ADMISSION and BRIDGE_REGISTER;
  tests keep an independent recomposition as an oracle so both sides can't be wrong together.
- `RelayPublishDegraded.last_outcome: Option<_>` — `None` on total failure rather than a
  fabricated `0 of 0`. Honest absence over synthesized data.
- Watch-slot pattern kills the frozen-snapshot class; publish and re-seed are ONE step.
