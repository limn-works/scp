---
name: scp-relayres-004-relay-write-path
description: SCP-RELAYRES-004 relay WRITE path (branch worktree-agent-ac667e2f552c34a31 @5b89baada) — the latch/read-back reversal is SOUND, but two live scar-tissue vectors remain (falsified §10.4 loopback-relay comment; PRD ACs prescribing the deleted bound_relay_count design)
metadata:
  type: project
---

# SCP-RELAYRES-004 (#482 relay DID resolution, WRITE path) — re-interrogation @ 5b89baada

## What the fix rounds reversed (verified SOUND — do not re-litigate)

- **One-shot `bound_relay_count()` latch + accessor DELETED** (36358fc17). Relay arm is now
  unconditionally scheduled whenever a signed record exists; `TransportRelayPublisher::publish`
  fails closed (`IdentityError::RelayPublishFailed`) with zero binds; `relay_republish_loop`
  backs off 30s→30min (cap) and fires `RelayPublishDegraded` at 6 consecutive failures.
  Genuinely self-healing — proven by `relay_arm_self_heals_when_a_relay_is_bound_after_start`
  (self_host.rs:3538): binds on the SAME shared `Arc<TransportRelayPublisher>` after start,
  advances 31s, asserts a `DidRecordV1` frame is published. Real regression guard, not prose.
- **DHT read-back DELETED.** `DidMethod::publish` / `DidDht::publish_document` now RETURN the
  `RepublishEntry` the signing pass computed. Structural: the triple can no longer be
  re-derived from a network read. `NoOpDidMethod::publish` fails closed with a typed error —
  never a fabricated record. No nullifier anywhere on this path.
- **Three frozen snapshots → live `watch` slots** (`NodeDidDocument`, `NodeRelayUrl`,
  `PublishedDidRecord`, lib.rs ~2140-2345). Right primitive; the "don't merge them" arguments
  hold (a `DhtMode::Disabled` node's doc must advance with `PublishedDidRecord == None`;
  `relay_url` is an INPUT to the document rewrite at lib.rs:2776, so deriving it from the doc
  would be circular). Exactly 3 `.set(` writers repo-wide (2420, 2793, 2794).
- **§3.10.6 layer-disabled warning wired** via `RepublishConfig::with_layer_disabled_callback`,
  invoked by `disable_dht()`/`disable_relay()`, tested; production never disables a layer.
- `BoundRelays` DRYs the READ/WRITE late-binding map; poisoned lock ⇒ "no binding" ⇒ fail closed.

## Live scar tissue found on the FINAL state (both BLOCKERs)

1. **self_host.rs:1404-1407** (`build_shared_cache_key_resolver`) — pre-existing 2026-06-22
   comment justifying `NoOpRelayQuerier`: "the node's own loopback relay is a protocol-unaware
   blob pipe (§10.4), not a DID-document QUERY source". Falsified 3 ways:
   `DidRecordValidation::Enabled` is `#[default]` (server.rs:211) and scp-node overrides only
   `bind_addr`/`bridge_secret` (config.rs:943,1088) ⇒ this relay DOES validate + slot DID
   records; the node advertises this exact relay as its own `SCPRelay` endpoint (lib.rs:3488,
   3773) ⇒ it IS the Layer-1 QUERY source; and §10.4's "protocol-unaware" goal is about
   ENCRYPTED CONTEXT BLOBS — §3.10.2/§3.10.8 carve DID records out as the one public,
   relay-inspectable frame class, so the citation is doctrine-outside-its-domain.
   This comment is the load-bearing rationale that SCP-RELAYRES-006 exists to overturn.
2. **PRD `.docs/prds/relay-did-resolution.json` prescribes the DELETED design.** File last
   touched at 4f6c247d3, BEFORE 36358fc17 removed the latch and the `bound_relay_count()`
   accessor. 8 stale sites: 004 description + AC[2] + actionItems[3]; 006 description +
   AC[2] + AC[6]; 007 AC[3] + AC[5]. Worst: 006 AC[6] "asserts `bound_relay_count() > 0` at
   the moment `start_self_did_republishing` is entered (the manager never observes a
   zero-relay publisher)" — re-imposes the exact ordering invariant the fix proved
   unnecessary. Artifact governs code ⇒ executing 006 as written regresses the fix.
3. (minor) self_host.rs:1840-1841 call-site comment "plus the relay arm once a relay is
   bound" — REWRITTEN in fix commit d672278a2d, still states the deleted latch semantics.

## Standing facts worth reusing

- `DidRecordValidation::Enabled` is `#[default]`; the self-host loopback relay validates DID
  records and enforces slot-exclusivity. Any comment calling it a "blob pipe" is FALSE.
- §3.10.6 "publishing to both layers is a MUST" is NOT met today: `DhtMode::Disabled` ⇒ zero
  arms (honestly disclosed); `Production` ⇒ DHT only at create/update. §3.10.5 step 3a is
  SCP-RELAYRES-008; the relay-client bind is 006; the bootstrap set is 007. Artifact-owned.
