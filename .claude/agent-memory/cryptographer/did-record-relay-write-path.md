---
name: did-record-relay-write-path
description: DidRecordV1 relay WRITE path (#482 / SCP-RELAYRES-004) — BEP44 preimage, seq/slot rules, routing-ID single-source derivation; SOUND with one latent snapshot-once staleness risk
metadata:
  type: project
---

# DID-record relay WRITE path (`DidRecordV1`, §9.10.12)

Reviewed at `781297f29` (branch `worktree-agent-ac667e2f552c34a31`, PR for #482).
Verdict: **SOUND**. No fabricated/defaulted/zeroed cryptographic value on any
production path.

## Frame + preimage

`DidRecordV1` = `version:u8=1 ‖ public_key[32] ‖ seq:u64 BE ‖ signature[64] ‖ value`
(105-byte fixed prefix, `value` = trailing remainder — positional, no length
prefix, unambiguous because everything before is fixed-width).
`crates/scp-protocol/src/envelope/did_record.rs`

**One BEP44 preimage function, four call sites, zero re-inlining:**
`scp_dht::bep44_signable(value, seq)` = `"3:seqi" ‖ dec(seq) ‖ "e1:v" ‖ dec(len) ‖ ":" ‖ value`
(`crates/scp-dht/src/lib.rs:121`). Matches BEP44 salt-less canonical form; `seq`
is `e`-delimited, `value` is length-prefixed → unambiguous.

- SIGN: `DidDht::publish_document` (`crates/scp-identity/src/dht.rs:851`) — signs
  via KeyCustody `sign_fn` over `bep44_signable`.
- RELAY VERIFY: `verify_bep44_signature` → same fn (`did_record_validation.rs:141`).
- CLIENT VERIFY: `verify_relay_record` → same fn (`resolution.rs:159`).
- WRITE: never re-signs. `RepublishEntry` is sourced verbatim from the node's own
  DHT record (`self_host.rs:1478`), re-framed by `RepublishEntry::to_did_record`.

`ed25519_dalek::verify_strict` on both verify paths (no malleability, no
small-order/torsion accept).

## Routing-ID collapse (the change under review)

`scp_identity::republish::did_record_routing_id(&DidRecordV1)` =
`SHA-256("scp:did:" ‖ "did:dht:z" ‖ zbase32(frame.public_key()))`
(`crates/scp-identity/src/republish.rs:190`) — now the ONE derivation. Callers:
- WRITE: `TransportRelayPublisher::publish` (`relay_publisher.rs:152`)
- RELAY ADMISSION: `classify_did_record_frame` (`did_record_validation.rs:133`)
- SLOT re-index: `DidSlotRegistry::classify_stored_frame` (`did_slot.rs:482`)

Byte-identical to the prior inlined form. Domain separator `b"scp:did:"`
(`resolution.rs:42`). Deriving from the frame's own key makes a
frame/routing_id mismatch unrepresentable; cross-DID slot capture needs a
SHA-256 collision. READ path queries at `did_routing_id(did_string)` — equal
because `extract_public_key` enforces z-base-32 canonicality (16 alternate
encodings rejected).

## Trust discipline

`TransportRelayQuerier` (`native/relay_querier.rs:149`) DISCARDS
`frame.public_key()` and keeps only `(value, signature, seq)`;
`RealMultiRelayQuerier` verifies against `extract_public_key(did)`;
`DualLayerResolver::validate_relay_result` re-verifies (defense in depth).
Frame key is relay-facing only.

## seq / replay

- Relay slot (`did_slot.rs publish_frame`): `seq >` supersedes; `seq ==` +
  identical `blob_id` = idempotent TTL refresh; `seq ==` different bytes or
  `seq <` = `NonSuperseding` reject. Cold index reconciles against storage
  (`highest_valid_frame(&query_routing_id, ...)` — passes the QUERY's routing_id,
  not the derived one, so a foreign frame can't be adopted into someone's slot).
- Client anti-rollback: `cached_sequence` gate (`resolver.rs:~513`) + highest-seq
  across relay+DHT. A replayed old-but-genuine frame is availability-only.
- NOTE: `classify_stored_frame`'s inner binding compare is tautological (it
  derives the routing_id then compares to itself). Intended (self-certifying
  blob ⇒ DELETE-protected), but the comment reads as if a binding check filters
  there. Only the signature check filters at that site.

## Latent risk (not exploitable today)

`self_did_republish_entry` snapshots `(value, signature, seq)` ONCE at serve
startup; both loops republish that frozen triple forever. If the node's document
is rotated during the serve lifetime, the 2h DHT arm keeps re-putting the OLD
seq — and `PkarrDhtClient::resolve_via_gateway` returns the FIRST gateway answer,
not the highest seq. Latent because self-host has no in-lifetime rotation.
Fix shape: re-read the record each cycle, or re-drive `start_republishing` on
publish.

## Production stand-in check (mandate)

Clean. `TransportRelayPublisher` is the real impl (fail-closed
`RelayPublishFailed` when unbound / all relays reject).
`InMemoryRelayPublisher` + `RecordedRelayPublish` are
`#[cfg(any(test, feature = "testing"))]`. `RepublishManager<D, R>` has no default
`R`. `DisabledDhtClient::publish` errors (`DhtError::Disabled`); its `resolve`
returns honest `Ok(None)`. Relay arm is honestly *disabled* (not faked) when
`bound_relay_count() == 0` — one-shot, disclosed at length in rustdoc.
