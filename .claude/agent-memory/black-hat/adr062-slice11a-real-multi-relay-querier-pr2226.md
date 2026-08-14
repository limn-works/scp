---
name: adr062-slice11a-real-multi-relay-querier-pr2226
description: Black-hat pass-3 on PR #2226 RealMultiRelayQuerier composer (ADR-062 slice 11a). Composer INERT in prod (uninstantiated, prod=NoOpRelayQuerier). Cap bounds verify-count not bytes; real bound delegated to UNBUILT TransportRelayQuerier.
metadata:
  type: project
---

# PR #2226 RealMultiRelayQuerier (feat/adr062-slice11a-real-multi-relay-querier)

File: crates/scp-identity/src/relay_querier.rs (+ resolution.rs RelayQuerier Vec contract).

## Prod-reachability (decisive for severity)
- `RealMultiRelayQuerier::new` has ZERO non-test call sites (grep crates/ bindings/ = 0 outside its own file). Prod `MultiRelayQuerier` wiring is `NoOpRelayQuerier` (resolver.rs:309, returns Ok(None)); FFI resolvers.rs:912/1195 use NoOp. So the composer is INERT in 11a. Matches memory "11a mergeable; 11b BLOCKED."
- `TransportRelayQuerier` (referenced repeatedly in docs as the prod single-relay impl that MUST bound candidate count) does NOT EXIST anywhere in the tree (grep = 0). It is 11b scope. The doc link `[TransportRelayQuerier]: https://docs.rs/scp-transport` resolves to a URL (not a broken intra-doc link, no rustdoc-deny failure) but points at a type that isn't published.

## Findings
- BLACK-2226-1 (FINDING, not prod-reachable in 11a): `.take(MAX_CANDIDATES_PER_RELAY=16)` is applied in the composer AFTER `inner.query()` returns a fully-materialized `Vec<RelayQueryRecord>`. The cap bounds Ed25519 verify COUNT only. It does NOT bound (a) memory of the incoming Vec (all N records materialized), (b) per-candidate `value: Vec<u8>` byte-size (verify_bep44_signature SHA-512s the whole value; DidDocument::from_json parses it). A malicious relay ignores SCP's server-side DEFAULT_QUERY_LIMIT=100/MAX_QUERY_LIMIT=1000/MAX_BLOB_SIZE=256KiB (native/protocol.rs, startup.rs) — those run on honest relays only. So the ONLY real wire bound lives in the unbuilt TransportRelayQuerier. The doc's "the cap bounds the Ed25519 verification budget" is accurate but the surrounding framing gives false comfort that the composer protects against relay DoS; the 11b impl MUST bound count AND per-value size AND total-bytes at scpr-decode.
- BLACK-2226-2 (INFO): seq-tie "two valid records at the same seq are byte-identical" is a slight overclaim. Relays don't enforce BEP44 single-value-per-seq; an owner could sign two DIFFERENT docs at the same seq → nondeterministic winner. Both owner-signed/authorized, so safe, not exploitable.
- BLACK-2226-3 (INFO): relay_urls count is unbounded → JoinSet spawns one task per URL. URLs come from the signed DID doc's serviceEndpoints (owner-controlled) or bootstrap → owner self-DoS only, not an attack on others.

## PASS (verified sound)
- Sybil / highest-seq: seq is inside BEP44 signed payload → no forged upgrade; downgrade defeated by cross-relay accumulation + resolver cached_seq high-water (resolver.rs:514-546) + parallel independent DHT layer.
- extract_public_key (dht.rs:2776): canonicality re-encode check + length + prefix, verify_strict downstream. No injection/panic on hostile DID string.
- verify_bep44_signature: verify_strict (no malleability). Cross-DID substitution blocked by self-cert + DID-derived pubkey.
- JoinError (task panic): warn+continue, no shared poisoned state (each task owns its data).
- Timeout partial-results downgrade: composer returns highest-of-collected; resolver rollback guard + DHT layer cover it. Documented threat boundary.
- empty[] suppression: extensively documented as pre-existing free capability; cross-relay + DHT fan-out is the defense.
