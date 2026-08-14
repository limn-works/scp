---
name: relayres004-write-path-reseed
description: SCP-RELAYRES-004 relay DID WRITE path + republish re-seed (branch worktree-agent-ac667e2f552c34a31 @5b89baada) — SOUND; signed-bytes chain, seq monotonicity, routing-ID single derivation
metadata:
  type: project
---

# SCP-RELAYRES-004 — relay WRITE path + live re-seed (verdict SOUND, 2026-08-08)

Branch `worktree-agent-ac667e2f552c34a31` @ `5b89baada`, 9 commits vs origin/main. PRD `.docs/prds/relay-did-resolution.json` (#482).

## Construction facts worth remembering

- **One BEP44 signable everywhere**: `scp_dht::bep44_signable(value, seq)` = `"3:seqi" || dec(seq) || "e1:v" || dec(len) || ":" || value` (crates/scp-dht/src/lib.rs:121). Used by SIGN (`DidDht::publish_document`, dht.rs:857), RELAY admission (`classify_did_record_frame` step 3), and CLIENT verify (`verify_relay_record`). `verify_strict`. Length-prefixed, unambiguous.
- **`DidMethod::publish` now returns `RepublishEntry`** — the signed `(public_key, seq, signature, value)` is an OUTPUT of signing. The DHT read-back republish source is DELETED. `value` is carried octet-for-octet: `document_bytes = value.to_vec()` → `to_did_record()` → `DidRecordV1::encode()` appends it verbatim at offset 105. Nothing re-signs, nothing re-serializes the document.
- **`RepublishEntry` has no `did` field** — derived via `did()` from `public_key`. Manager task-map key is the derived DID.
- **Frame is outside the signed bytes**: `DidRecordV1` = `version(1) || pk(32) || seq(8 BE) || sig(64) || value[..]`, 105-byte fixed prefix, no value_len prefix (unambiguous remainder), canonical raw binary (not msgpack).
- **Live slots (scp-node/src/lib.rs)**: `NodeDidDocument`, `NodeRelayUrl`, `PublishedDidRecord` — all `Arc<watch::Sender<_>>`, `set()` module-private. Only writers: `apply_tier_change` (first two) and `NodeDidPublisher::publish` (third). Debug impls print only `document.id` / URL / `sequence` — no key material.
- **Re-seed is structural**: `reseed_republish_arms` observes the `PublishedDidRecord` watch receiver; `seed_republish_arms` = `stop_all().await` then `start_republishing(entry)`. Single serial observer task; `SelfDidRepublishing::stop` aborts the observer BEFORE `stop_all` (else an in-flight `changed()` respawns arms past shutdown).

## Why seq monotonicity holds
Single `AtomicU64` in the shared `DidDht`; `fetch_add` per publish. Startup publish is awaited before `spawn_tier_reevaluation`, and the tier task is the only later publisher → serial single-writer → the slot never regresses. Old/new arms cannot both publish (abort + insert under the manager's task-map lock). An aborted in-flight put can only land a LOWER seq, which BEP44 and `DidSlotRegistry::publish_frame` (`seq > slot.seq`, else `NonSuperseding`) both reject. Cold-index reconciliation (did_slot.rs:334-349) scans storage with the WIRE routing_id and ADOPTS a stored higher/equal-different frame while rejecting the newcomer.

## Routing-ID family (§3.10.2)
`did_routing_id(did) = SHA-256("scp:did:" || did)` (unchanged) → `did_key_routing_id(pk) = did_routing_id(did_from_ed25519_public_key(pk))` → `did_record_routing_id(rec) = did_key_routing_id(rec.public_key())`. All three re-exported from `scp_identity` root.
Production callers: `TransportRelayPublisher::publish` (write), `classify_did_record_frame` (admission), `DidSlotRegistry::classify_stored_frame` (delete gate), `verify_bridge_registration`. The ONLY remaining direct `did_routing_id` production use is `scp-identity/src/relay_querier.rs:157` (input is a DID string — the base of the family, not a re-inline). Every other occurrence is inside `mod tests` (verified by grep). Test-side independent oracles are deliberately RETAINED.

## Residual notes (all LOW/INFO, non-blocking, reported not filed)
1. `TransportRelayPublisher` is constructed at self_host.rs:1764 and **never bound** on any production path — the relay arm fails closed forever and warns `RelayPublishDegraded` every ~30 min on a shipped node. Honest + PRD-disclosed (binding is SCP-RELAYRES-006), but self_host.rs:1436-1454 doesn't say so.
2. dht.rs:872-879 publishes to the DHT and THEN `sequence_store.store(...).await?`. A store failure returns Err after the record is live at seq N, so the slot/arms stay pinned to N-1 → the live record stops being kept alive. Fix: write-ahead the sequence, or file the slot as soon as `dht_client.publish` returns Ok.
3. `classify_stored_frame` returns `Option<([u8;32], u64)>` but its sole caller (`gate_delete`, did_slot.rs:707) uses only `.is_some()` — the self-derived routing_id is dead. Narrow the return so no future caller mistakes it for a wire-checked one.
4. `initialize_sequence` (dht.rs:813) does a blind `sequence.store(best_seq)`, not `fetch_max`, and self_host calls it AFTER the startup publish (pre-existing ordering). Safe only because self_host wires no `NetworkChangeDetector`. Prefer `fetch_max`.
5. relay_querier.rs ~171 comment overstates: two same-seq valid records need not be byte-identical (a §3.10.4 owner-inflicted same-seq conflict).

Tests at HEAD: scp-identity 214, scp-transport 619+19+19, scp-node 405+42 — all pass, 0 failures.
