---
name: adr057-jssocket-transport-1980-audit
description: ADR-057 #1980 browser relay transport slice (JsSocket + pseudonym fan-out) review — self-echo BLOCKER, serde extraction is actually sound
metadata:
  type: project
---

# ADR-057 #1980 JsSocket transport slice audit (branch feat/adr057-transport-jssocket @68f986c9a)

## BLOCKER: shared-channel announcement self-echo throws in handle_relay_frame
- Relay `deliver_to_subscribers` (crates/scp-transport/src/relay/subscription.rs:142) delivers a published blob to ALL subscribers of the routing_id with NO publisher/origin exclusion → relay echoes a member's own PUBLISH back to it.
- Every member subscribes to shared `context_routing_id` (install_local_routing) AND publishes its `PseudonymAnnouncement` there (announce_pseudonym → encrypt_and_fanout).
- So each announce → own echo → handle_relay_frame → receive_message → decrypt_message → outer MLS decrypt of OWN message → openmls 0.8.1 framing/validation.rs:111-112 returns `ValidationError::CannotDecryptOwnMessage` → Err propagates → wasm surface throws JsValue.
- Tests CANNOT catch it: `route_publishes(from,to)` in transport_tests.rs always routes to a DISTINCT party; self-delivery never exercised.
- Tell: handle_relay_frame treats unknown-RID as benign drop but NOT own-echo — asymmetric. Fix: drop own-echo (CannotDecryptOwnMessage / self-sourced frame) as benign, same as unknown RID.
- App data NOT affected (fanned to peer pseudonyms; publisher not subscribed to those). Announcements only. No state corruption (error raised pre-persist), but fires on the join→announce happy path every time.

## Serde private-key extraction (group.rs extract_ed25519_seed) — ACTUALLY SOUND
- Headline worry disproven: openmls_basic_credential 0.5.0 `test-utils` feature gates ONLY the `private()` method; `#[derive(Serialize,Deserialize)]` + struct layout are feature-INDEPENDENT. So the cross-check test's serde path == production serde path byte-for-byte.
- `private: Vec<u8>` = ed25519 32-byte seed (sk.to_bytes()). to_vec_named → named map; deserialize into {private:Vec<u8>} ignores public/scheme; len!=32 fails closed. Field rename → missing-field error (loud). Well-guarded, fail-closed. Minor: TLS codec would be more stable than serde, but fine.

## Other findings
- MEDIUM: encrypt_and_fanout persists ratchet BEFORE the publish loop; a mid-loop socket.send failure returns Err after some peers already got the blob; retry increments sequence and re-fans to ALL → duplicate app-data (distinct seq, no receiver dedup) to already-delivered peers + duplicate MessageSent.
- MEDIUM (test gap): fan_out 3-party test asserts ADDRESSING (2 PUBLISH, identical blob, distinct RIDs) but never routes them to Bob/Carol to prove they DECRYPT "to everyone". Carol joined at later epoch / Bob-as-bystander decryptability of fanned app-data is unproven end-to-end. 2-party round-trip IS genuine (asserts decrypted plaintext via drain_events).
- Coder committed --no-verify + scoped nextest → cannot have exercised wasm target or full-workspace integration; self-echo is exactly what that misses.

## Good
- Poison-on-persist-failure model is careful and consistent. Key-package Lifetime hardened-clock re-validation + RFC9420 max-range enforcement is solid, well-tested. Fail-closed wrapping-key/invariant-3 admission. 2-party round-trip test is real.
