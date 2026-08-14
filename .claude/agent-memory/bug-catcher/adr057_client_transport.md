---
name: adr057-client-transport
description: ADR-057 scp-client browser relay transport slice — self-echo BLOCKER + ordering/restore hazards
metadata:
  type: project
---

# ADR-057 scp-client transport slice (feat/adr057-transport-jssocket @ 68f986c9a)

Reviewed the JsSocket outbound port + handle_relay_frame inbound pump + §9.10.4 pseudonym fan-out.

**BLOCKER — announcement self-echo.** Every member SUBSCRIBEs to `context_routing_id`
(`install_local_routing`, client.rs ~857-862) AND publishes its `PseudonymAnnouncement`
to that same routing id (`announce_pseudonym`→`encrypt_and_fanout`, routing_ids=[context_routing_id],
client.rs ~936). The native relay `handle_publish` (transport/src/native/server.rs:1097) takes
NO connection_id and `deliver_to_subscribers` (relay/subscription.rs:142) excludes no one — so the
relay echoes each announcement back to its own publisher. `handle_relay_frame` (client.rs:1028) then
resolves it (known routing id → NOT dropped) and calls `receive_message`→`decrypt_message`→openmls
`process_message` on the member's OWN MLS frame → typed Err → thrown from `handleRelayFrame`
(scp-client-wasm/src/lib.rs). Fires on EVERY announce (join/add/bystander). Untested: both harnesses
(`tests/common/mod.rs route_publishes`, `wasm_surface_exchange.rs`) only route from→other, never self.
Pattern: relay pub/sub has no publisher-exclusion; any subscribe-and-publish-to-same-rid self-echoes.

**minor — cross-routing-id reorder wedge.** recv_sequence_tracker keyed per-sender-DID
(crypto_state.rs:788,817) is shared across the announcement channel (context_routing_id) and the
app-data channel (peer pseudonym) — different relay routing ids, no cross-channel ordering. Announcement
is seq 0, first app-data seq 1. If app-data arrives first, announcement rejected as reorder →
peer pseudonym never learned → that direction permanently PseudonymRegistryEmpty (no periodic re-announce).

**minor — restore subscribes in constructor.** restore_from_storage→install_local_routing→subscribe→
socket.send (client.rs:1710-1713) runs inside ScpClient::new; a reopened tab with contexts emits SUBSCRIBE
frames at construction. If JsSocket isn't open/buffering, send throws → whole construction fails (recoverable).

**minor — partial fan-out.** encrypt_and_fanout persists advanced ratchet + buffers MessageSent BEFORE the
send loop; a socket.send failure mid-loop returns Err after some peers got it and it's recorded as sent →
caller retry duplicates to already-delivered peers under a new sequence.
