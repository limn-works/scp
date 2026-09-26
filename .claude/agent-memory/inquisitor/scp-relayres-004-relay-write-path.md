---
name: scp-relayres-004-relay-write-path
description: SCP-RELAYRES-004 relay WRITE path — trait/frame work SOUND, self-host wiring UNSOUND (inert-by-construction, §3.10.6 MUST warning suppressed, #482 phantom provenance, entry sourced by network round-trip)
metadata:
  type: project
---

Interrogation of branch `worktree-agent-ac667e2f552c34a31` @ `781297f29` (SCP-RELAYRES-004,
issue #482 relay-based DID resolution Model B).

**Verdict: SOUND primitive, UNSOUND wiring.** Keep the trait/frame change; reverse the
self-host `RepublishManager` wiring.

## What is sound (do not re-litigate)
- `RelayPublisher::publish(&self, blob_ttl, &DidRecordV1)` replacing
  `(routing_id, ttl, &[u8])`. Makes bare-`document_bytes` publication AND frame/routing_id
  mismatch *unrepresentable* rather than documented. Mechanical > documentation. Also fixed a
  real latent bare-bytes bug in the resolver heal arm.
- One shared `scp_identity::republish::did_record_routing_id` used by both the WRITE path and
  the relay ADMISSION check, with tests deliberately retaining an *independent oracle*
  recomposition so a bug can't make both sides vacuously agree. Correct.
- `TransportRelayPublisher` fails closed (typed error) on zero bound relays / all-reject.
  Honest absence, NOT a nullifier. The no-dev-stand-in mandate is satisfied here.

## Root-cause decision (the thing to fix)
`DidDht::publish_document` (scp-identity/src/dht.rs) computes exactly
`(public_key, signature, value, seq)` — a complete `RepublishEntry` — and **discards it**,
returning `Ok(())`. §3.10.5 makes publish and RepublishManager-scheduling one step. Because
that seam doesn't exist, downstream `scp-node/src/self_host.rs::self_did_republish_entry`
recovers the tuple via a **live Mainline DHT network read** (`PkarrDhtClient::resolve`,
timeout + HTTP-gateway fallback). One-shot at startup, no retry ⇒ a timeout or propagation
miss leaves the node with NO republishing for its whole serve lifetime, after which its DHT
record silently expires. Same root cause makes the entry a frozen snapshot: a later rotation /
relay-URL update bumps seq and nothing re-seeds, so the keep-alive re-asserts a superseded seq
forever. **Fix flows from `publish_document`, not from the self-host lookup.**

## Blockers found (all scar-tissue class)
1. Doc comment claims "when a signed record appears, the DHT keep-alive activates
   automatically" — FALSE. The ONE-SHOT disclosure covers only the relay dimension and
   actively denies the entry-sourcing dimension.
2. §3.10.6 MUST carved out: self_host calls `RepublishConfig::disable_relay()` — the API the
   spec designates for *explicit operator opt-out* — to express "infrastructure not wired,"
   then deliberately declines `layer_disabled_callback` so `LAYER_DISABLED_WARNING` never
   fires. `RepublishConfig::default()` sets no callback, so the mandated warning is
   structurally unreachable. Wrong primitive + suppressed invariant. The comment's own
   argument ("not a deliberate user disable") is the tell that the primitive doesn't fit.
3. `#482` pointer is phantom provenance. #482 IS this PRD
   (`.docs/prds/relay-did-resolution.json`). Grep the whole PRD: ZERO hits for "bootstrap",
   "18.5.1", "connection set"; no story covers binding a relay client. The artifact cited as
   owning the work does not contain the work; when 001-005 land the pointer dangles.
4. **The load-bearing premise is factually FALSE.** The comment says "The self-host node
   exposes a relay *server*, not a bound relay *client* to publish through." It exposes BOTH.
   `connect_loopback_supervisor` (self_host.rs:602-626) constructs a live
   `NativeRelayAdapter` via `connect_sourced_with_bearer` on the production path, and it runs
   inside `SelfHostDeployer::start` → called at :1730, i.e. BEFORE the
   `bound_relay_count()` check at :1588. That relay defaults to
   `did_record_validation: Enabled` (scp-transport/src/native/server.rs:211, via
   `RelayConfig::default()` at scp-node/src/config.rs:943/:1088) with a `DidSlotRegistry` —
   a fully validating §3.10.2 DID-record store, and the exact relay a peer resolves through
   (`push_relay_service` puts its URL in the DID document; `DualLayerResolver` queries
   document-published relay URLs first). Only mechanical friction: the adapter is moved by
   value into `RelayTransportProvider::new`, and there's a `Box<dyn TransportAdapter>` blanket
   impl but no `Arc` one — a ~5-line `from_arc`. Not a capability gap.
   Same false premise powers the `NoOpRelayQuerier` at :1434-1445 ("the node's own loopback
   relay is a protocol-unaware blob pipe (§10.4), not a DID-document QUERY source").
   External/bootstrap relays are the genuinely-absent half: `NodeConfig` has no relay-URL
   field, and `DefaultRelayResolver` + `FALLBACK_RELAYS` (scp-transport/src/config.rs:220-364)
   are written, tested, and **dead** — constructed only in their own tests.
5. Compounding accidental status quo: `TransportRelayQuerier` (SCP-RELAYRES-002) has **zero**
   production construction sites — every non-doc reference outside its own file is a comment,
   its only `bind` calls are its own tests. 004's comment cites that as precedent
   ("mirrors the unbound READ-path TransportRelayQuerier"). 002 shipped a prod type with no
   caller; 004 ships a prod construction with no binding, citing 002. **The root-cause
   decision is 002's, not 004's.**
6. PRD gap: §3.10.5 step 3a (relay PUBLISH at DID create/update, parallel to the DHT leg,
   both MUST) is unimplemented and unowned by any of the five stories.
   `publish_did_document_for_mode` writes the DHT only.

## Reusable lesson
"Documented sharp edge" on a one-shot activation is not honesty — the right construction is to
remove the state (bind before constructing), not to add a re-evaluating loop, which would be
scar tissue on scar tissue: machinery whose only purpose is tolerating a gap that shouldn't
exist. See [[adr057-reciprocal-announce-mesh]] for the same shape (documented residue with no
recovery path).
