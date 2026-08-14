---
name: relay-did-resolution-cleanroom
description: Clean-room (convention-lens) design verdict for relay-based DID resolution (#482) — reuse BEP44 gateway framing + dumb relay, do NOT invent SCPR
metadata:
  type: project
---

Clean-room design verdict for relay-layer DID resolution (GH #482, #2202), reasoned independently under a convention/consistency lens, then cross-checked against spec §3.10.

**Verdict: REUSE, do not invent.** Spec §3.10.2 is explicit and upstream-authoritative: "No new wire types, no special relay behavior — a DID document is a blob addressed by a deterministic routing_id" and "Relays require no awareness that a blob contains a DID document." This MANDATES the dumb-relay design and contradicts any net-new framing (the prior attempt's "SCPR" tagged envelope).

- **Physical blob framing:** REUSE the existing BEP44 HTTP-gateway byte layout already in `dht_client/pkarr_client.rs` — `signature(64) || seq(8 BE) || value(JSON DID doc)`. The relay is just a THIRD transport for the identical signed BEP44 record (mainline DHT MutableItem = 1st, HTTP gateway blob = 2nd). Sig+seq MUST live inside the opaque blob because relay PUBLISH/QUERY carries only an opaque `blob: Vec<u8>` (no sig/seq wire fields). Optional single justified deviation: 2-byte `version` prefix mirroring `OuterEnvelope.version` (§13 versioning convention).
- **OuterEnvelope reuse = REJECT.** It is the MLS-ciphertext frame (`encrypted_blob`). Stuffing public signed bytes into it is exactly the #2202 dishonesty. The honest fix for both DID records AND KeyPackages: publish RAW record bytes directly as the blob (the blob is already opaque), NOT wrapped in OuterEnvelope. routing_id domain-separation is the type discriminant; no common tagged envelope (SCPR) needed.
- **Relay = dumb store (Design 2A), NOT BEP44-validating (2B).** Spec mandates dumb. Also: client already runs `verify_bep44_signature` + `verify_self_certification` + seq>=last_known (`resolution.rs::relay_resolve`) — the real security boundary. Relay-side BEP44 validation would REDUNDANTLY re-check, in weaker form, a property the client enforces soundly ⇒ negative value per CLAUDE.md over-engineering guard. Dumb-pipe tenet is about not trusting relays / not inspecting ENCRYPTED content; a public self-verifying record re-verified by the client violates neither. (If ever added, relay validation is a storage-bounding operational policy only, using the existing BRIDGE_REGISTER pubkey→routing_id check convention.)
- **Anti-flood/replay:** reuse existing per-IP publish rate-limit + blob_ttl (7d) + `RepublishManager` (6-day relay cycle per §3.10.2). Replay of stale record is inert: signed seq + client seq-check rejects it. NOTE spec §3.10.2 says QUERY `limit:1` — insufficient under junk-flooding of a victim routing_id; robust client should scan a bounded batch (limit>1), skip sig-invalid blobs, pick highest valid seq. Worth revisiting in spec.
- **Anti-suppression (§3.10.8):** single-relay omission unpreventable; defeated by MultiRelayQuerier (multiple relays) + parallel DHT (§3.10.1). DHT layer unaffected.
- **Verify path (#482 q4):** REUSE `dht::verify_bep44_signature` + `verify_self_certification` verbatim, CLIENT-side. Same code path as DHT arm. Relay never verifies.
- **Transport (q5):** REUSE `ClientMessage::Publish`/`Query` verbatim — no new variant. routing_id = `SHA-256("scp:did:" || did)` (already in `resolution.rs::did_routing_id`, golden-tested).

Reconciles with [[adr062-relay-public-record-framing]]: that note recorded the prior attempt treated framing as NET-NEW (SCPR); this clean-room + spec §3.10.2 say the opposite — reuse, no new wire type.
