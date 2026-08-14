---
name: scpr-frame-adr062-011
description: SCPR relay public-record frame (ADR-062 Slice 11, spec §9.10.12) — layering premise contradicts OuterEnvelope-only transport; BLOCKER
metadata:
  type: project
---

# SCPR frame (§9.10.12, ADR-062 Slice 11) — inquisition

PR #2200 / branch `docs/adr062-011-scpr-frame` (commit 522cdae73) added §9.10.12 defining
the SCPR relay public-record frame (`magic "SCPR" + version:u8 + kind:u8`; kind 1 = DID-record
body seq/sig/value_len/value; kinds 2-4 reserved/undefined).

**Root finding (BLOCKER): SCPR-vs-OuterEnvelope layering is contradictory.**
- §9.10.12 frames SCPR as the *sibling/counterpart* of OuterEnvelope: "a public-record routing
  ID carries SCPR frames, not OuterEnvelopes; a resolver MUST NOT deserialize one as the other."
- But the transport is **OuterEnvelope-only**: `TransportAdapter::send(&OuterEnvelope)` /
  `query() -> Vec<OuterEnvelope>` / `TransportEvent::Envelope(OuterEnvelope)` (traits.rs:162-226,
  97-100); native adapter serializes the FULL OuterEnvelope as the wire blob
  (native/adapter.rs:467 `envelope.to_bytes()`). No raw-blob channel exists.
- Story SCP-CAPINJECT-011's file scope EXCLUDES scp-transport → the querier MUST reuse
  `query()->Vec<OuterEnvelope>` and peel `.encrypted_blob` (model B: SCPR nested in
  encrypted_blob). Under B the "counterpart/not-OuterEnvelopes/MUST-NOT-deserialize" text is
  FALSE, and SCPR replicates the exact `encrypted_blob` misuse it criticizes. Under A (raw SCPR
  wire blob) "no protocol changes" is false and the story is under-scoped.
- KeyPackage misuse premise CONFIRMED real: `publish_key_package` wraps public KP bytes in
  `OuterEnvelope.encrypted_blob` (provider.rs:231-242 via build_envelope 105-115).

**Secondary:** reserved kinds 3-4 (Context-metadata, Revocation) have NO upstream provenance
(invented in this commit) — mild speculative over-design vs "No DOA decisions." Alternative not
taken: store the canonical bencoded BEP44 mutable item as the relay blob (byte-identity free,
zero new format) — not rejected in spec. RelayPublisher::publish docstring (republish.rs:112,123)
still says "blob = BEP44-signed DID document bytes" — stale vs new §3.10.5 (blob = SCPR frame).
SCPR constant rows landed in §9.18.8 "Sender Key Protocol" (belongs in §9.18.11 Transport/Relay).
ADR-062 has NO ADR file — realized only via PRD + human ratification.

**AC2 correction (NoOp stays prod, only InMemory demotes): SOUND** — NoOp is the honest
not-a-DID-source arm (§10.4 blob pipe), fails closed Ok(None), node resolves via its real DHT arm.

Production RelayPublisher + MultiRelayQuerier do NOT exist yet (InMemory/NoOp only) — so the DID
relay wire format has never been exercised; greenfield, correct time to define it (no migration).
