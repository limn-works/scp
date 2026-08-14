---
name: scpr-relay-public-record-frame
description: SCPR relay public-record frame (§9.10.12) Model A revision — blocker resolved at spec layer; residual phantom "11b" publish-side deferral at story layer
metadata:
  type: project
---

SCPR (Relay Public-Record Frame, spec §9.10.12 / §3.10.2/4/5 / ADR-062 PRD story
SCP-CAPINJECT-011). Branch `docs/adr062-011-scpr-frame-v2`, commit ea4f90bb8.

**Prior BLOCKER (RESOLVED):** original §9.10.12 framed SCPR as a wire-level sibling of
OuterEnvelope carried directly at the routing ID, but the SDK transport is OuterEnvelope-only
(`TransportAdapter::send(&OuterEnvelope)`/`query()->Vec<OuterEnvelope>`, traits.rs;
native/adapter.rs deserializes every Blob as `OuterEnvelope::from_bytes`) — forcing Model A
(raw-blob transport surface, story under-scoped) or Model B (SCPR inside encrypted_blob = the
KeyPackage misuse). Ruled UNSOUND-REVERSE. Revision commits to **Model A** cleanly: SCPR is a
RAW relay blob, not OuterEnvelope-wrapped, not MLS-encrypted; relay wire unchanged (opaque
`ClientMessage::Publish{routing_id,blob_ttl,blob}`); SDK gains `publish_raw`/`query_raw`.
All code premises verified true on branch. Byte-disjointness holds: OuterEnvelope is
`to_vec_named` (map marker first byte 0x80-0x8f/0xde/0xdf), SCPR starts 0x53 'S'. LOW items
all fixed (named kinds 3-4 dropped → generic 3-255 reserved; alt-rejected bencode-item
rationale added; §9.10 privacy mislabel fixed). **Spec layer: SOUND.**

**Residual finding (NEW scar-tissue, STORY/ADR layer — not spec):** Model A has a read half
and a write half. §3.10.5 (cited by the story) requires PUBLISH to SCPR-wrap + `publish_raw`;
§3.10.13 names "the relay publisher" as a consumer of the SCPR frame. Story 011 builds only
the READ half (real `MultiRelayQuerier` via `query_raw` + SCPR-decode) plus the `publish_raw`
capability, but wires NO production publisher — RepublishManager still defaults
`R: RelayPublisher = InMemoryRelayPublisher` (republish.rs:397); no real RelayPublisher exists
anywhere. The publish half is deferred to a **phantom "11b"** that is NOT a story in the PRD
(only 000/001/006/009/010/011 exist) nor a slice in the ADR (only 6/9/10/11). Consequences:
(1) fabricated forward-reference (CLAUDE.md "never fabricate story references to justify
gaps"); (2) 011 claims "dual-layer suppression resilience is restored" but in production the
now-real querier reads relays that never receive DID frames → resilience NOT restored by 011
alone; (3) `publish_raw` added with no production consumer (only the AC test) = dangling
capability, empty integration-checklist cell with no filed dependent story. Note
InMemoryRelayPublisher-as-default is itself the dev-backend-default category ADR-062 exists to
sever (cf. Slice 1 InMemoryDhtClient default removal) — natural home for the write half.
Root fix (one-way flow, downstream artifacts only): make "11b" a real ADR slice + PRD story
covering publish-side (SCPR-wrap, real RelayPublisher via publish_raw, InMemoryRelayPublisher
default severance, republish.rs) OR expand 011; correct 011's "resilience restored" claim to
match what it delivers. Spec needs no change.
